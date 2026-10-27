"""IMAP auto-reply utility.

Fetched replies are staged as PendingReply records and require manual approval
before sending.  Sending uses the original campaign sender's SMTP credentials
so replies originate from the same account that launched the campaign.
"""

import email
import imaplib
import os
import re
import time
from datetime import datetime
from email.header import decode_header
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

from dropoutjeep_lib import db

from .mailer import Mailer


def _decode_header_value(value):
    if not value:
        return ''
    parts = []
    for payload, charset in decode_header(value):
        if isinstance(payload, bytes):
            parts.append(payload.decode(charset or 'utf-8', errors='replace'))
        else:
            parts.append(str(payload))
    return ''.join(parts)


class AutoReplier:
    """Poll an IMAP inbox and build templated replies."""

    def __init__(self, imap_host=None, imap_user=None, imap_pass=None,
                 imap_port=993, imap_use_tls=True):
        from dropoutjeep_lib.utils.settings import get_setting, get_setting_int
        self.imap_host = imap_host or get_setting('imap_host') or os.environ.get('IMAP_HOST')
        self.imap_user = imap_user or get_setting('imap_user') or os.environ.get('IMAP_USER')
        self.imap_pass = imap_pass or get_setting('imap_pass') or os.environ.get('IMAP_PASS')
        configured_port = get_setting_int('imap_port', 0)
        self.imap_port = imap_port or configured_port or 993
        self.imap_use_tls = imap_use_tls if imap_use_tls is not None else True

    @classmethod
    def from_sending_profile(cls, sending_profile):
        """Build an AutoReplier from a SendingProfile's IMAP settings."""
        return cls(
            imap_host=sending_profile.imap_host,
            imap_user=sending_profile.imap_user,
            imap_pass=sending_profile.get_imap_pass(),
            imap_port=sending_profile.imap_port or 993,
            imap_use_tls=sending_profile.imap_use_tls if sending_profile.imap_use_tls is not None else True,
        )

    def _imap_conn(self):
        if not all([self.imap_host, self.imap_user, self.imap_pass]):
            raise RuntimeError('IMAP credentials not configured')
        if self.imap_use_tls:
            conn = imaplib.IMAP4_SSL(self.imap_host, self.imap_port)
        else:
            conn = imaplib.IMAP4(self.imap_host, self.imap_port)
        conn.login(self.imap_user, self.imap_pass)
        conn.select('INBOX')
        return conn

    def fetch_pending_replies(self, rule, campaign_base_url=''):
        """Return a list of dicts representing replies awaiting approval."""
        conn = self._imap_conn()
        try:
            status, messages = conn.search(None, 'UNSEEN')
            if status != 'OK':
                return []

            pending = []
            for num in messages[0].split()[:rule.max_replies_per_session]:
                status, data = conn.fetch(num, '(RFC822)')
                if status != 'OK':
                    continue

                raw_msg = data[0][1]
                msg = email.message_from_bytes(raw_msg)

                sender = msg.get('From', '')
                subject = _decode_header_value(msg.get('Subject', ''))
                message_id = msg.get('Message-ID', make_msgid())

                if rule.filter_sender_pattern and \
                        not re.search(rule.filter_sender_pattern, sender, re.I):
                    continue
                if rule.filter_subject_pattern and \
                        not re.search(rule.filter_subject_pattern, subject, re.I):
                    continue

                reply_subject = rule.reply_subject_template.replace('{subject}', subject)
                if not reply_subject.lower().startswith('re:'):
                    reply_subject = f'Re: {reply_subject}'

                reply_html = rule.reply_template_html
                unsubscribe = f'<{campaign_base_url}/unsubscribe>' if campaign_base_url else ''
                if unsubscribe:
                    reply_html += f'\n<p><a href="{campaign_base_url}/unsubscribe">Unsubscribe</a></p>'

                pending.append({
                    'message_id': message_id,
                    'sender': sender,
                    'subject': subject,
                    'reply_subject': reply_subject,
                    'reply_body_html': reply_html,
                    'unsubscribe': unsubscribe,
                })

                # Mark as seen so we don't fetch it again next poll.
                conn.store(num, '+FLAGS', '\\Seen')
                time.sleep(rule.delay_seconds)
            return pending
        finally:
            try:
                conn.logout()
            except Exception:
                pass

    def process_auto_replies(self, rule, sending_profile, campaign_base_url=''):
        """Fetch replies for an auto-approve rule and send them immediately.

        Returns a tuple of (sent_count, failed_count, staged_count).
        """
        from dropoutjeep_lib.models import PendingReply

        pending = self.fetch_pending_replies(rule, campaign_base_url=campaign_base_url)
        sent = failed = staged = 0
        for item in pending:
            exists = PendingReply.query.filter_by(
                rule_id=rule.id,
                original_message_id=item.get('message_id'),
                original_sender=item.get('sender'),
            ).first()
            if exists:
                continue

            if rule.auto_approve:
                reply = PendingReply(
                    rule_id=rule.id,
                    campaign_id=rule.campaign_id,
                    original_message_id=item.get('message_id'),
                    original_subject=item.get('subject'),
                    original_sender=item.get('sender'),
                    reply_subject=item.get('reply_subject'),
                    reply_body_html=item.get('reply_body_html'),
                    status='pending',
                )
                ok, err = self.send_reply(reply, sending_profile=sending_profile)
                if ok:
                    reply.status = 'sent'
                    reply.sent_at = datetime.utcnow()
                    sent += 1
                else:
                    reply.status = 'failed'
                    failed += 1
                    reply.provision_error = err
                db.session.add(reply)
                db.session.commit()
            else:
                db.session.add(PendingReply(
                    rule_id=rule.id,
                    campaign_id=rule.campaign_id,
                    original_message_id=item.get('message_id'),
                    original_subject=item.get('subject'),
                    original_sender=item.get('sender'),
                    reply_subject=item.get('reply_subject'),
                    reply_body_html=item.get('reply_body_html'),
                    status='pending',
                ))
                staged += 1
                db.session.commit()
        return sent, failed, staged

    def send_reply(self, pending_reply, sending_profile=None):
        """Send an approved PendingReply via the campaign sender's SMTP.

        If sending_profile is None, the caller must ensure MAILER_* env vars
        are set.  Returns (ok, error_message).
        """
        if not sending_profile:
            mailer = Mailer(
                os.environ.get('SMTP_HOST', 'localhost'),
                smtp_port=int(os.environ.get('SMTP_PORT', '25')),
                smtp_user=os.environ.get('SMTP_USER'),
                smtp_pass=os.environ.get('SMTP_PASS'),
                use_tls=os.environ.get('SMTP_USE_TLS', 'true').lower() == 'true',
            )
        else:
            mailer = Mailer(
                sending_profile.smtp_host or os.environ.get('SMTP_HOST', 'localhost'),
                smtp_port=sending_profile.smtp_port or int(os.environ.get('SMTP_PORT', '25')),
                smtp_user=sending_profile.smtp_user,
                smtp_pass=sending_profile.get_smtp_pass(),
                use_tls=sending_profile.use_tls if sending_profile.use_tls is not None else True,
            )

        msg = MIMEText(pending_reply.reply_body_html, 'html')
        msg['From'] = sending_profile.subsidiary.from_address if sending_profile and sending_profile.subsidiary else \
            (sending_profile.smtp_user if sending_profile else os.environ.get('SMTP_USER'))
        msg['To'] = pending_reply.original_sender
        msg['Subject'] = pending_reply.reply_subject
        msg['Date'] = formatdate(localtime=True)
        msg['Message-ID'] = make_msgid()
        msg['In-Reply-To'] = pending_reply.original_message_id or ''
        msg['References'] = pending_reply.original_message_id or ''

        from .mailer import unsubscribe_headers
        for header, value in unsubscribe_headers().items():
            msg[header] = value

        try:
            mailer.send(
                envelope_from=msg['From'],
                to_addr=pending_reply.original_sender,
                subject=pending_reply.reply_subject,
                html_body=pending_reply.reply_body_html,
                from_header=msg['From']
            )
            return True, None
        except Exception as e:
            return False, str(e)
        finally:
            mailer.close()


def process_all_auto_replies():
    """Poll inboxes for every active auto-reply rule and process replies.

    Intended to be called periodically by the APScheduler.
    """
    rules = AutoReplyRule.query.filter_by(is_active=True).all()
    for rule in rules:
        campaign = Campaign.query.get(rule.campaign_id) if rule.campaign_id else None
        if not campaign or not campaign.sending_profile:
            continue
        sp = campaign.sending_profile
        if not sp.imap_host or not sp.imap_user:
            continue
        try:
            replier = AutoReplier.from_sending_profile(sp)
            replier.process_auto_replies(rule, sp)
        except Exception:
            import logging
            logging.getLogger(__name__).exception(
                "Auto-reply poll failed for rule %s", rule.id
            )
