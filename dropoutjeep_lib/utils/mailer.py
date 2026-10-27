import email.utils
import hashlib
import logging
import os
import random
import smtplib
import ssl
import threading
import time
import uuid
from email.message import EmailMessage
from email.utils import formataddr
from typing import List, Optional

from .dkim_utils import sign_email
from .ics_builder import build_ics

logger = logging.getLogger("dropoutjeep")


def unsubscribe_headers() -> dict:
    """List-Unsubscribe headers, or nothing when no target is configured.

    Set UNSUBSCRIBE_TARGET to an https URL for RFC 8058 one-click, or to a real
    mailbox address for the mailto form. Anything else is ignored: a header that
    points at a mailbox nobody reads is worse than no header.
    """
    value = (os.environ.get("UNSUBSCRIBE_TARGET") or "").strip()
    if not value:
        return {}
    if value.lower().startswith("http"):
        return {
            "List-Unsubscribe": f"<{value}>",
            "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
        }
    if "@" in value:
        return {"List-Unsubscribe": f"<mailto:{value}>"}
    return {}


def _open_smtp(host, port, timeout, use_tls=True):
    """Open an SMTP connection, implicit TLS on 465 and STARTTLS everywhere else.

    Port 465 speaks TLS from the first byte, so smtplib.SMTP() there reads the
    handshake as a banner and fails. Shared hosts often present a broken
    certificate on 587 but a valid one on 465, so supporting both matters.
    """
    port = int(port or 587)
    if port == 465:
        ctx = ssl.create_default_context()
        conn = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
        conn.ehlo()
        return conn
    conn = smtplib.SMTP(host, port, timeout=timeout)
    conn.ehlo()
    if use_tls and conn.has_extn('STARTTLS'):
        conn.starttls(context=ssl.create_default_context())
        conn.ehlo()
    return conn


def _is_valid_email(addr):
    # Minimal sanity check; not a full RFC validator.
    return isinstance(addr, str) and "@" in addr and "." in addr.split("@")[-1]


def make_message_id(domain):
    """Generate a randomized Message-ID using uuid4 to prevent
    timestamp-correlation clustering by Gmail/Outlook filters."""
    return f"<{uuid.uuid4().hex}@{domain}>"


def build_headers(msg, envelope_from, from_header=None, reply_to=None,
                  dkim_selector=None, dkim_domain=None, dkim_private_key=None):
    """Build standard email headers.

    Sim headers (X-Mailer, X-DropoutJeep-Sim) have been REMOVED — they were
    instant spam-folder triggers against Gmail/Outlook/Proofpoint.
    """
    if 'Date' not in msg:
        msg['Date'] = email.utils.formatdate(localtime=True)
    if 'Message-ID' not in msg:
        _, env_addr = email.utils.parseaddr(envelope_from)
        domain = env_addr.split('@')[-1]
        msg['Message-ID'] = make_message_id(domain)
    if from_header:
        msg['From'] = from_header
    if reply_to:
        msg['Reply-To'] = reply_to

    # List-Unsubscribe only when the operator configured a real target. A dead
    # mailto address on every message is a negative signal and gives Gmail's
    # one-click handler nothing to POST to.
    if 'List-Unsubscribe' not in msg:
        for header, value in unsubscribe_headers().items():
            msg[header] = value

    # No Authentication-Results header. Receivers MUST discard AR headers from
    # untrusted sources (RFC 8601 section 5), and a self-asserted "pass" that the
    # receiver's own check contradicts is a stronger phishing signal than no
    # header at all. The real result comes from SPF, DKIM and DMARC in DNS.

    return msg


class SMTPConnectionPool:
    """Reusable SMTP connection pool with health checks."""

    def __init__(self, host, port, use_tls=True, user=None, password=None,
                 timeout=10, max_conn=5, max_conn_age=300):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.user = user
        self.password = password
        self.timeout = timeout
        self.max_conn = max_conn
        self.max_conn_age = max_conn_age
        self._pool: list = []
        self._lock = threading.Lock()

    def _create(self):
        s = _open_smtp(self.host, self.port, self.timeout, self.use_tls)
        if self.user and self.password:
            s.login(self.user, self.password)
        return s

    def acquire(self):
        with self._lock:
            while self._pool:
                conn = self._pool.pop()
                try:
                    status = conn.noop()[0]
                    if status == 250:
                        return conn
                except Exception:
                    try:
                        conn.quit()
                    except Exception:
                        pass
            return self._create()

    def release(self, conn):
        with self._lock:
            if len(self._pool) < self.max_conn:
                self._pool.append(conn)
            else:
                try:
                    conn.quit()
                except Exception:
                    pass

    def close_all(self):
        with self._lock:
            while self._pool:
                c = self._pool.pop()
                try:
                    c.quit()
                except Exception:
                    pass


class Mailer:
    """SMTP sender with optional DKIM signing, connection pooling, and retry/backoff."""

    def __init__(self, smtp_host, smtp_port=25, smtp_user=None, smtp_pass=None,
                 use_tls=True, timeout=10, max_retries=3, dkim_selector=None,
                 dkim_domain=None, dkim_private_key=None, pool_size=0,
                 backoff_base=0.5, backoff_factor=2.0, backoff_jitter=0.1):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_pass = smtp_pass
        self.use_tls = use_tls
        self.timeout = timeout
        self.max_retries = max_retries
        self.dkim_selector = dkim_selector
        self.dkim_domain = dkim_domain
        self.dkim_private_key = dkim_private_key
        self.backoff_base = backoff_base
        self.backoff_factor = backoff_factor
        self.backoff_jitter = backoff_jitter
        self.pool = None
        if pool_size > 0:
            self.pool = SMTPConnectionPool(
                smtp_host, smtp_port, use_tls, smtp_user, smtp_pass,
                timeout, max_conn=pool_size
            )

    def close(self):
        if self.pool:
            self.pool.close_all()

    def _retry_backoff(self, attempt):
        base = self.backoff_base * (self.backoff_factor ** attempt)
        jitter = random.uniform(0, self.backoff_jitter)
        return base + jitter

    def _prepare_message(self, envelope_from, to_addr, subject, html_body,
                         plain_body=None, from_header=None, reply_to=None,
                         ics_event=None, attachments=None):
        if not _is_valid_email(to_addr):
            raise ValueError("invalid recipient address")
        if not _is_valid_email(envelope_from):
            raise ValueError("invalid envelope from address")

        msg = EmailMessage()
        msg['To'] = to_addr
        msg['Subject'] = subject

        # Auto-generate text/plain alternative if not provided.
        # Some filters score HTML-only mail higher; Gmail displays
        # "View entire message" link without a text part.
        if not plain_body and html_body:
            plain_body = _html_to_text(html_body)

        if plain_body:
            msg.set_content(plain_body)
        msg.add_alternative(html_body, subtype='html')

        if ics_event:
            ics_content = build_ics(
                event_title=ics_event.get('title', 'Meeting'),
                event_start=ics_event['start'],
                event_end=ics_event['end'],
                location=ics_event.get('location'),
                description=ics_event.get('description'),
                organizer_email=envelope_from,
            )
            msg.add_attachment(
                ics_content.encode('utf-8'),
                maintype='text',
                subtype='calendar',
                filename='invite.ics',
                headers=[('Content-Class', 'urn:content-classes:calendarmessage')]
            )

        for attachment in attachments or []:
            data = attachment.get('content')
            filename = attachment.get('filename', 'attachment.bin')
            mime_type = attachment.get('mime_type', 'application/octet-stream')
            if '/' in mime_type:
                maintype, subtype = mime_type.split('/', 1)
            else:
                maintype, subtype = 'application', 'octet-stream'
            msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)

        build_headers(
            msg, envelope_from, from_header, reply_to,
            dkim_selector=self.dkim_selector,
            dkim_domain=self.dkim_domain,
            dkim_private_key=self.dkim_private_key,
        )

        raw = msg.as_bytes()
        if self.dkim_selector and self.dkim_domain and self.dkim_private_key:
            try:
                raw = sign_email(raw, self.dkim_selector,
                                 self.dkim_domain, self.dkim_private_key)
            except Exception as e:
                logger.warning("dkim signing failed: %s", e)
        return msg, raw

    def send(self, envelope_from, to_addr, subject, html_body, plain_body=None,
             from_header=None, reply_to=None, timeout_override=None,
             ics_event=None, attachments=None):
        msg, raw_bytes = self._prepare_message(
            envelope_from, to_addr, subject, html_body, plain_body,
            from_header, reply_to, ics_event, attachments)

        timeout = timeout_override or self.timeout
        last_exc = None

        if self.pool:
            return self._send_with_pool(envelope_from, to_addr, raw_bytes, timeout)
        return self._send_direct(envelope_from, to_addr, raw_bytes, timeout)

    def _send_with_pool(self, envelope_from, to_addr, raw_bytes, timeout):
        last_exc = None
        for attempt in range(self.max_retries):
            conn = None
            try:
                conn = self.pool.acquire()
                if timeout:
                    conn.timeout = timeout
                conn.sendmail(envelope_from, [to_addr], raw_bytes)
                logger.info("sent mail (pool) envelope_from=%s to=%s attempt=%d",
                            envelope_from, to_addr, attempt)
                self.pool.release(conn)
                return True
            except Exception as e:
                last_exc = e
                logger.warning("send error (pool) %s attempt=%d", e, attempt)
                if conn:
                    try:
                        conn.quit()
                    except Exception:
                        pass
                if attempt < self.max_retries - 1:
                    backoff = self._retry_backoff(attempt)
                    time.sleep(backoff)
        logger.error("mail send failed (pool) envelope_from=%s to=%s last_err=%s",
                     envelope_from, to_addr, last_exc)
        raise last_exc

    def _send_direct(self, envelope_from, to_addr, raw_bytes, timeout):
        last_exc = None
        for attempt in range(self.max_retries):
            server = None
            try:
                server = _open_smtp(self.smtp_host, self.smtp_port, timeout, self.use_tls)
                if self.smtp_user and self.smtp_pass:
                    server.login(self.smtp_user, self.smtp_pass)
                server.sendmail(envelope_from, [to_addr], raw_bytes)
                logger.info("sent mail envelope_from=%s to=%s subject=%s attempt=%d",
                            envelope_from, to_addr, attempt)
                server.quit()
                return True
            except Exception as e:
                last_exc = e
                logger.warning("send error %s attempt=%d", e, attempt)
                if server:
                    try:
                        server.quit()
                    except Exception:
                        pass
                if attempt < self.max_retries - 1:
                    time.sleep(0.5 * (2 ** attempt))
        logger.error("mail send failed envelope_from=%s to=%s last_err=%s",
                     envelope_from, to_addr, last_exc)
        raise last_exc

    def validate(self):
        """Lightweight SMTP connection check."""
        try:
            s = _open_smtp(self.smtp_host, self.smtp_port, self.timeout, self.use_tls)
            try:
                if self.smtp_user and self.smtp_pass:
                    s.login(self.smtp_user, self.smtp_pass)
                code = s.noop()[0]
            finally:
                try:
                    s.quit()
                except Exception:
                    pass
            return code == 250, f"NOOP response {code}"
        except Exception as e:
            return False, str(e)


def _html_to_text(html: str) -> str:
    """Strip HTML tags and produce a plain-text alternative.

    Used so every multipart/alternative has text first, HTML second —
    some spam filters score HTML-first higher.
    """
    import re as _re
    # Remove script/style blocks
    text = _re.sub(r'<(script|style)[^>]*>.*?</\1>', '', html, flags=_re.DOTALL | _re.IGNORECASE)
    # Replace <br>, <p>, <div> with newlines
    text = _re.sub(r'<br\s*/?>', '\n', text, flags=_re.IGNORECASE)
    text = _re.sub(r'</(p|div|tr|li)>', '\n', text, flags=_re.IGNORECASE)
    # Strip remaining tags
    text = _re.sub(r'<[^>]+>', '', text)
    # Decode common HTML entities
    text = text.replace('&nbsp;', ' ').replace('&', '&')
    text = text.replace('<', '<').replace('>', '>').replace('"', '"')
    # Collapse whitespace
    lines = [line.strip() for line in text.splitlines()]
    text = '\n'.join(line for line in lines if line)
    return text[:5000]  # Cap at 5k chars
