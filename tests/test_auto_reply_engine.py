"""Tests for the auto-reply engine IMAP integration and auto-approval."""

import email
import os
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import (
    User, Campaign, SendingProfile, Subsidiary, AutoReplyRule, PendingReply
)
from dropoutjeep_lib.utils.auto_replier import AutoReplier, process_all_auto_replies


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def _build_imap_response(sender, subject, message_id='msg-1'):
    msg = email.message.EmailMessage()
    msg['From'] = sender
    msg['Subject'] = subject
    msg['Message-ID'] = message_id
    msg['Date'] = datetime.utcnow().isoformat()
    msg.set_content('original body')
    raw = msg.as_bytes()
    return ('OK', [(b'1 (RFC822 {len})'.replace(b'{len}', str(len(raw)).encode()), raw)])


def test_auto_replier_from_sending_profile(client):
    with app.app_context():
        sp = SendingProfile(
            name='Test',
            smtp_host='smtp.example.com',
            imap_host='imap.example.com',
            imap_port=993,
            imap_user='user@example.com',
            imap_use_tls=True,
        )
        sp.set_imap_pass('secret')
        db.session.add(sp)
        db.session.commit()

        replier = AutoReplier.from_sending_profile(sp)
        assert replier.imap_host == 'imap.example.com'
        assert replier.imap_user == 'user@example.com'
        assert replier.imap_pass == 'secret'
        assert replier.imap_port == 993
        assert replier.imap_use_tls is True


def test_process_auto_replies_stages_pending_when_not_auto_approve(client):
    with app.app_context():
        sub = Subsidiary(name='Sub', sending_domain='example.com', display_name='Sub', from_address='sub@example.com')
        sp = SendingProfile(name='Test', smtp_host='smtp.example.com', imap_host='imap.example.com', imap_user='u', imap_port=993)
        sp.set_imap_pass('p')
        c = Campaign(name='C', subject='s', body_html='b', landing_html='l', sending_profile=sp)
        rule = AutoReplyRule(
            name='R1',
            campaign=c,
            reply_template_html='<p>Reply</p>',
            auto_approve=False,
            is_active=True,
        )
        db.session.add_all([sub, sp, c, rule])
        db.session.commit()

        replier = AutoReplier.from_sending_profile(sp)

        mock_conn = MagicMock()
        mock_conn.search.return_value = ('OK', [b'1'])
        mock_conn.fetch.return_value = _build_imap_response('victim@example.com', 'Re: Hello', 'msg-1')
        mock_conn.store.return_value = ('OK', None)

        with patch.object(replier, '_imap_conn', return_value=mock_conn):
            sent, failed, staged = replier.process_auto_replies(rule, sp)

        assert staged == 1
        assert sent == 0
        assert failed == 0
        assert PendingReply.query.filter_by(status='pending').count() == 1


def test_process_auto_replies_sends_when_auto_approve(client):
    with app.app_context():
        sub = Subsidiary(name='Sub', sending_domain='example.com', display_name='Sub', from_address='sub@example.com')
        sp = SendingProfile(name='Test', smtp_host='smtp.example.com', smtp_user='u', imap_host='imap.example.com', imap_user='u', imap_port=993)
        sp.set_smtp_pass('p')
        sp.set_imap_pass('p')
        c = Campaign(name='C', subject='s', body_html='b', landing_html='l', sending_profile=sp)
        rule = AutoReplyRule(
            name='R1',
            campaign=c,
            reply_template_html='<p>Reply</p>',
            auto_approve=True,
            is_active=True,
        )
        db.session.add_all([sub, sp, c, rule])
        db.session.commit()

        replier = AutoReplier.from_sending_profile(sp)

        mock_conn = MagicMock()
        mock_conn.search.return_value = ('OK', [b'1'])
        mock_conn.fetch.return_value = _build_imap_response('victim@example.com', 'Re: Hello', 'msg-2')
        mock_conn.store.return_value = ('OK', None)

        with patch.object(replier, '_imap_conn', return_value=mock_conn):
            with patch.object(replier, 'send_reply', return_value=(True, None)) as mock_send:
                sent, failed, staged = replier.process_auto_replies(rule, sp)

        assert sent == 1
        assert failed == 0
        assert staged == 0
        mock_send.assert_called_once()
