"""Tests for email attachment support in standard and enterprise mailers."""

import base64

from dropoutjeep_lib.utils.mailer import Mailer
from dropoutjeep_lib.utils.enterprise_mailer import EnterpriseMailer


def _attachment():
    return {
        'filename': 'image.iso',
        'content': b'fake iso content',
        'mime_type': 'application/x-iso9660-image',
    }


def _expected_b64():
    return base64.b64encode(_attachment()['content'])


def test_standard_mailer_prepares_attachment():
    mailer = Mailer(smtp_host='localhost', pool_size=0)
    msg, raw = mailer._prepare_message(
        envelope_from='sender@example.com',
        to_addr='recipient@example.com',
        subject='Test attachment',
        html_body='<html><body>Hello</body></html>',
        attachments=[_attachment()],
    )
    assert 'image.iso' in msg.as_string()
    assert 'application/x-iso9660-image' in msg.as_string()
    assert _expected_b64() in raw


def test_enterprise_mailer_prepares_attachment():
    mailer = EnterpriseMailer(
        smtp_host='localhost',
        enable_human_behavior=False,
        audit_log_dir=None,
    )
    msg, raw = mailer._prepare_message(
        envelope_from='sender@example.com',
        to_addr='recipient@example.com',
        subject='Test attachment',
        html_body='<html><body>Hello</body></html>',
        attachments=[_attachment()],
    )
    assert 'image.iso' in msg.as_string()
    assert 'application/x-iso9660-image' in msg.as_string()
    assert _expected_b64() in raw
