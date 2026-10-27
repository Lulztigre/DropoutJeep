"""Turn bounce mail (DSNs) into events.

A delivery status notification is a multipart/report with a
message/delivery-status part. The failed address lives in Final-Recipient and
the outcome in Action, so those are parsed properly rather than by grabbing the
first email-shaped string in the body, which is usually the postmaster address
or your own Return-Path.
"""

import re
from email.message import Message

from dropoutjeep_lib import db
from dropoutjeep_lib.models import Event, Recipient

_ADDR = re.compile(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}')
_FINAL = re.compile(r'Final-Recipient:\s*(?:rfc822|utf-8)\s*;\s*(\S+)', re.IGNORECASE)
_ORIGINAL = re.compile(r'Original-Recipient:\s*(?:rfc822|utf-8)\s*;\s*(\S+)', re.IGNORECASE)
_ACTION = re.compile(r'Action:\s*(\w+)', re.IGNORECASE)
_STATUS = re.compile(r'Status:\s*([\d.]+)', re.IGNORECASE)
_DIAGNOSTIC = re.compile(r'Diagnostic-Code:\s*(.+)', re.IGNORECASE)


def _delivery_status_text(msg: Message) -> str:
    """Concatenate the message/delivery-status parts, which is where the truth is."""
    chunks = []
    if not msg.is_multipart():
        return ""
    for part in msg.walk():
        if part.get_content_type() == 'message/delivery-status':
            payload = part.get_payload()
            if isinstance(payload, list):
                for sub in payload:
                    try:
                        chunks.append(sub.as_string())
                    except Exception:
                        chunks.append(str(sub))
            elif isinstance(payload, str):
                chunks.append(payload)
    return "\n".join(chunks)


def _body_text(msg: Message) -> str:
    if msg.is_multipart():
        out = []
        for part in msg.walk():
            if part.get_content_type() in ('text/plain', 'message/delivery-status'):
                payload = part.get_payload(decode=True)
                if payload:
                    out.append(payload.decode(errors='ignore'))
        return "\n".join(out)
    payload = msg.get_payload(decode=True)
    return payload.decode(errors='ignore') if payload else ""


def extract_bounce_recipient(msg: Message):
    """Return (address, action, status, diagnostic) for a DSN.

    Falls back to the first plausible address in the body when there is no
    structured delivery-status part, because some MTAs send free-form bounces.
    """
    ds = _delivery_status_text(msg)
    action = status = diagnostic = None
    address = None

    if ds:
        m = _ACTION.search(ds)
        action = m.group(1).lower() if m else None
        m = _STATUS.search(ds)
        status = m.group(1) if m else None
        m = _DIAGNOSTIC.search(ds)
        diagnostic = m.group(1).strip() if m else None
        m = _FINAL.search(ds) or _ORIGINAL.search(ds)
        if m:
            address = m.group(1).strip('<>;, ')
    if not address:
        body = _body_text(msg)
        m = _ADDR.search(body or "")
        if m:
            address = m.group(0)
    return address, action, status, diagnostic


def parse_bounce(msg: Message):
    """Record a bounce event when the DSN reports a failure.

    Returns the address that bounced, or None. Delayed notifications are ignored:
    they are not a failure and counting them inflates the bounce rate.
    """
    address, action, status, diagnostic = extract_bounce_recipient(msg)
    if not address:
        return None
    if action and action not in ('failed', 'failure', 'rejected'):
        return None
    if status and status.startswith('4.'):
        return None

    recipient = Recipient.query.filter_by(email=address).first()
    if not recipient:
        return address

    meta = f"Bounced: {msg.get('Subject', '')}"
    if status:
        meta += f" [{status}]"
    if diagnostic:
        meta += f" {diagnostic[:200]}"

    event = Event(
        campaign_id=recipient.campaign_id,
        recipient_id=recipient.id,
        event_type="bounce",
        meta=meta,
    )
    db.session.add(event)
    db.session.commit()
    return address
