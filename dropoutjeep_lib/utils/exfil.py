"""Exfiltration channel helpers for authorized phishing simulations.

Landing pages can send small amounts of data back to DropoutJeep over HTTP,
DNS-like requests, or WebSocket. Each event is tied to the recipient token
and campaign for analysis.
"""

import base64
import json
import logging
from typing import Any

from dropoutjeep_lib import db
from dropoutjeep_lib.models import Event, Recipient, Campaign

logger = logging.getLogger(__name__)


def _get_recipient(token: str) -> Recipient | None:
    return Recipient.query.filter_by(token=token).first()


def record_http_exfil(token: str, data: dict[str, Any], ip: str | None, ua: str | None) -> bool:
    """Store an HTTP exfiltration event from a landing page."""
    r = _get_recipient(token)
    if not r:
        return False

    e = Event(
        campaign_id=r.campaign_id,
        recipient_id=r.id,
        event_type='exfil_http',
        meta=json.dumps({
            'data': data,
            'ip': ip,
            'ua': ua,
        }, default=str),
    )
    db.session.add(e)
    db.session.commit()
    return True


def record_dns_exfil(token: str, encoded_data: str, ip: str | None, ua: str | None) -> bool:
    """Store a DNS-style exfiltration event.

    ``encoded_data`` is typically base64 or hex data sent as a subdomain/query
    parameter from the landing page.
    """
    r = _get_recipient(token)
    if not r:
        return False

    decoded = _try_decode(encoded_data)
    e = Event(
        campaign_id=r.campaign_id,
        recipient_id=r.id,
        event_type='exfil_dns',
        meta=json.dumps({
            'encoded': encoded_data,
            'decoded': decoded,
            'ip': ip,
            'ua': ua,
        }, default=str),
    )
    db.session.add(e)
    db.session.commit()
    return True


def _try_decode(value: str) -> str:
    """Best-effort decode of base64 or hex exfil data."""
    try:
        return base64.b64decode(value, validate=True).decode('utf-8', errors='replace')
    except Exception:
        pass
    try:
        if all(c in '0123456789abcdefABCDEF' for c in value):
            return bytes.fromhex(value).decode('utf-8', errors='replace')
    except Exception:
        pass
    return value
