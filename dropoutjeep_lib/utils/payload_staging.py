"""Payload staging helpers for authorized phishing simulations.

DropoutJeep can attach Office documents, HTA files, and Windows shortcuts to a
campaign. The payloads are stored encrypted at rest and served either as raw
downloads or through an HTML smuggling dropper.
"""

from dropoutjeep_lib import db
from dropoutjeep_lib.models import Payload, Campaign, Recipient


def list_payloads(campaign_id: int):
    """Return all payloads for a campaign as dicts."""
    return [
        {
            "id": p.id,
            "name": p.name,
            "filename": p.filename,
            "extension": p.extension,
            "mime_type": p.mime_type,
            "per_recipient": p.per_recipient,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        }
        for p in Payload.query.filter_by(campaign_id=campaign_id).order_by(Payload.id).all()
    ]


def create_payload(
    campaign_id: int,
    name: str,
    filename: str,
    content: bytes,
    per_recipient: bool = False,
) -> Payload | None:
    """Create and persist a new campaign payload."""
    from dropoutjeep_lib.utils.html_smuggler import PAYLOAD_MIME_TYPES

    ext = filename.split('.')[-1].lower() if '.' in filename else 'bin'
    if ext not in PAYLOAD_MIME_TYPES:
        return None

    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        return None

    payload = Payload(
        campaign_id=campaign_id,
        name=name,
        filename=filename,
        extension=ext,
        mime_type=PAYLOAD_MIME_TYPES.get(ext, 'application/octet-stream'),
        per_recipient=per_recipient,
    )
    payload.set_content(content)
    db.session.add(payload)
    db.session.commit()
    return payload


def get_payload_for_recipient(payload_id: int, token: str) -> tuple[Payload | None, Recipient | None, Campaign | None]:
    """Return the payload, recipient, and campaign if all are valid."""
    payload = Payload.query.get(payload_id)
    if not payload:
        return None, None, None

    recipient = Recipient.query.filter_by(token=token, campaign_id=payload.campaign_id).first()
    if not recipient:
        return None, None, None

    return payload, recipient, payload.campaign


def get_payload_content(payload: Payload, recipient_token: str | None = None) -> bytes:
    """Return payload bytes, polymorphed per recipient when configured."""
    content = payload.get_content()
    if payload.per_recipient and recipient_token:
        from dropoutjeep_lib.utils.polymorphic_payloads import polymorph_payload
        return polymorph_payload(content, payload.extension, recipient_token)
    return content
