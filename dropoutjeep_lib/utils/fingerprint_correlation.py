"""Device fingerprint correlation across recipients and campaigns.

The browser fingerprint collector (static/js/fingerprint.js) POSTs stable
browser traits to /api/fingerprint/<token>. This module turns those traits
into a hash and links recipients that share the same device, so operators can
see multi-session behavior even when the same person is targeted across
multiple campaigns.
"""

import hashlib
import json
import logging
from typing import Any

from dropoutjeep_lib import db
from dropoutjeep_lib.models import Recipient, RecipientFingerprint, Event, Campaign

logger = logging.getLogger(__name__)


def compute_device_hash(data: dict[str, Any]) -> str | None:
    """Return a deterministic hash for browser-collected fingerprint data.

    The hash is intentionally fuzzy: it ignores volatile values (referrer,
    exact UA string) and focuses on hardware/rendering traits that stay stable
    across sessions from the same browser profile.
    """
    if not data or not isinstance(data, dict):
        return None

    screen = data.get("screen") or {}
    plugins = data.get("plugins") or []
    plugin_names = ",".join(sorted({p.get("name", "") for p in plugins if isinstance(p, dict)}))

    components = [
        str(data.get("language", "")),
        str(data.get("platform", "")),
        f"{screen.get('width')}x{screen.get('height')}x{screen.get('colorDepth')}",
        str(screen.get("pixelRatio", "")),
        str(data.get("timezone", "")),
        str(data.get("touch", "")),
        str(data.get("cores", "")),
        str(data.get("memory", "")),
        str(data.get("canvas_hash", "")),
        str(data.get("webgl_hash", "")),
        plugin_names,
    ]
    payload = "|".join(components)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def get_or_create_recipient_fingerprint(
    recipient: Recipient,
    campaign_id: int,
    ip: str | None,
    ua: str | None,
    device_data: dict[str, Any],
) -> RecipientFingerprint:
    """Return the RecipientFingerprint row for a recipient, creating it if needed.

    Updates the device_hash when new browser fingerprint data arrives.
    """
    fp = RecipientFingerprint.query.filter_by(
        recipient_id=recipient.id,
        campaign_id=campaign_id,
    ).first()

    device_hash = compute_device_hash(device_data)

    if fp is None:
        from dropoutjeep_lib.utils.sandbox_evasion import fingerprint_request
        fp = RecipientFingerprint(
            recipient_id=recipient.id,
            campaign_id=campaign_id,
            first_seen_ip=ip,
            first_seen_ua=ua,
            first_seen_hash=fingerprint_request(ip or "", ua or ""),
            device_hash=device_hash,
        )
        db.session.add(fp)
    elif device_hash and fp.device_hash != device_hash:
        fp.device_hash = device_hash
        db.session.add(fp)

    db.session.commit()
    return fp


def find_correlated_recipients(device_hash: str | None, exclude_recipient_id: int | None = None):
    """Return all recipients that share a device fingerprint hash.

    Result is grouped by device_hash for easy display.
    """
    if not device_hash:
        return []

    query = RecipientFingerprint.query.filter_by(device_hash=device_hash)
    if exclude_recipient_id is not None:
        query = query.filter(RecipientFingerprint.recipient_id != exclude_recipient_id)

    fingerprints = query.all()
    recipient_ids = [fp.recipient_id for fp in fingerprints]
    recipients = {r.id: r for r in Recipient.query.filter(Recipient.id.in_(recipient_ids)).all()}
    campaigns = {c.id: c for c in Campaign.query.filter(Campaign.id.in_([fp.campaign_id for fp in fingerprints])).all()}

    results = []
    for fp in fingerprints:
        r = recipients.get(fp.recipient_id)
        c = campaigns.get(fp.campaign_id)
        if r and c:
            results.append({
                "recipient_id": r.id,
                "email": r.email,
                "campaign_id": c.id,
                "campaign_name": c.name,
                "first_seen_at": fp.first_seen_at.isoformat() if fp.first_seen_at else None,
                "first_seen_ip": fp.first_seen_ip,
            })
    return results


def get_recipient_correlations(recipient_id: int):
    """Return all recipients correlated with the given recipient by device hash."""
    fp = RecipientFingerprint.query.filter_by(recipient_id=recipient_id).first()
    if not fp or not fp.device_hash:
        return []
    return find_correlated_recipients(fp.device_hash, exclude_recipient_id=recipient_id)


def get_correlated_events(recipient_id: int, limit: int = 100):
    """Return recent events for all recipients sharing a device fingerprint."""
    correlated = get_recipient_correlations(recipient_id)
    correlated_ids = [r["recipient_id"] for r in correlated]
    correlated_ids.append(recipient_id)

    events = Event.query.filter(Event.recipient_id.in_(correlated_ids)) \
        .order_by(Event.created_at.desc()) \
        .limit(limit) \
        .all()

    return [
        {
            "id": e.id,
            "recipient_id": e.recipient_id,
            "campaign_id": e.campaign_id,
            "event_type": e.event_type,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in events
    ]
