"""Canary token helpers for DropoutJeep."""

import json
from datetime import datetime

from dropoutjeep_lib import db
from dropoutjeep_lib.models import CanaryToken, Campaign, Event


def build_canary_url(base_url: str, token: str, token_type: str = 'url') -> str:
    """Return the public URL for a canary token."""
    base = (base_url or '').rstrip('/')
    if token_type == 'image':
        return f"{base}/canary/{token}.gif"
    return f"{base}/canary/{token}"


def get_canary_embeds(campaign_id: int | None, base_url: str) -> dict:
    """Return active canary embed strings for a campaign.

    Returns a dict with keys:
      - CANARY_URL: raw URL string (or empty string)
      - CANARY_IMAGE: <img> tag string (or empty string)
    """
    result = {'CANARY_URL': '', 'CANARY_IMAGE': ''}
    if campaign_id is None:
        return result

    canaries = CanaryToken.query.filter_by(
        campaign_id=campaign_id, status='active'
    ).order_by(CanaryToken.created_at).all()

    for c in canaries:
        url = build_canary_url(base_url, c.token, c.token_type)
        if c.token_type == 'url' and not result['CANARY_URL']:
            result['CANARY_URL'] = url
        elif c.token_type == 'image' and not result['CANARY_IMAGE']:
            result['CANARY_IMAGE'] = (
                f'<img src="{url}" width="1" height="1" alt="" '
                f'style="display:none;border:0;" />'
            )
        if result['CANARY_URL'] and result['CANARY_IMAGE']:
            break
    return result


def record_canary_trigger(canary: CanaryToken, request) -> Event:
    """Log a canary trigger event and update the token status."""
    meta = {
        'canary_id': canary.id,
        'canary_name': canary.name,
        'token_type': canary.token_type,
        'ip_address': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', ''),
        'referer': request.headers.get('Referer', ''),
    }
    event = Event(
        campaign_id=canary.campaign_id,
        event_type='canary_triggered',
        meta=json.dumps(meta, default=str),
    )
    canary.status = 'triggered'
    canary.triggered_at = datetime.utcnow()
    canary.trigger_meta = json.dumps(meta, default=str)
    db.session.add(event)
    db.session.add(canary)
    db.session.commit()

    try:
        from dropoutjeep_lib.utils.live import push_event
        push_event('canary_triggered', campaign_id=canary.campaign_id)
    except Exception:
        pass

    return event
