"""Campaign funnel computation.

Stages represent distinct recipients that reached each milestone.
Drop-off is the percentage of recipients that did not progress from the
previous stage.
"""

from sqlalchemy import func

from dropoutjeep_lib import db
from dropoutjeep_lib.models import Campaign, Event, Recipient


STAGES = [
    ('total', 'Recipients'),
    ('sent', 'Sent'),
    ('delivered', 'Delivered'),
    ('opened', 'Opened'),
    ('clicked', 'Clicked'),
    ('credentials', 'Credentials'),
    ('mfa_failure', 'MFA Failure'),
]


def _distinct_event_count(campaign_id: int, event_types: list[str]) -> int:
    return db.session.query(func.count(func.distinct(Event.recipient_id))).filter(
        Event.campaign_id == campaign_id,
        Event.event_type.in_(event_types)
    ).scalar() or 0


def compute_funnel(campaign_id: int) -> list[dict]:
    """Return funnel stages with counts and drop-off rates."""
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        return []

    total = db.session.query(func.count(Recipient.id)).filter(
        Recipient.campaign_id == campaign_id
    ).scalar() or 0

    sent = _distinct_event_count(campaign_id, ['sent', 'send_failed'])
    delivered = _distinct_event_count(campaign_id, ['sent'])
    opened = _distinct_event_count(campaign_id, ['open'])
    clicked = _distinct_event_count(campaign_id, ['click'])
    credentials = _distinct_event_count(campaign_id, ['credential_attempt'])
    mfa_failure = _distinct_event_count(campaign_id, ['mfa_attempt'])

    counts = {
        'total': total,
        'sent': sent,
        'delivered': delivered,
        'opened': opened,
        'clicked': clicked,
        'credentials': credentials,
        'mfa_failure': mfa_failure,
    }

    result = []
    prev_count = None
    for key, label in STAGES:
        count = counts[key]
        if prev_count and prev_count > 0:
            drop_off = round((prev_count - count) / prev_count * 100, 1)
        else:
            drop_off = 0.0
        result.append({
            'stage': key,
            'label': label,
            'count': count,
            'drop_off_rate': drop_off,
        })
        prev_count = count

    return result
