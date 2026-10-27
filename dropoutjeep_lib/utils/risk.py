"""Recipient human-risk scoring based on engagement telemetry.

Risk is computed on demand from the Event table.  The more severe the
action taken by the recipient, the higher the weighted contribution.
"""

from sqlalchemy import func

from dropoutjeep_lib import db
from dropoutjeep_lib.models import Event, Recipient


RISK_WEIGHTS = {
    'open': 1,
    'click': 3,
    'credential_attempt': 7,
    'mfa_attempt': 10,
}


def _bucket(score: int) -> str:
    if score == 0:
        return 'low'
    if score <= 30:
        return 'medium'
    if score <= 60:
        return 'high'
    return 'critical'


def recipient_risk_score(recipient_id: int) -> dict:
    """Return the risk score, bucket, and event breakdown for one recipient."""
    rows = db.session.query(
        Event.event_type,
        func.count(Event.id).label('cnt')
    ).filter(
        Event.recipient_id == recipient_id,
        Event.event_type.in_(list(RISK_WEIGHTS.keys()))
    ).group_by(Event.event_type).all()

    breakdown = {event_type: 0 for event_type in RISK_WEIGHTS}
    score = 0
    for event_type, cnt in rows:
        breakdown[event_type] = cnt
        score += RISK_WEIGHTS.get(event_type, 0) * cnt

    score = min(100, score)
    return {
        'score': score,
        'bucket': _bucket(score),
        'breakdown': breakdown,
    }


def recipient_click_count(recipient_id: int) -> int:
    """Return the number of click events recorded for one recipient."""
    return db.session.query(Event).filter(
        Event.recipient_id == recipient_id,
        Event.event_type == 'click'
    ).count()


def campaign_risk_summary(campaign_id: int) -> dict:
    """Return average risk score and high-risk recipient count for a campaign."""
    recipient_ids = db.session.query(Recipient.id).filter(
        Recipient.campaign_id == campaign_id
    ).all()
    if not recipient_ids:
        return {'avg_score': 0, 'high_risk_count': 0, 'recipient_count': 0}

    total = 0
    high = 0
    for (rid,) in recipient_ids:
        score = recipient_risk_score(rid)['score']
        total += score
        if score > 60:
            high += 1

    return {
        'avg_score': round(total / len(recipient_ids), 1),
        'high_risk_count': high,
        'recipient_count': len(recipient_ids),
    }
