"""Timing analytics for phishing simulations.

Measures intervals between campaign events per recipient, e.g. time from email
sent to open, sent to click, and click to credential submission.
"""

from datetime import datetime
from typing import Dict, List, Optional

from dropoutjeep_lib.models import Event, Recipient


def _first_event_time(events, event_type: str) -> Optional[datetime]:
    for e in events:
        if e.event_type == event_type:
            return e.created_at
    return None


def recipient_timing(recipient_id: int) -> Dict:
    """Return timing intervals for a single recipient."""
    events = Event.query.filter_by(recipient_id=recipient_id) \
        .order_by(Event.created_at).all()
    if not events:
        return {}

    sent = _first_event_time(events, 'sent')
    open_ = _first_event_time(events, 'open')
    click = _first_event_time(events, 'click')
    cred = _first_event_time(events, 'credential_attempt')
    mfa = _first_event_time(events, 'mfa_attempt')

    def _seconds(a: Optional[datetime], b: Optional[datetime]) -> Optional[float]:
        if a and b:
            return max(0.0, (b - a).total_seconds())
        return None

    return {
        'sent_to_open_seconds': _seconds(sent, open_),
        'sent_to_click_seconds': _seconds(sent, click),
        'click_to_credential_seconds': _seconds(click, cred),
        'click_to_mfa_seconds': _seconds(click, mfa),
        'sent_to_credential_seconds': _seconds(sent, cred),
        'sent_to_mfa_seconds': _seconds(sent, mfa),
    }


def _percentile(values: List[float], pct: float) -> Optional[float]:
    if not values:
        return None
    sorted_vals = sorted(values)
    k = (len(sorted_vals) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (k - f) * (sorted_vals[c] - sorted_vals[f])


def campaign_timing_summary(campaign_id: int) -> Dict:
    """Return aggregate timing metrics for a campaign."""
    recipients = Recipient.query.filter_by(campaign_id=campaign_id).all()
    per_recipient = []
    for r in recipients:
        timing = recipient_timing(r.id)
        if any(v is not None for v in timing.values()):
            per_recipient.append({
                'recipient_id': r.id,
                'email': r.email,
                **timing,
            })

    def _collect(key: str) -> List[float]:
        return [p[key] for p in per_recipient if p[key] is not None]

    metrics = {}
    for key in [
        'sent_to_open_seconds',
        'sent_to_click_seconds',
        'click_to_credential_seconds',
        'click_to_mfa_seconds',
        'sent_to_credential_seconds',
        'sent_to_mfa_seconds',
    ]:
        values = _collect(key)
        metrics[key] = {
            'count': len(values),
            'min': min(values) if values else None,
            'max': max(values) if values else None,
            'median': _percentile(values, 50),
            'p90': _percentile(values, 90),
            'p95': _percentile(values, 95),
        }

    return {
        'campaign_id': campaign_id,
        'recipients_analyzed': len(per_recipient),
        'metrics': metrics,
        'per_recipient': per_recipient,
    }
