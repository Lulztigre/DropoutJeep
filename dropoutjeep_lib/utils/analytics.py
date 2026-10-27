"""Analytics helpers for campaign reporting.

Provides per-recipient timelines, GeoIP enrichment, CSV/PDF export, and
click-heatmap aggregation from the Event table.
"""

import csv
import json
import logging
from datetime import datetime
from io import BytesIO, StringIO
from typing import Any

from dropoutjeep_lib.models import Campaign, Recipient, Event, CapturedCredential, CapturedCookie
from .geoip import enrich_ip, format_geo

logger = logging.getLogger(__name__)


def get_recipient_timeline(recipient_id: int) -> list[dict]:
    """Return chronological event stream for one recipient with geo enrichment."""
    events = Event.query.filter_by(recipient_id=recipient_id).order_by(Event.created_at.asc()).all()
    result = []
    for e in events:
        geo = enrich_ip(e.ip_address) if e.ip_address else {}
        result.append({
            'id': e.id,
            'event_type': e.event_type,
            'created_at': e.created_at.isoformat() if e.created_at else None,
            'ip_address': e.ip_address,
            'geo': format_geo(geo),
            'user_agent': e.user_agent,
            'meta': e.meta,
        })
    return result


def get_campaign_events(campaign_id: int, event_type: str | None = None) -> list[Event]:
    """Return events for a campaign, optionally filtered by type."""
    q = Event.query.filter_by(campaign_id=campaign_id)
    if event_type:
        q = q.filter_by(event_type=event_type)
    return q.order_by(Event.created_at.desc()).all()


def get_heatmap_data(campaign_id: int) -> list[dict]:
    """Aggregate heatmap_click events into (selector, x, y) points."""
    events = Event.query.filter_by(campaign_id=campaign_id, event_type='heatmap_click').all()
    points = []
    for e in events:
        try:
            meta = json.loads(e.meta or '{}')
            points.append({
                'x': meta.get('x'),
                'y': meta.get('y'),
                'selector': meta.get('selector'),
                'recipient_id': e.recipient_id,
                'created_at': e.created_at.isoformat() if e.created_at else None,
            })
        except Exception:
            logger.warning("Failed to parse heatmap event meta: %s", e.meta)
    return points


def export_campaign_csv(campaign_id: int) -> str:
    """Return a CSV string with campaign events, credentials, and cookies."""
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['section', 'id', 'timestamp', 'type', 'recipient_email', 'ip', 'geo', 'details'])

    campaign = Campaign.query.get(campaign_id)
    recipient_map = {r.id: r.email for r in Recipient.query.filter_by(campaign_id=campaign_id).all()}

    for e in Event.query.filter_by(campaign_id=campaign_id).order_by(Event.created_at.desc()):
        geo = format_geo(enrich_ip(e.ip_address)) if e.ip_address else ''
        writer.writerow([
            'event',
            e.id,
            e.created_at.isoformat() if e.created_at else '',
            e.event_type,
            recipient_map.get(e.recipient_id, ''),
            e.ip_address or '',
            geo,
            e.meta or '',
        ])

    for c in CapturedCredential.query.filter_by(campaign_id=campaign_id):
        writer.writerow([
            'credential',
            c.id,
            c.captured_at.isoformat() if c.captured_at else '',
            c.credential_type,
            recipient_map.get(c.recipient_id, ''),
            '',
            '',
            f"field={c.field_name} username={c.username}",
        ])

    for c in CapturedCookie.query.filter_by(campaign_id=campaign_id):
        writer.writerow([
            'cookie',
            c.id,
            c.captured_at.isoformat() if c.captured_at else '',
            c.source,
            recipient_map.get(c.recipient_id, ''),
            '',
            '',
            f"name={c.cookie_name} domain={c.cookie_domain}",
        ])

    return output.getvalue()


def export_campaign_pdf(campaign_id: int) -> bytes:
    """Return a PDF byte stream summarizing campaign results."""
    try:
        from fpdf import FPDF
        from fpdf.enums import XPos, YPos
    except ImportError as exc:
        raise RuntimeError("fpdf2 is required for PDF export") from exc

    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        raise ValueError("Campaign not found")

    events = Event.query.filter_by(campaign_id=campaign_id).all()
    creds = CapturedCredential.query.filter_by(campaign_id=campaign_id).count()
    cookies = CapturedCookie.query.filter_by(campaign_id=campaign_id).count()

    counts: dict[str, int] = {}
    unique_ips: set[str] = set()
    for e in events:
        counts[e.event_type] = counts.get(e.event_type, 0) + 1
        if e.ip_address:
            unique_ips.add(e.ip_address)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 16)
    pdf.cell(0, 10, f'Campaign Report: {campaign.name}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font('Helvetica', '', 12)
    pdf.cell(0, 8, f'Generated: {datetime.now().isoformat()}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)

    pdf.set_font('Helvetica', 'B', 13)
    pdf.cell(0, 8, 'Summary', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font('Helvetica', '', 11)
    pdf.cell(0, 6, f"Total events: {len(events)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f"Unique IPs: {len(unique_ips)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f"Credentials captured: {creds}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f"Cookies captured: {cookies}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)

    pdf.set_font('Helvetica', 'B', 13)
    pdf.cell(0, 8, 'Event Breakdown', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font('Helvetica', '', 11)
    for event_type, count in sorted(counts.items()):
        pdf.cell(0, 6, f"{event_type}: {count}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    return bytes(pdf.output())


def compare_campaigns(campaign_ids: list[int]) -> list[dict]:
    """Return side-by-side summary metrics for the requested campaigns."""
    from dropoutjeep_lib.utils.funnel import compute_funnel

    summaries = []
    for cid in campaign_ids:
        campaign = Campaign.query.get(cid)
        if not campaign:
            continue
        funnel = {s['stage']: s for s in compute_funnel(cid)}
        summaries.append({
            'id': campaign.id,
            'name': campaign.name,
            'created_at': campaign.created_at.isoformat() if campaign.created_at else None,
            'total_recipients': funnel.get('total', {}).get('count', 0),
            'sent': funnel.get('sent', {}).get('count', 0),
            'opened': funnel.get('opened', {}).get('count', 0),
            'clicked': funnel.get('clicked', {}).get('count', 0),
            'credentials': funnel.get('credentials', {}).get('count', 0),
            'click_rate': _rate(funnel, 'clicked', 'opened'),
            'conversion_rate': _rate(funnel, 'credentials', 'clicked'),
        })
    return summaries


def _rate(funnel: dict, numerator: str, denominator: str) -> float:
    num = funnel.get(numerator, {}).get('count', 0)
    den = funnel.get(denominator, {}).get('count', 0)
    if not den:
        return 0.0
    return round(num / den * 100, 1)

    return bytes(pdf.output())
