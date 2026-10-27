"""A/B testing utilities for campaign variants."""

import hashlib
from typing import List, Optional

from dropoutjeep_lib import db
from dropoutjeep_lib.models import CampaignVariant, Recipient


DEFAULT_VARIANT_KEY = 'control'


def get_variants(campaign_id: int) -> List[CampaignVariant]:
    return CampaignVariant.query.filter_by(campaign_id=campaign_id) \
        .order_by(CampaignVariant.variant_key).all()


def assign_variant(campaign_id: int, token: str) -> str:
    """Deterministically assign a recipient token to a variant by weight."""
    variants = get_variants(campaign_id)
    if not variants:
        return DEFAULT_VARIANT_KEY

    total_weight = sum(v.weight for v in variants)
    if total_weight <= 0:
        return variants[0].variant_key if variants else DEFAULT_VARIANT_KEY

    digest = hashlib.sha256(f"{campaign_id}:{token}".encode()).hexdigest()
    bucket = int(digest, 16) % total_weight
    cumulative = 0
    for variant in variants:
        cumulative += variant.weight
        if bucket < cumulative:
            return variant.variant_key
    return variants[-1].variant_key


def ensure_recipient_variant(recipient: Recipient) -> str:
    """Assign and persist a variant for a recipient if not already set."""
    if recipient.variant_key:
        return recipient.variant_key
    key = assign_variant(recipient.campaign_id, recipient.token)
    recipient.variant_key = key
    db.session.add(recipient)
    db.session.commit()
    return key


def variant_funnel(campaign_id: int) -> List[dict]:
    """Return recipient counts grouped by variant for the campaign."""
    from sqlalchemy import func
    rows = db.session.query(
        Recipient.variant_key,
        func.count(Recipient.id),
    ).filter_by(campaign_id=campaign_id).group_by(Recipient.variant_key).all()
    return [
        {'variant_key': key or DEFAULT_VARIANT_KEY, 'recipient_count': count}
        for key, count in rows
    ]


def variant_html(campaign: object, variant_key: Optional[str]) -> tuple[str, str]:
    """Return (body_html, landing_html) for a campaign and variant key."""
    if not variant_key or variant_key == DEFAULT_VARIANT_KEY:
        return campaign.body_html or campaign.template_html, campaign.landing_html
    variant = CampaignVariant.query.filter_by(
        campaign_id=campaign.id, variant_key=variant_key
    ).first()
    if variant:
        return variant.body_html or campaign.body_html, variant.landing_html or campaign.landing_html
    return campaign.body_html or campaign.template_html, campaign.landing_html
