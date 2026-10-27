"""Tests for campaign A/B testing variants."""

import os

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import Campaign, Recipient, CampaignVariant
from dropoutjeep_lib.utils.ab_testing import (
    assign_variant, ensure_recipient_variant, variant_funnel, variant_html,
    get_variants, DEFAULT_VARIANT_KEY,
)


@pytest.fixture
def ctx():
    app.config['TESTING'] = True
    with app.app_context():
        db.create_all()
        campaign = Campaign(name='AB Test', subject='s', body_html='<p>control</p>', landing_html='<form></form>')
        db.session.add(campaign)
        db.session.commit()
        yield {'campaign': campaign}
        db.session.remove()
        db.drop_all()


def test_assign_variant_control_when_no_variants(ctx):
    campaign = ctx['campaign']
    assert assign_variant(campaign.id, 'tok1') == DEFAULT_VARIANT_KEY


def test_assign_variant_weighted(ctx):
    campaign = ctx['campaign']
    db.session.add(CampaignVariant(campaign_id=campaign.id, variant_key='a', name='A', weight=1))
    db.session.add(CampaignVariant(campaign_id=campaign.id, variant_key='b', name='B', weight=1))
    db.session.commit()
    keys = {assign_variant(campaign.id, f'tok{i}') for i in range(20)}
    assert 'a' in keys
    assert 'b' in keys


def test_ensure_recipient_variant_persists(ctx):
    campaign = ctx['campaign']
    db.session.add(CampaignVariant(campaign_id=campaign.id, variant_key='a', name='A', weight=1))
    db.session.commit()
    recipient = Recipient(campaign_id=campaign.id, email='victim@example.com')
    db.session.add(recipient)
    db.session.commit()
    key1 = ensure_recipient_variant(recipient)
    key2 = ensure_recipient_variant(recipient)
    assert key1 == key2
    assert recipient.variant_key == key1


def test_variant_html_uses_variant(ctx):
    campaign = ctx['campaign']
    db.session.add(CampaignVariant(
        campaign_id=campaign.id, variant_key='a', name='A',
        body_html='<p>variant a</p>', landing_html='<form>a</form>',
    ))
    db.session.commit()
    body, landing = variant_html(campaign, 'a')
    assert 'variant a' in body
    assert 'a</form>' in landing


def test_variant_html_fallback_to_campaign(ctx):
    campaign = ctx['campaign']
    body, landing = variant_html(campaign, 'missing')
    assert body == campaign.body_html
    assert landing == campaign.landing_html


def test_variant_funnel(ctx):
    campaign = ctx['campaign']
    db.session.add(CampaignVariant(campaign_id=campaign.id, variant_key='a', name='A', weight=1))
    db.session.commit()
    r1 = Recipient(campaign_id=campaign.id, email='a@example.com', variant_key='a')
    r2 = Recipient(campaign_id=campaign.id, email='b@example.com', variant_key=DEFAULT_VARIANT_KEY)
    db.session.add_all([r1, r2])
    db.session.commit()
    funnel = variant_funnel(campaign.id)
    keys = {row['variant_key'] for row in funnel}
    assert 'a' in keys
    assert DEFAULT_VARIANT_KEY in keys
