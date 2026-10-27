"""Tests for timing analytics."""

import os
from datetime import datetime, timedelta

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import Campaign, Recipient, Event
from dropoutjeep_lib.utils.timing import recipient_timing, campaign_timing_summary


@pytest.fixture
def ctx():
    app.config['TESTING'] = True
    with app.app_context():
        db.create_all()
        campaign = Campaign(name='Timing Test', subject='s', body_html='b', landing_html='l')
        db.session.add(campaign)
        db.session.commit()
        recipient = Recipient(campaign_id=campaign.id, email='victim@example.com')
        db.session.add(recipient)
        db.session.commit()
        yield {'campaign': campaign, 'recipient': recipient}
        db.session.remove()
        db.drop_all()


def _event(recipient, campaign, event_type, when):
    e = Event(recipient_id=recipient.id, campaign_id=campaign.id, event_type=event_type)
    e.created_at = when
    db.session.add(e)


def test_recipient_timing(ctx):
    campaign = ctx['campaign']
    recipient = ctx['recipient']
    base = datetime.utcnow()
    _event(recipient, campaign, 'sent', base)
    _event(recipient, campaign, 'open', base + timedelta(seconds=10))
    _event(recipient, campaign, 'click', base + timedelta(seconds=30))
    _event(recipient, campaign, 'credential_attempt', base + timedelta(seconds=60))
    db.session.commit()

    timing = recipient_timing(recipient.id)
    assert timing['sent_to_open_seconds'] == 10.0
    assert timing['sent_to_click_seconds'] == 30.0
    assert timing['click_to_credential_seconds'] == 30.0
    assert timing['sent_to_credential_seconds'] == 60.0


def test_campaign_timing_summary(ctx):
    campaign = ctx['campaign']
    recipient = ctx['recipient']
    base = datetime.utcnow()
    _event(recipient, campaign, 'sent', base)
    _event(recipient, campaign, 'click', base + timedelta(seconds=30))
    db.session.commit()

    summary = campaign_timing_summary(campaign.id)
    assert summary['campaign_id'] == campaign.id
    assert summary['recipients_analyzed'] == 1
    assert summary['metrics']['sent_to_click_seconds']['count'] == 1
    assert summary['metrics']['sent_to_click_seconds']['median'] == 30.0
