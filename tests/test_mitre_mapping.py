"""Tests for MITRE ATT&CK event mapping."""

import os

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import Campaign, Event
from dropoutjeep_lib.utils.mitre import map_event_type, summarize_campaign, technique_details


@pytest.fixture
def ctx():
    app.config['TESTING'] = True
    with app.app_context():
        db.create_all()
        campaign = Campaign(name='MITRE Test', subject='s', body_html='b', landing_html='l')
        db.session.add(campaign)
        db.session.commit()
        yield {'campaign': campaign}
        db.session.remove()
        db.drop_all()


def test_map_event_type_click(ctx):
    techniques = map_event_type('click')
    assert 'T1566.002' in techniques
    assert 'T1204.001' in techniques


def test_map_event_type_credential_attempt(ctx):
    techniques = map_event_type('credential_attempt')
    assert 'T1566.002' in techniques
    assert 'T1003' in techniques


def test_map_event_type_mfa(ctx):
    assert 'T1556.006' in map_event_type('mfa_attempt')


def test_technique_details(ctx):
    info = technique_details('T1539')
    assert info['name'] == 'Steal Web Session Cookie'
    assert info['tactic'] == 'Credential Access'


def test_event_auto_populates_mitre(ctx):
    campaign = ctx['campaign']
    event = Event(campaign_id=campaign.id, event_type='click')
    db.session.add(event)
    db.session.commit()
    assert event.mitre_techniques_list() == map_event_type('click')


def test_summarize_campaign(ctx):
    campaign = ctx['campaign']
    for et in ['sent', 'click', 'credential_attempt', 'mfa_attempt']:
        db.session.add(Event(campaign_id=campaign.id, event_type=et))
    db.session.commit()
    summary = summarize_campaign(Event.query.filter_by(campaign_id=campaign.id).all())
    assert summary['total_mapped_events'] > 0
    ids = {t['id'] for t in summary['techniques']}
    assert 'T1566.002' in ids
    assert 'T1003' in ids
    assert 'T1556.006' in ids
