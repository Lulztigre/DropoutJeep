"""Tests for MITRE ATT&CK coverage report."""

import os

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import User, Campaign, Recipient, Event
from dropoutjeep_lib.utils.mitre import coverage_report


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def _create_admin(client):
    u = User(username='admin_test', role='admin', is_active=True)
    u.set_password('testpass')
    db.session.add(u)
    db.session.commit()
    client.post('/admin/login', data={'username': 'admin_test', 'password': 'testpass'})
    return u


def test_coverage_report_shows_missing_techniques(client):
    with client.application.app_context():
        c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
        db.session.add(c)
        db.session.commit()
        e = Event(campaign_id=c.id, event_type='click')
        db.session.add(e)
        db.session.commit()

        report = coverage_report(Event.query.filter_by(campaign_id=c.id).all())
        assert report['observed_count'] >= 1
        assert report['possible_count'] > report['observed_count']
        assert 0 < report['coverage_percent'] <= 100
        assert len(report['missing']) > 0


def test_api_campaign_mitre_returns_summary_and_coverage(client):
    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    e = Event(campaign_id=c.id, event_type='credential_attempt')
    db.session.add(e)
    db.session.commit()

    resp = client.get(f'/api/campaign/{c.id}/mitre')
    assert resp.status_code == 200
    payload = resp.get_json()
    assert 'summary' in payload
    assert 'coverage' in payload
    assert payload['summary']['total_mapped_events'] >= 1
    assert payload['coverage']['observed_count'] >= 1
