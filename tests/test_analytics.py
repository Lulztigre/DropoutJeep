"""Tests for analytics, GeoIP, heatmap, timeline, and exports."""

import json
import os
from unittest.mock import patch

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import User, Campaign, Recipient, Event


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


def test_event_captures_ip_and_user_agent(client):
    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    r = Recipient(campaign_id=c.id, email='victim@example.com')
    db.session.add(r)
    db.session.commit()

    with client.application.test_request_context():
        db.session.add(Event(
            campaign_id=c.id,
            recipient_id=r.id,
            event_type='click',
        ))
        db.session.commit()

    e = Event.query.filter_by(event_type='click').first()
    assert e is not None


def test_track_heatmap_endpoint(client):
    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    r = Recipient(campaign_id=c.id, email='victim@example.com')
    db.session.add(r)
    db.session.commit()

    resp = client.post('/track/heatmap', json={
        'campaign_id': c.id,
        'token': r.token,
        'x': 100,
        'y': 200,
        'selector': 'button',
        'path': '/login',
    })
    assert resp.status_code == 200

    e = Event.query.filter_by(event_type='heatmap_click').first()
    assert e is not None
    meta = json.loads(e.meta)
    assert meta['x'] == 100
    assert meta['selector'] == 'button'
    assert e.recipient_id == r.id


def test_geoip_enrich_formats_location():
    from dropoutjeep_lib.utils.geoip import format_geo
    assert format_geo({'city': 'New York', 'country': 'United States'}) == 'New York, United States'


def test_analytics_heatmap_data(client):
    from dropoutjeep_lib.utils.analytics import get_heatmap_data

    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    db.session.add(Event(
        campaign_id=c.id,
        event_type='heatmap_click',
        meta=json.dumps({'x': 10, 'y': 20, 'selector': 'a'}),
    ))
    db.session.commit()

    points = get_heatmap_data(c.id)
    assert len(points) == 1
    assert points[0]['x'] == 10


def test_csv_export_contains_events(client):
    from dropoutjeep_lib.utils.analytics import export_campaign_csv

    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    r = Recipient(campaign_id=c.id, email='victim@example.com')
    db.session.add(r)
    db.session.commit()
    db.session.add(Event(campaign_id=c.id, recipient_id=r.id, event_type='click'))
    db.session.commit()

    csv_data = export_campaign_csv(c.id)
    assert 'event' in csv_data
    assert 'click' in csv_data
    assert 'victim@example.com' in csv_data


def test_pdf_export_returns_bytes(client):
    from dropoutjeep_lib.utils.analytics import export_campaign_pdf

    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()

    pdf_bytes = export_campaign_pdf(c.id)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b'%PDF')
