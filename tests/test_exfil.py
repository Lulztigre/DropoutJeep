"""Tests for exfiltration channels."""

import base64
import json
import os

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


def test_http_exfil_creates_event(client):
    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    r = Recipient(campaign_id=c.id, email='a@example.com')
    db.session.add(r)
    db.session.commit()

    resp = client.post(f'/api/exfil/{r.token}', json={'key': 'value'})
    assert resp.status_code == 200

    events = Event.query.filter_by(event_type='exfil_http').all()
    assert len(events) == 1
    meta = json.loads(events[0].meta)
    assert meta['data']['key'] == 'value'


def test_dns_exfil_creates_event(client):
    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    r = Recipient(campaign_id=c.id, email='a@example.com')
    db.session.add(r)
    db.session.commit()

    encoded = base64.b64encode(json.dumps({'foo': 'bar'}).encode()).decode()
    resp = client.get(f'/dns-exfil?token={r.token}&data={encoded}')
    assert resp.status_code == 200
    assert resp.content_type == 'image/gif'

    events = Event.query.filter_by(event_type='exfil_dns').all()
    assert len(events) == 1
