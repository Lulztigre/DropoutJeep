"""Tests for device fingerprint correlation across recipients and campaigns."""

import json
import os

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import User, Campaign, Recipient, RecipientFingerprint


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


def _device_data(canvas_hash='abc', webgl_hash='xyz'):
    return {
        'ua': 'Mozilla/5.0 Test',
        'language': 'en-US',
        'platform': 'Win32',
        'screen': {'width': 1920, 'height': 1080, 'colorDepth': 24, 'pixelRatio': 1},
        'timezone': 'America/New_York',
        'touch': False,
        'cores': 8,
        'memory': 8,
        'canvas_hash': canvas_hash,
        'webgl_hash': webgl_hash,
        'plugins': [{'name': 'PDF Viewer'}],
    }


def test_compute_device_hash_deterministic():
    from dropoutjeep_lib.utils.fingerprint_correlation import compute_device_hash
    data = _device_data()
    assert compute_device_hash(data) == compute_device_hash(data)


def test_compute_device_hash_differs_by_traits():
    from dropoutjeep_lib.utils.fingerprint_correlation import compute_device_hash
    a = compute_device_hash(_device_data(canvas_hash='abc'))
    b = compute_device_hash(_device_data(canvas_hash='def'))
    assert a != b


def test_api_fingerprint_creates_recipient_fingerprint(client):
    _create_admin(client)
    c = Campaign(name='Test', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    r = Recipient(campaign_id=c.id, email='a@example.com')
    db.session.add(r)
    db.session.commit()

    resp = client.post(f'/api/fingerprint/{r.token}', json=_device_data())
    assert resp.status_code == 200

    fp = RecipientFingerprint.query.filter_by(recipient_id=r.id).first()
    assert fp is not None
    assert fp.device_hash is not None


def test_correlations_link_two_recipients_same_device(client):
    _create_admin(client)
    c1 = Campaign(name='C1', subject='s', body_html='b', landing_html='l')
    c2 = Campaign(name='C2', subject='s', body_html='b', landing_html='l')
    db.session.add_all([c1, c2])
    db.session.commit()

    r1 = Recipient(campaign_id=c1.id, email='user@example.com')
    r2 = Recipient(campaign_id=c2.id, email='user@example.com')
    db.session.add_all([r1, r2])
    db.session.commit()

    data = _device_data()
    client.post(f'/api/fingerprint/{r1.token}', json=data)
    client.post(f'/api/fingerprint/{r2.token}', json=data)

    resp = client.get(f'/api/recipient/{r1.id}/correlations')
    assert resp.status_code == 200
    payload = resp.get_json()
    assert len(payload['correlations']) == 1
    assert payload['correlations'][0]['recipient_id'] == r2.id


def test_correlated_events_include_linked_recipients(client):
    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()

    r1 = Recipient(campaign_id=c.id, email='a@example.com')
    r2 = Recipient(campaign_id=c.id, email='b@example.com')
    db.session.add_all([r1, r2])
    db.session.commit()

    data = _device_data()
    client.post(f'/api/fingerprint/{r1.token}', json=data)
    client.post(f'/api/fingerprint/{r2.token}', json=data)

    resp = client.get(f'/api/recipient/{r1.id}/correlated-events')
    assert resp.status_code == 200
    payload = resp.get_json()
    # Two fingerprint events should be returned.
    assert len(payload['events']) == 2
