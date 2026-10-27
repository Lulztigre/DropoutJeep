"""Tests for extended sandbox evasion checks."""

import os

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import User, Campaign, Recipient
from dropoutjeep_lib.utils.sandbox_evasion import (
    is_sandbox_ua,
    _is_suspicious_fingerprint,
    should_serve_real_page,
)


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


def test_is_sandbox_ua_detects_crawlers():
    assert is_sandbox_ua('Mozilla/5.0 Googlebot')
    assert not is_sandbox_ua('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')


def test_suspicious_fingerprint_no_mouse():
    data = {
        'webgl_hash': 123,
        'plugins': [{'name': 'PDF'}],
        'screen': {'width': 1920, 'height': 1080},
        'mouse_events': 0,
    }
    assert _is_suspicious_fingerprint(data) == 'no_mouse_interaction'


def test_suspicious_fingerprint_missing_webgl():
    data = {
        'plugins': [{'name': 'PDF'}],
        'screen': {'width': 1920, 'height': 1080},
        'mouse_events': 5,
    }
    assert _is_suspicious_fingerprint(data) == 'missing_webgl'


def test_suspicious_fingerprint_looks_real():
    data = {
        'webgl_hash': 123,
        'plugins': [{'name': 'PDF'}],
        'screen': {'width': 1920, 'height': 1080},
        'mouse_events': 5,
        'battery_level': 0.8,
    }
    assert _is_suspicious_fingerprint(data) is None


def test_api_sandbox_check_returns_verdict(client):
    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    r = Recipient(campaign_id=c.id, email='a@example.com')
    db.session.add(r)
    db.session.commit()

    resp = client.post(f'/api/sandbox-check/{r.token}', json={
        'webgl_hash': 123,
        'plugins': [{'name': 'PDF'}],
        'screen': {'width': 1920, 'height': 1080},
        'mouse_events': 5,
    })
    assert resp.status_code == 200
    assert resp.get_json()['serve_real'] is True

    resp = client.post(f'/api/sandbox-check/{r.token}', json={
        'webgl_hash': None,
        'plugins': [],
        'screen': {'width': 1920, 'height': 1080},
        'mouse_events': 0,
    })
    assert resp.status_code == 200
    assert resp.get_json()['serve_real'] is False
