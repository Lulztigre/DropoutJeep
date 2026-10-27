"""Tests for cookie replay validation."""

import os

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import User, Campaign, CapturedCookie
from dropoutjeep_lib.utils.cookie_validation import validate_captured_cookie


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


def _make_proxy_campaign():
    c = Campaign(
        name='Proxy Campaign',
        subject='s',
        body_html='b',
        landing_html='l',
        flow_type='reverse_proxy',
        flow_config='{"target_url": "https://target.example.com/dashboard"}',
    )
    db.session.add(c)
    db.session.commit()
    return c


def test_validate_cookie_success(client, monkeypatch):
    _create_admin(client)
    c = _make_proxy_campaign()
    cookie = CapturedCookie(
        campaign_id=c.id,
        cookie_name='session',
        cookie_value='abc123',
        cookie_domain='target.example.com',
        source='response',
    )
    db.session.add(cookie)
    db.session.commit()

    class FakeResponse:
        status_code = 200
        headers = {}

    def fake_get(url, headers, timeout, allow_redirects):
        assert 'session=abc123' in headers['Cookie']
        assert url == 'https://target.example.com/dashboard'
        return FakeResponse()

    monkeypatch.setattr('dropoutjeep_lib.utils.cookie_validation.requests.get', fake_get)

    result = validate_captured_cookie(cookie.id)
    assert result['valid'] is True
    assert result['error'] is None
    assert result['status_code'] == 200

    refreshed = CapturedCookie.query.get(cookie.id)
    assert refreshed.is_valid is True
    assert refreshed.validation_error is None
    assert refreshed.validated_at is not None


def test_validate_cookie_login_redirect(client, monkeypatch):
    _create_admin(client)
    c = _make_proxy_campaign()
    cookie = CapturedCookie(
        campaign_id=c.id,
        cookie_name='session',
        cookie_value='expired',
        source='response',
    )
    db.session.add(cookie)
    db.session.commit()

    class FakeResponse:
        status_code = 302
        headers = {'Location': 'https://target.example.com/login?return=/dashboard'}

    monkeypatch.setattr('dropoutjeep_lib.utils.cookie_validation.requests.get', lambda *a, **k: FakeResponse())

    result = validate_captured_cookie(cookie.id)
    assert result['valid'] is False
    assert 'login path' in result['error']
    assert result['status_code'] == 302

    refreshed = CapturedCookie.query.get(cookie.id)
    assert refreshed.is_valid is False


def test_validate_cookie_no_target_url(client):
    _create_admin(client)
    c = Campaign(name='No Proxy', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    cookie = CapturedCookie(campaign_id=c.id, cookie_name='session', cookie_value='x')
    db.session.add(cookie)
    db.session.commit()

    result = validate_captured_cookie(cookie.id)
    assert result['valid'] is False
    assert 'no proxy target url' in result['error'].lower()


def test_validate_cookie_missing():
    with app.app_context():
        db.create_all()
        try:
            result = validate_captured_cookie(9999)
            assert result['valid'] is False
            assert 'not found' in result['error']
        finally:
            db.session.remove()
            db.drop_all()


def test_api_validate_cookie_success(client, monkeypatch):
    _create_admin(client)
    c = _make_proxy_campaign()
    cookie = CapturedCookie(campaign_id=c.id, cookie_name='session', cookie_value='abc123')
    db.session.add(cookie)
    db.session.commit()

    class FakeResponse:
        status_code = 200
        headers = {}

    monkeypatch.setattr('dropoutjeep_lib.utils.cookie_validation.requests.get', lambda *a, **k: FakeResponse())

    resp = client.post(f'/api/campaign/{c.id}/cookie/{cookie.id}/validate')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['valid'] is True
    assert data['validated_at'] is not None


def test_api_validate_cookie_invalid(client, monkeypatch):
    _create_admin(client)
    c = _make_proxy_campaign()
    cookie = CapturedCookie(campaign_id=c.id, cookie_name='session', cookie_value='expired')
    db.session.add(cookie)
    db.session.commit()

    class FakeResponse:
        status_code = 401
        headers = {}

    monkeypatch.setattr('dropoutjeep_lib.utils.cookie_validation.requests.get', lambda *a, **k: FakeResponse())

    resp = client.post(f'/api/campaign/{c.id}/cookie/{cookie.id}/validate')
    assert resp.status_code == 400
    data = resp.get_json()
    assert data['valid'] is False
    assert '401' in data['error']


def test_api_validate_cookie_wrong_campaign(client):
    _create_admin(client)
    c1 = _make_proxy_campaign()
    c2 = Campaign(name='Other', subject='s', body_html='b', landing_html='l')
    db.session.add(c2)
    db.session.commit()
    cookie = CapturedCookie(campaign_id=c1.id, cookie_name='session', cookie_value='x')
    db.session.add(cookie)
    db.session.commit()

    resp = client.post(f'/api/campaign/{c2.id}/cookie/{cookie.id}/validate')
    assert resp.status_code == 404


def test_api_validate_cookie_requires_auth(client):
    c = _make_proxy_campaign()
    cookie = CapturedCookie(campaign_id=c.id, cookie_name='session', cookie_value='x')
    db.session.add(cookie)
    db.session.commit()

    resp = client.post(f'/api/campaign/{c.id}/cookie/{cookie.id}/validate')
    assert resp.status_code == 401
    assert resp.get_json()['error'] == 'unauthorized'
