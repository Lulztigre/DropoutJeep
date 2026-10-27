"""Tests for OAuth/SAML token parser and captured OAuth token storage."""

import base64
import json
import os
from unittest import mock

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import User, Campaign, Recipient, CapturedOAuthToken, OAuthTokenCapture
from dropoutjeep_lib.utils.token_parser import parse_jwt_id_token
from dropoutjeep_lib.utils.oauth_phish import store_oauth_tokens, exchange_code_for_tokens


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _make_id_token(claims: dict) -> str:
    header = _b64url(json.dumps({'alg': 'none'}).encode())
    payload = _b64url(json.dumps(claims).encode())
    return f'{header}.{payload}.signature'


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


def test_parse_jwt_id_token_extracts_claims():
    token = _make_id_token({
        'sub': 'user-123',
        'aud': 'client-123',
        'iss': 'https://idp.example.com',
        'exp': 1234567890,
        'name': 'Alice',
    })
    claims = parse_jwt_id_token(token)
    assert claims.get('sub') == 'user-123'
    assert claims.get('aud') == 'client-123'
    assert claims.get('iss') == 'https://idp.example.com'
    assert claims.get('exp') == 1234567890


def test_parse_jwt_id_token_returns_empty_for_malformed():
    assert parse_jwt_id_token('not-a-jwt') == {}
    assert parse_jwt_id_token('') == {}
    assert parse_jwt_id_token('only.two.parts') == {}


def test_store_oauth_tokens_creates_record(client):
    _create_admin(client)
    campaign = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(campaign)
    db.session.commit()
    recipient = Recipient(campaign_id=campaign.id, email='a@example.com')
    db.session.add(recipient)
    db.session.commit()

    token_response = {
        'access_token': 'access-xyz',
        'refresh_token': 'refresh-abc',
        'id_token': _make_id_token({'sub': 'user-123'}),
        'token_type': 'Bearer',
        'expires_in': 3600,
        'scope': 'openid profile',
    }
    capture = store_oauth_tokens(campaign.id, recipient.token, 'test-provider', token_response)

    assert capture is not None
    assert capture.campaign_id == campaign.id
    assert capture.recipient_id == recipient.id
    assert capture.recipient_token == recipient.token
    assert capture.provider == 'test-provider'
    assert capture.access_token == 'access-xyz'
    assert capture.refresh_token == 'refresh-abc'
    assert capture.token_type == 'Bearer'
    assert capture.expires_in == 3600
    assert capture.scope == 'openid profile'

    stored = CapturedOAuthToken.query.first()
    assert stored is not None
    assert stored.parsed_id_token_claims()['sub'] == 'user-123'


def test_api_campaign_oauth_tokens(client):
    _create_admin(client)
    campaign = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(campaign)
    db.session.commit()
    recipient = Recipient(campaign_id=campaign.id, email='a@example.com')
    db.session.add(recipient)
    db.session.commit()

    store_oauth_tokens(
        campaign.id,
        recipient.token,
        'test-provider',
        {
            'access_token': 'access-xyz',
            'id_token': _make_id_token({'sub': 'user-123', 'iss': 'https://idp.example.com'}),
            'token_type': 'Bearer',
        },
    )

    resp = client.get(f'/api/campaign/{campaign.id}/oauth-tokens')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['campaign_id'] == campaign.id
    assert len(data['tokens']) == 1
    token = data['tokens'][0]
    assert token['provider'] == 'test-provider'
    assert token['access_token'] == 'access-xyz'
    assert token['id_token_claims']['sub'] == 'user-123'
    assert token['id_token_claims']['iss'] == 'https://idp.example.com'


def test_exchange_code_for_tokens_stores_parsed_copy(client):
    _create_admin(client)
    campaign = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(campaign)
    db.session.commit()
    recipient = Recipient(campaign_id=campaign.id, email='a@example.com')
    db.session.add(recipient)
    db.session.commit()

    auth_capture = OAuthTokenCapture(
        campaign_id=campaign.id,
        recipient_id=recipient.id,
        recipient_token=recipient.token,
        provider='test-provider',
        auth_code='auth-code-123',
    )
    db.session.add(auth_capture)
    db.session.commit()

    token_response = {
        'access_token': 'access-xyz',
        'refresh_token': 'refresh-abc',
        'id_token': _make_id_token({'sub': 'user-123'}),
        'token_type': 'Bearer',
        'expires_in': 3600,
    }

    with mock.patch('dropoutjeep_lib.utils.oauth_phish.requests.post') as mock_post:
        mock_resp = mock.Mock()
        mock_resp.raise_for_status = mock.Mock()
        mock_resp.json.return_value = token_response
        mock_post.return_value = mock_resp

        ok = exchange_code_for_tokens(
            auth_capture,
            'https://idp.example.com/token',
            'client123',
            'secret',
            'http://localhost:5000/oauth/callback',
        )

    assert ok is True
    assert auth_capture.access_token == 'access-xyz'
    assert CapturedOAuthToken.query.count() == 1
    parsed = CapturedOAuthToken.query.first().parsed_id_token_claims()
    assert parsed['sub'] == 'user-123'
