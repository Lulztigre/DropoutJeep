"""Tests for the REST API v1 endpoints."""

import hashlib
import os
import secrets

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import User, Campaign, Recipient, SendingProfile, ApiToken


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


def test_create_campaign(client):
    user = _create_user('operator')
    _login(client, user)
    resp = client.post('/api/v1/campaigns/', json={
        'name': 'API Campaign',
        'subject': 'Test subject',
        'body_html': '<p>email</p>',
        'landing_html': '<form></form>',
    })
    assert resp.status_code == 201
    data = resp.get_json()
    assert data['status'] == 'created'
    assert data['campaign']['name'] == 'API Campaign'


def test_non_admin_cannot_create_reverse_proxy(client):
    user = _create_user('operator')
    _login(client, user)
    resp = client.post('/api/v1/campaigns/', json={
        'name': 'Proxy Campaign',
        'flow_type': 'reverse_proxy',
        'flow_config': {'target_url': 'https://example.com'},
    })
    assert resp.status_code == 403


def test_admin_can_create_reverse_proxy(client):
    user = _create_user('admin')
    _login(client, user)
    resp = client.post('/api/v1/campaigns/', json={
        'name': 'Proxy Campaign',
        'flow_type': 'reverse_proxy',
        'flow_config': {'target_url': 'https://example.com'},
    })
    assert resp.status_code == 201
    assert resp.get_json()['campaign']['flow_type'] == 'reverse_proxy'


def test_update_campaign(client):
    user = _create_user('operator')
    _login(client, user)
    c = Campaign(name='Old', subject='sub', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()

    resp = client.patch(f'/api/v1/campaigns/{c.id}', json={'name': 'New'})
    assert resp.status_code == 200
    assert resp.get_json()['campaign']['name'] == 'New'


def test_delete_campaign(client):
    user = _create_user('operator')
    _login(client, user)
    c = Campaign(name='Delete', subject='sub', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()

    resp = client.delete(f'/api/v1/campaigns/{c.id}')
    assert resp.status_code == 200
    assert Campaign.query.get(c.id) is None


def test_add_and_list_recipients(client):
    user = _create_user('operator')
    _login(client, user)
    c = Campaign(name='Recipients', subject='sub', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()

    resp = client.post(f'/api/v1/campaigns/{c.id}/recipients', json={
        'email': 'alice@example.com',
        'name': 'Alice',
    })
    assert resp.status_code == 201
    rid = resp.get_json()['id']

    resp = client.get(f'/api/v1/campaigns/{c.id}/recipients')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['total'] == 1
    assert data['recipients'][0]['email'] == 'alice@example.com'
    assert data['recipients'][0]['id'] == rid


def test_bulk_import_recipients_json(client):
    user = _create_user('operator')
    _login(client, user)
    c = Campaign(name='Bulk', subject='sub', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()

    resp = client.post('/api/v1/recipients/bulk', json={
        'campaign_id': c.id,
        'recipients': [
            {'email': 'bob@example.com', 'name': 'Bob'},
            {'email': 'charlie@example.com'},
            {'email': 'invalid'},
        ],
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['created'] == 2
    assert data['duplicates'] == 0
    assert len(data['errors']) == 1


def test_send_campaign(client, monkeypatch):
    user = _create_user('operator')
    _login(client, user)
    c = Campaign(name='Send', subject='sub', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    Recipient(campaign_id=c.id, email='victim@example.com')
    db.session.commit()

    # Avoid starting a real background sender thread in tests.
    started = []
    def fake_start(self, campaign_id, rate_per_min=None):
        started.append(campaign_id)
        return True
    monkeypatch.setattr('dropoutjeep_lib.utils.dialer.Dialer.start_campaign', fake_start)

    resp = client.post(f'/api/v1/campaigns/{c.id}/send')
    assert resp.status_code == 200
    assert resp.get_json()['status'] == 'started'
    assert started == [c.id]


def test_get_results(client):
    user = _create_user('operator')
    _login(client, user)
    c = Campaign(name='Results', subject='sub', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()

    resp = client.get(f'/api/v1/campaigns/{c.id}/results')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'funnel' in data
    assert 'job' in data
    assert 'events' in data
    assert 'credentials' in data
    assert 'cookies' in data


def test_create_sending_profile(client):
    user = _create_user('operator')
    _login(client, user)
    resp = client.post('/api/v1/sending-profiles/', json={
        'name': 'SMTP 1',
        'smtp_host': 'smtp.example.com',
        'smtp_port': 587,
        'smtp_user': 'user',
        'smtp_pass': 'secret',
        'use_tls': True,
    })
    assert resp.status_code == 201
    data = resp.get_json()
    assert data['status'] == 'created'
    assert data['profile']['name'] == 'SMTP 1'


def test_get_sending_profile(client):
    user = _create_user('operator')
    _login(client, user)
    p = SendingProfile(name='SMTP 2', smtp_host='smtp.example.com', smtp_port=25)
    db.session.add(p)
    db.session.commit()

    resp = client.get(f'/api/v1/sending-profiles/{p.id}')
    assert resp.status_code == 200
    assert resp.get_json()['name'] == 'SMTP 2'


def test_api_token_auth(client):
    user = _create_user('admin')
    plain = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(plain.encode()).hexdigest()
    t = ApiToken(name='test-token', token_hash=token_hash, created_by_user_id=user.id, is_active=True)
    t.set_scopes(['campaigns:read'])
    db.session.add(t)
    db.session.commit()

    c = Campaign(name='Token', subject='sub', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()

    resp = client.get(f'/api/v1/campaigns/{c.id}', headers={'Authorization': f'Bearer {plain}'})
    assert resp.status_code == 200
    assert resp.get_json()['id'] == c.id
