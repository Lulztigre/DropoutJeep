"""Tests for OAuth2 phishing flow."""

import base64
import json
import os

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import User, Campaign, Recipient, OAuthTokenCapture


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


def _set_oauth_config(campaign):
    config = campaign.get_flow_config() or {}
    config['oauth'] = {
        'provider': 'test-provider',
        'authorization_endpoint': 'https://idp.example.com/authorize',
        'token_endpoint': 'https://idp.example.com/token',
        'client_id': 'client123',
        'client_secret': 'secret',
        'redirect_uri': 'http://localhost:5000/oauth/callback',
        'scope': 'openid profile',
    }
    campaign.set_flow_config(config)
    db.session.commit()


def test_oauth_start_redirects_to_provider(client):
    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    r = Recipient(campaign_id=c.id, email='a@example.com')
    db.session.add(r)
    db.session.commit()
    _set_oauth_config(c)

    resp = client.get(f'/oauth/start/{r.token}', follow_redirects=False)
    assert resp.status_code == 302
    loc = resp.headers['Location']
    assert 'idp.example.com/authorize' in loc
    assert 'client_id=client123' in loc
    assert 'state=' in loc


def test_oauth_callback_captures_auth_code(client):
    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    r = Recipient(campaign_id=c.id, email='a@example.com')
    db.session.add(r)
    db.session.commit()
    _set_oauth_config(c)

    state = base64.urlsafe_b64encode(f"{c.id}:{r.token}".encode()).decode().rstrip('=')
    resp = client.get(f'/oauth/callback?code=abc123&state={state}')
    assert resp.status_code == 200

    captures = OAuthTokenCapture.query.all()
    assert len(captures) == 1
    assert captures[0].auth_code == 'abc123'
    assert captures[0].recipient_id == r.id
