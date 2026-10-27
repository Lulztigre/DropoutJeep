"""Tests for the campaign-level credential plaintext/encrypted storage toggle."""

import json
import os

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import Campaign, Recipient, Event, User


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def _campaign_and_recipient(plaintext=False):
    c = Campaign(
        name='ToggleTest',
        subject='s',
        body_html='b',
        landing_html='<form><input name="password"></form>',
        store_credentials_plaintext=plaintext,
    )
    db.session.add(c)
    db.session.commit()
    r = Recipient(campaign_id=c.id, email='victim@example.com')
    db.session.add(r)
    db.session.commit()
    return c, r


def test_default_credential_storage_is_encrypted(client):
    c, r = _campaign_and_recipient(plaintext=False)
    resp = client.post(
        f'/landing/{r.token}',
        data={'password': 'hunter2', 'token': r.token},
        follow_redirects=True,
    )
    assert resp.status_code == 200

    event = Event.query.filter_by(event_type='credential_attempt').first()
    assert event is not None
    meta = json.loads(event.meta)
    assert not meta['password'].startswith('hunter2')
    assert meta['password'].startswith('enc::')


def test_plaintext_toggle_stores_credentials_in_plaintext(client):
    c, r = _campaign_and_recipient(plaintext=True)
    resp = client.post(
        f'/landing/{r.token}',
        data={'password': 'hunter2', 'token': r.token},
        follow_redirects=True,
    )
    assert resp.status_code == 200

    event = Event.query.filter_by(event_type='credential_attempt').first()
    assert event is not None
    meta = json.loads(event.meta)
    assert meta['password'] == 'hunter2'


def test_events_page_decrypts_encrypted_credentials(client):
    _campaign_and_recipient(plaintext=False)
    c = Campaign.query.first()
    r = Recipient.query.first()
    u = User(username='admin_test', role='admin', is_active=True)
    u.set_password('testpass')
    db.session.add(u)
    db.session.commit()
    client.post('/admin/login', data={'username': 'admin_test', 'password': 'testpass'})

    client.post(f'/landing/{r.token}', data={'password': 'hunter2', 'token': r.token})

    resp = client.get('/admin/events')
    assert resp.status_code == 200
    assert b'hunter2' in resp.data


def test_logs_json_decrypts_credential_attempt_meta(client):
    _campaign_and_recipient(plaintext=False)
    c = Campaign.query.first()
    r = Recipient.query.first()
    u = User(username='admin_test', role='admin', is_active=True)
    u.set_password('testpass')
    db.session.add(u)
    db.session.commit()
    client.post('/admin/login', data={'username': 'admin_test', 'password': 'testpass'})

    client.post(f'/landing/{r.token}', data={'password': 'hunter2', 'token': r.token})

    resp = client.get('/admin/logs/errors')
    assert resp.status_code == 200
    data = resp.get_json()
    assert any('hunter2' in (item.get('meta') or '') for item in data)
