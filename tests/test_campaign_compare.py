"""Tests for campaign comparison reporting."""

import os

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

import pytest

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


def _login_admin(client):
    u = User(username='admin_test', role='admin', is_active=True)
    u.set_password('testpass')
    db.session.add(u)
    db.session.commit()
    client.post('/admin/login', data={'username': 'admin_test', 'password': 'testpass'})


def _campaign_with_events(name: str, total: int, opened: int, clicked: int, creds: int):
    c = Campaign(name=name, subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    recipients = []
    with db.session.no_autoflush:
        for i in range(total):
            r = Recipient(campaign_id=c.id, email=f'{name}_{i}@example.com')
            db.session.add(r)
            recipients.append(r)
    db.session.commit()
    with db.session.no_autoflush:
        for i, r in enumerate(recipients):
            rid = r.id
            if i < opened:
                db.session.add(Event(campaign_id=c.id, recipient_id=rid, event_type='open'))
            if i < clicked:
                db.session.add(Event(campaign_id=c.id, recipient_id=rid, event_type='click'))
            if i < creds:
                db.session.add(Event(campaign_id=c.id, recipient_id=rid, event_type='credential_attempt'))
    db.session.commit()
    return c


def test_compare_requires_two_campaigns(client):
    _login_admin(client)
    c = _campaign_with_events('A', 10, 5, 2, 1)
    resp = client.get(f'/admin/campaigns/compare?campaign_ids={c.id}')
    assert resp.status_code == 302


def test_compare_shows_side_by_side_metrics(client):
    _login_admin(client)
    c1 = _campaign_with_events('A', 3, 2, 1, 1)
    c2 = _campaign_with_events('B', 5, 3, 2, 1)

    resp = client.get(f'/admin/campaigns/compare?campaign_ids={c1.id},{c2.id}')
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'CAMPAIGN COMPARE' in body
    assert 'A' in body
    assert 'B' in body
    assert 'Recipients' in body
    assert 'Click Rate' in body


def test_api_compare_returns_json(client):
    _login_admin(client)
    c1 = _campaign_with_events('A', 3, 2, 1, 1)
    c2 = _campaign_with_events('B', 5, 3, 2, 1)

    resp = client.get(f'/api/campaigns/compare?campaign_ids={c1.id},{c2.id}')
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data) == 2
    assert data[0]['name'] == 'A'
    assert data[0]['total_recipients'] == 3
    assert data[1]['name'] == 'B'
    assert data[1]['total_recipients'] == 5
    assert isinstance(data[0]['click_rate'], (int, float))
    assert isinstance(data[0]['conversion_rate'], (int, float))


def test_api_compare_rejects_single_id(client):
    _login_admin(client)
    c = _campaign_with_events('A', 10, 5, 2, 1)
    resp = client.get(f'/api/campaigns/compare?campaign_ids={c.id}')
    assert resp.status_code == 400
