"""Tests for clean URL path obfuscation."""

import os

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import User, Campaign, Recipient, Event
from dropoutjeep_lib.utils.clean_urls import build_clean_url
from dropoutjeep_lib.utils.renderer import render_email


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


def test_build_clean_url_strips_trailing_slash():
    assert build_clean_url('https://example.com', 'tok123') == 'https://example.com/l/tok123'
    assert build_clean_url('https://example.com/', 'tok123') == 'https://example.com/l/tok123'
    assert build_clean_url('https://example.com/path/', 'tok123') == 'https://example.com/path/l/tok123'


def test_build_clean_url_with_empty_base():
    assert build_clean_url('', 'tok123') == '/l/tok123'


def test_clean_url_redirects_to_landing(client):
    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    r = Recipient(campaign_id=c.id, email='a@example.com')
    db.session.add(r)
    db.session.commit()

    resp = client.get(f'/l/{r.token}', follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers['Location'].endswith(f'/landing/{r.token}')

    clicks = Event.query.filter_by(event_type='click').all()
    assert len(clicks) == 1
    assert clicks[0].recipient_id == r.id
    assert clicks[0].campaign_id == c.id


def test_clean_url_redirects_to_proxy_for_reverse_proxy_campaign(client):
    _create_admin(client)
    c = Campaign(
        name='C',
        subject='s',
        body_html='b',
        landing_html='l',
        flow_type='reverse_proxy',
        flow_config='{"target_url": "https://target.example.com"}'
    )
    db.session.add(c)
    db.session.commit()
    r = Recipient(campaign_id=c.id, email='a@example.com')
    db.session.add(r)
    db.session.commit()

    resp = client.get(f'/l/{r.token}', follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers['Location'].endswith(f'/proxy/{c.id}/t/{r.token}/')


def test_clean_url_invalid_token_returns_404(client):
    resp = client.get('/l/not-a-real-token')
    assert resp.status_code == 404


def test_landing_body_substitutes_clean_url(client):
    _create_admin(client)
    c = Campaign(
        name='C',
        subject='s',
        body_html='b',
        landing_html='<a href="{{CLEAN_URL}}">click</a>'
    )
    db.session.add(c)
    db.session.commit()
    r = Recipient(campaign_id=c.id, email='a@example.com')
    db.session.add(r)
    db.session.commit()

    resp = client.get(f'/landing/{r.token}')
    assert resp.status_code == 200
    expected = f'http://localhost/l/{r.token}'
    assert expected in resp.get_data(as_text=True)


def test_email_rendering_substitutes_clean_url():
    html = '<a href="{{CLEAN_URL}}">click</a>'
    context = {'CLEAN_URL': build_clean_url('https://dj.example.com', 'tok123')}
    rendered = render_email(html, context)
    assert 'https://dj.example.com/l/tok123' in rendered
