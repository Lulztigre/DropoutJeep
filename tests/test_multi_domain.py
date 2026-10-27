"""Tests for multi-domain wildcard routing and provisioning."""

import json
import os

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import User, Campaign, Recipient, ProxyDomain


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


def test_proxy_domain_wildcard_fields(client):
    _create_admin(client)
    c = Campaign(name='Proxy', subject='s', body_html='b', landing_html='l', flow_type='reverse_proxy')
    db.session.add(c)
    db.session.commit()

    resp = client.post('/admin/proxy-domains/new', data={
        'domain': '*.campaigns.example.com',
        'campaign_id': c.id,
        'server_ip': '203.0.113.10',
        'dns_provider': 'manual',
        'tls_provider': 'caddy',
        'acme_email': 'admin@example.com',
        'auto_tls_enabled': 'on',
    }, follow_redirects=True)
    assert resp.status_code == 200

    pd = ProxyDomain.query.filter_by(domain='*.campaigns.example.com').first()
    assert pd is not None
    assert pd.is_wildcard is True
    assert pd.base_domain == 'campaigns.example.com'
    assert pd.server_ip == '203.0.113.10'
    assert pd.dns_provider == 'manual'
    assert pd.tls_provider == 'caddy'
    assert pd.auto_tls_enabled is True


def test_caddy_ask_authorizes_wildcard(client):
    _create_admin(client)
    c = Campaign(name='Proxy', subject='s', body_html='b', landing_html='l', flow_type='reverse_proxy')
    db.session.add(c)
    db.session.commit()
    pd = ProxyDomain(
        domain='*.campaigns.example.com',
        campaign_id=c.id,
        is_wildcard=True,
        base_domain='campaigns.example.com',
        is_active=True,
    )
    db.session.add(pd)
    db.session.commit()

    resp = client.get('/internal/caddy-ask?domain=token123.campaigns.example.com')
    assert resp.status_code == 200
    assert b'authorized' in resp.data

    resp = client.get('/internal/caddy-ask?domain=other.example.com')
    assert resp.status_code == 403


def test_caddy_ask_rejects_unknown_domain(client):
    resp = client.get('/internal/caddy-ask?domain=anything.example.com')
    assert resp.status_code == 403


def test_domain_routing_uses_wildcard_url(client):
    from dropoutjeep_lib.utils.domain_routing import get_recipient_proxy_url

    _create_admin(client)
    c = Campaign(name='Proxy', subject='s', body_html='b', landing_html='l', flow_type='reverse_proxy')
    db.session.add(c)
    db.session.commit()
    pd = ProxyDomain(
        domain='*.campaigns.example.com',
        campaign_id=c.id,
        is_wildcard=True,
        base_domain='campaigns.example.com',
        is_active=True,
    )
    db.session.add(pd)
    db.session.commit()

    url = get_recipient_proxy_url(c.id, 'tok123', 'http://127.0.0.1:5000')
    assert url == 'https://tok123.campaigns.example.com/'


def test_domain_routing_falls_back_to_proxy_path(client):
    from dropoutjeep_lib.utils.domain_routing import get_recipient_proxy_url

    _create_admin(client)
    c = Campaign(name='Proxy', subject='s', body_html='b', landing_html='l', flow_type='reverse_proxy')
    db.session.add(c)
    db.session.commit()

    url = get_recipient_proxy_url(c.id, 'tok123', 'http://127.0.0.1:5000')
    assert url == 'http://127.0.0.1:5000/proxy/1/t/tok123/'


def test_dns_manager_logs_manual_record(client, caplog):
    import logging
    from dropoutjeep_lib.dns import DNSManager

    _create_admin(client)
    c = Campaign(name='Proxy', subject='s', body_html='b', landing_html='l', flow_type='reverse_proxy')
    db.session.add(c)
    db.session.commit()
    pd = ProxyDomain(
        domain='*.campaigns.example.com',
        campaign_id=c.id,
        is_wildcard=True,
        base_domain='campaigns.example.com',
        server_ip='203.0.113.10',
        dns_provider='manual',
        is_active=True,
    )
    db.session.add(pd)
    db.session.commit()

    with caplog.at_level(logging.WARNING):
        ok = DNSManager(pd).provision()
    assert ok is True
    assert 'MANUAL DNS: create *.campaigns.example.com A -> 203.0.113.10' in caplog.text


def test_wildcard_lookup_in_standalone_server(client):
    pytest.importorskip("starlette")
    from dropoutjeep_lib.proxy.server import _lookup_campaign_by_domain

    _create_admin(client)
    c = Campaign(name='Proxy', subject='s', body_html='b', landing_html='l', flow_type='reverse_proxy')
    db.session.add(c)
    db.session.commit()
    pd = ProxyDomain(
        domain='*.campaigns.example.com',
        campaign_id=c.id,
        is_wildcard=True,
        base_domain='campaigns.example.com',
        is_active=True,
    )
    db.session.add(pd)
    db.session.commit()

    campaign, proxy_domain = _lookup_campaign_by_domain('abc123.campaigns.example.com')
    assert campaign is not None
    assert campaign.id == c.id
    assert proxy_domain is not None
    assert proxy_domain.is_wildcard is True
