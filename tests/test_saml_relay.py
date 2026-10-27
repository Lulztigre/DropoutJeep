"""Tests for SAML/SSO relay capture."""

import base64
import json
import os

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import User, Campaign, Recipient, SamlCapture


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


def test_saml_acs_captures_response(client):
    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    r = Recipient(campaign_id=c.id, email='a@example.com')
    db.session.add(r)
    db.session.commit()

    encoded = base64.b64encode(b'<samlp:Response></samlp:Response>').decode()
    resp = client.post(f'/saml/acs/{r.token}', data={
        'SAMLResponse': encoded,
        'RelayState': 'https://app.example.com',
    })
    assert resp.status_code == 200

    captures = SamlCapture.query.all()
    assert len(captures) == 1
    assert captures[0].saml_response == encoded
    assert captures[0].recipient_id == r.id
