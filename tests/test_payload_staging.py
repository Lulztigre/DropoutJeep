"""Tests for campaign payload staging endpoints."""

import io
import os

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import User, Campaign, Recipient, Payload


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


def test_list_payloads_empty(client):
    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()

    resp = client.get(f'/api/campaign/{c.id}/payloads')
    assert resp.status_code == 200
    assert resp.get_json()['payloads'] == []


def test_create_payload_and_list(client):
    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()

    data = {'name': 'Test doc', 'file': (io.BytesIO(b'fake docx content'), 'invoice.docx')}
    resp = client.post(
        f'/api/campaign/{c.id}/payloads',
        data=data,
        content_type='multipart/form-data',
    )
    assert resp.status_code == 201
    payload_id = resp.get_json()['id']

    resp = client.get(f'/api/campaign/{c.id}/payloads')
    assert resp.status_code == 200
    payloads = resp.get_json()['payloads']
    assert len(payloads) == 1
    assert payloads[0]['filename'] == 'invoice.docx'
    assert payloads[0]['extension'] == 'docx'

    payload = Payload.query.get(payload_id)
    assert payload.get_content() == b'fake docx content'


def test_create_payload_accepts_disk_images(client):
    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()

    for filename in ('image.iso', 'disk.vhd', 'volume.vhdx'):
        data = {'name': filename, 'file': (io.BytesIO(b'fake disk bytes'), filename)}
        resp = client.post(
            f'/api/campaign/{c.id}/payloads',
            data=data,
            content_type='multipart/form-data',
        )
        assert resp.status_code == 201, filename
        assert resp.get_json()['extension'] == filename.split('.')[-1]


def test_create_payload_rejects_bad_extension(client):
    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()

    data = {'name': 'Bad', 'file': (io.BytesIO(b'x'), 'evil.exe')}
    resp = client.post(
        f'/api/campaign/{c.id}/payloads',
        data=data,
        content_type='multipart/form-data',
    )
    assert resp.status_code == 400


def test_payload_dropper_serves_html(client):
    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    r = Recipient(campaign_id=c.id, email='a@example.com')
    db.session.add(r)
    db.session.commit()

    payload = Payload(
        campaign_id=c.id,
        name='doc',
        filename='invoice.docx',
        extension='docx',
        mime_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        per_recipient=False,
    )
    payload.set_content(b'payload bytes')
    db.session.add(payload)
    db.session.commit()

    resp = client.get(f'/payload/{payload.id}/{r.token}')
    assert resp.status_code == 200
    assert b'<html' in resp.data.lower()
    assert resp.content_type == 'text/html; charset=utf-8'


def test_payload_raw_download(client):
    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    r = Recipient(campaign_id=c.id, email='a@example.com')
    db.session.add(r)
    db.session.commit()

    payload = Payload(
        campaign_id=c.id,
        name='doc',
        filename='invoice.docx',
        extension='docx',
        mime_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        per_recipient=False,
    )
    payload.set_content(b'raw bytes')
    db.session.add(payload)
    db.session.commit()

    resp = client.get(f'/payload/{payload.id}/{r.token}/raw')
    assert resp.status_code == 200
    assert resp.data == b'raw bytes'
