"""Tests for polymorphic payload generation."""

import io
import os
import zipfile

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import User, Campaign, Recipient, Payload
from dropoutjeep_lib.utils.polymorphic_payloads import polymorph_payload


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


def test_hta_polymorphism_inserts_unique_comment():
    base = b'<hta:application />\n<script></script>'
    a = polymorph_payload(base, 'hta', 'token-a')
    b = polymorph_payload(base, 'hta', 'token-b')
    assert a != b
    assert b'<!-- dj-' in a


def test_binary_polymorphism_appends_trailer():
    base = b'\x4d\x5a'  # MZ header
    a = polymorph_payload(base, 'bin', 'token-a')
    b = polymorph_payload(base, 'bin', 'token-b')
    assert a != b
    assert b'DJ_MARKER' in a


def test_ooxml_polymorphism_changes_zip_contents():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types />')
        zf.writestr('word/document.xml', '<?xml version="1.0"?><w:document />')
    base = buf.getvalue()

    a = polymorph_payload(base, 'docx', 'token-a')
    b = polymorph_payload(base, 'docx', 'token-b')
    assert a != b
    with zipfile.ZipFile(io.BytesIO(a), 'r') as zf:
        doc = zf.read('word/document.xml').decode('utf-8')
    assert 'dj-' in doc


def test_disk_image_polymorphism_appends_trailer():
    for ext in ('iso', 'vhd', 'vhdx'):
        base = b'\x00\x01\x02\x03'
        a = polymorph_payload(base, ext, 'token-a')
        b = polymorph_payload(base, ext, 'token-b')
        assert a != b
        assert b'DJ_MARKER' in a


def test_per_recipient_payload_serves_unique_bytes(client):
    _create_admin(client)
    c = Campaign(name='C', subject='s', body_html='b', landing_html='l')
    db.session.add(c)
    db.session.commit()
    r1 = Recipient(campaign_id=c.id, email='a@example.com')
    r2 = Recipient(campaign_id=c.id, email='b@example.com')
    db.session.add_all([r1, r2])
    db.session.commit()

    payload = Payload(
        campaign_id=c.id,
        name='doc',
        filename='invoice.docx',
        extension='docx',
        mime_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        per_recipient=True,
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types />')
        zf.writestr('word/document.xml', '<?xml version="1.0"?><w:document />')
    payload.set_content(buf.getvalue())
    db.session.add(payload)
    db.session.commit()

    resp1 = client.get(f'/payload/{payload.id}/{r1.token}/raw')
    resp2 = client.get(f'/payload/{payload.id}/{r2.token}/raw')
    assert resp1.status_code == 200
    assert resp2.status_code == 200
    assert resp1.data != resp2.data
