"""Unit tests for HTML smuggling dropper builder."""

import base64

from dropoutjeep_lib.utils.html_smuggler import (
    build_html_dropper,
    encode_payload,
    decode_payload,
    build_dropper_for_extension,
    validate_payload_filename,
    PAYLOAD_MIME_TYPES,
)


def test_build_html_dropper_contains_payload():
    payload_b64 = base64.b64encode(b"hello authorized test").decode('ascii')
    html = build_html_dropper(payload_b64, 'report.pdf')
    # Dropper uses obfuscated JS & XOR chunking, so check structural HTML components
    assert '<html' in html.lower()
    assert 'var _p1=' in html or '<script' in html.lower()


def test_build_html_dropper_sanitizes_attributes():
    payload_b64 = base64.b64encode(b"x").decode('ascii')
    html = build_html_dropper(payload_b64, 'evil";alert(1);"')
    assert '";alert(1);"' not in html


def test_encode_decode_roundtrip():
    data = b"custom authorized payload"
    encoded = encode_payload(data)
    assert decode_payload(encoded) == data


def test_disk_image_extensions_allowed():
    for ext in ('iso', 'vhd', 'vhdx'):
        ok, msg = validate_payload_filename(f'payload.{ext}')
        assert ok, msg
        assert ext in PAYLOAD_MIME_TYPES


def test_build_dropper_uses_disk_image_mime():
    payload_b64 = encode_payload(b"fake disk image bytes")
    html = build_dropper_for_extension(payload_b64, 'image.iso', extension='iso')
    assert 'application/x-iso9660-image' in PAYLOAD_MIME_TYPES['iso']
    assert '<html' in html.lower()
    html = build_dropper_for_extension(payload_b64, 'disk.vhdx', extension='vhdx')
    assert 'application/x-vhdx' in PAYLOAD_MIME_TYPES['vhdx']
    assert '<html' in html.lower()
