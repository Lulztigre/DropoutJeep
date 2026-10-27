"""Unit tests for MFA relay body construction and state store."""

import json
import os
from urllib.parse import parse_qs

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import Campaign
from dropoutjeep_lib.proxy.mfa_relay import (
    MfaRelayStore,
    build_relay_body,
    extract_auth_fields,
    prepare_relay_body,
)


@pytest.fixture
def store_ctx():
    app.config['TESTING'] = True
    with app.app_context():
        db.create_all()
        campaign = Campaign(name='MFA Test', subject='s', body_html='b', landing_html='l')
        db.session.add(campaign)
        db.session.commit()
        yield {'campaign_id': campaign.id, 'store': MfaRelayStore(ttl=60)}
        db.session.remove()
        db.drop_all()


def _urldecode(body: bytes) -> dict:
    return {k: v[0] if len(v) == 1 else v for k, v in parse_qs(body.decode(), keep_blank_values=True).items()}


def test_extract_auth_fields_detects_password_and_mfa():
    body = b"email=alice@example.com&password=secret123&code=654321"
    result = extract_auth_fields(body, "application/x-www-form-urlencoded", {})
    assert result["has_password"]
    assert result["has_mfa"]
    assert result["username"] == "alice@example.com"
    assert result["password_value"] == "secret123"
    assert result["mfa_value"] == "654321"


def test_extract_auth_fields_detects_json_credentials():
    body = json.dumps({"user": "bob", "pass": "hunter2", "otp": "111222"}).encode()
    result = extract_auth_fields(body, "application/json", {})
    assert result["has_password"]
    assert result["has_mfa"]
    assert result["username"] == "bob"
    assert result["mfa_value"] == "111222"


def test_store_and_retrieve_partial_auth(store_ctx):
    store = store_ctx['store']
    cid = store_ctx['campaign_id']
    fields = {"email": "alice@example.com", "password": "secret123"}
    store.store(cid, "token-a", "127.0.0.1", "/login", fields)

    partial = store.get(cid, "token-a", "127.0.0.1")
    assert partial is not None
    assert partial.username_value == "alice@example.com"
    assert partial.password_value == "secret123"
    assert partial.path == "/login"


def test_prepare_relay_body_stage1_returns_original_and_stores_state(store_ctx):
    store = store_ctx['store']
    cid = store_ctx['campaign_id']
    body = b"email=alice@example.com&password=secret123"
    config = {"mfa_relay_enabled": True}
    fwd, ct, did_relay = prepare_relay_body(cid, "tok", None, "POST", "/login", body,
                                            "application/x-www-form-urlencoded", config, store=store)
    assert not did_relay
    assert fwd == body
    assert store.get(cid, "tok", None) is not None


def test_prepare_relay_body_stage2_replays_combined_credentials_form(store_ctx):
    store = store_ctx['store']
    cid = store_ctx['campaign_id']
    stage1 = {"email": "alice@example.com", "password": "secret123"}
    store.store(cid, "tok", None, "/login", stage1)

    stage2 = b"code=654321"
    config = {"mfa_relay_enabled": True}
    fwd, ct, did_relay = prepare_relay_body(cid, "tok", None, "POST", "/verify", stage2,
                                            "application/x-www-form-urlencoded", config, store=store)
    assert did_relay
    decoded = _urldecode(fwd)
    assert decoded["email"] == "alice@example.com"
    assert decoded["password"] == "secret123"
    assert decoded["code"] == "654321"
    assert store.get(cid, "tok", None) is None  # cleared after relay


def test_prepare_relay_body_stage2_replays_combined_credentials_json(store_ctx):
    store = store_ctx['store']
    cid = store_ctx['campaign_id']
    stage1 = {"user": "bob", "pass": "hunter2"}
    store.store(cid, "tok", None, "/login", stage1)

    stage2 = json.dumps({"otp": "111222"}).encode()
    config = {"mfa_relay_enabled": True}
    fwd, ct, did_relay = prepare_relay_body(cid, "tok", None, "POST", "/verify", stage2,
                                            "application/json", config, store=store)
    assert did_relay
    decoded = json.loads(fwd)
    assert decoded["user"] == "bob"
    assert decoded["pass"] == "hunter2"
    assert decoded["otp"] == "111222"


def test_prepare_relay_body_disabled_returns_original(store_ctx):
    store = store_ctx['store']
    cid = store_ctx['campaign_id']
    body = b"code=654321"
    config = {"mfa_relay_enabled": False}
    fwd, ct, did_relay = prepare_relay_body(cid, "tok", None, "POST", "/verify", body,
                                            "application/x-www-form-urlencoded", config, store=store)
    assert not did_relay
    assert fwd == body


def test_prepare_relay_body_mfa_without_state_returns_original(store_ctx):
    store = store_ctx['store']
    cid = store_ctx['campaign_id']
    body = b"code=654321"
    config = {"mfa_relay_enabled": True}
    fwd, ct, did_relay = prepare_relay_body(cid, "tok", None, "POST", "/verify", body,
                                            "application/x-www-form-urlencoded", config, store=store)
    assert not did_relay
    assert fwd == body


def test_build_relay_body_updates_content_type_for_multipart():
    partial = type("Partial", (), {"username_field": "email", "username_value": "a@b.com",
                                   "password_field": "password", "password_value": "pw"})()
    body = b"------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"code\"\r\n\r\n123456"
    fwd, ct = build_relay_body(partial, {"code": "123456"}, "multipart/form-data", body)
    assert ct == "application/x-www-form-urlencoded"
    decoded = _urldecode(fwd)
    assert decoded["email"] == "a@b.com"
    assert decoded["password"] == "pw"
    assert decoded["code"] == "123456"


def test_store_expires_old_entries(store_ctx):
    store = MfaRelayStore(ttl=0)
    cid = store_ctx['campaign_id']
    fields = {"email": "alice@example.com", "password": "secret123"}
    store.store(cid, "tok", None, "/login", fields)
    assert store.get(cid, "tok", None) is None


def test_extract_auth_fields_uses_custom_username_fields():
    body = b"login_id=alice&password=secret123"
    result = extract_auth_fields(body, "application/x-www-form-urlencoded", {
        "username_field_names": ["login_id"],
    })
    assert result["username"] == "alice"
    assert result["username_field"] == "login_id"
    assert result["has_password"]


def test_prepare_relay_body_disabled_returns_original_body(store_ctx):
    store = store_ctx['store']
    cid = store_ctx['campaign_id']
    stage1 = {"email": "alice@example.com", "password": "secret123"}
    store.store(cid, "tok", None, "/login", stage1)

    stage2 = b"code=654321"
    config = {"mfa_relay_enabled": False}
    fwd, ct, did_relay = prepare_relay_body(cid, "tok", None, "POST", "/verify", stage2,
                                            "application/x-www-form-urlencoded", config, store=store)
    assert not did_relay
    assert fwd == stage2
    # State should remain intact when relay is disabled.
    assert store.get(cid, "tok", None) is not None


def test_build_relay_body_preserves_custom_username_field_name():
    partial = type("Partial", (), {
        "username_field": "login_id",
        "username_value": "alice",
        "password_field": "password",
        "password_value": "secret123",
    })()
    body = b"code=654321"
    fwd, ct = build_relay_body(partial, {"code": "654321"}, "application/x-www-form-urlencoded", body)
    decoded = _urldecode(fwd)
    assert decoded["login_id"] == "alice"
    assert decoded["password"] == "secret123"
    assert decoded["code"] == "654321"
