"""Webhook dispatcher for DropoutJeep events.

When an Event row is inserted, active webhooks matching the event type receive
an HMAC-signed JSON POST to their configured URL. Dispatch runs in a background
thread so the request path is not blocked.
"""

import hashlib
import hmac
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import requests

logger = logging.getLogger(__name__)

# Reusable background thread pool for webhook dispatches.
_dispatch_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="webhook-")


def _serialize_event(event) -> dict:
    """Build a JSON-safe payload from an Event instance or event dict."""
    if isinstance(event, dict):
        meta = event.get("meta")
        created_at = event.get("created_at")
        event_type = event.get("event_type")
        campaign_id = event.get("campaign_id")
        recipient_id = event.get("recipient_id")
        target_id = event.get("target_id")
    else:
        meta = event.meta
        created_at = event.created_at
        event_type = event.event_type
        campaign_id = event.campaign_id
        recipient_id = event.recipient_id
        target_id = event.target_id

    try:
        data = json.loads(meta) if meta else {}
    except Exception:
        data = {"raw": meta}

    return {
        "event": event_type,
        "campaign_id": campaign_id,
        "recipient_id": recipient_id,
        "target_id": target_id,
        "data": data,
        "timestamp": created_at.isoformat() if created_at else datetime.utcnow().isoformat(),
    }


def _sign_payload(body: bytes, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _post_webhook(webhook, payload: dict) -> None:
    """POST the payload to a single webhook and update its status."""
    body = json.dumps(payload, default=str).encode("utf-8")
    signature = _sign_payload(body, webhook.secret)
    headers = {
        "Content-Type": "application/json",
        "X-DropoutJeep-Signature": f"sha256={signature}",
    }

    try:
        resp = requests.post(
            webhook.url,
            data=body,
            headers=headers,
            timeout=10,
        )
        webhook.last_status = str(resp.status_code)
        webhook.last_sent_at = datetime.utcnow()
    except Exception as exc:
        webhook.last_status = f"error: {exc}"
        webhook.last_sent_at = datetime.utcnow()
        logger.exception("Webhook dispatch failed for webhook %s", webhook.id)


def _dispatch_single(payload: dict, app):
    """Load matching webhooks and POST the payload to each one.

    Runs inside a worker thread so the after_insert listener never performs
    ORM queries on the request-scoped session.
    """
    from dropoutjeep_lib.models import Webhook
    from dropoutjeep_lib import db

    event_type = payload["event"]
    campaign_id = payload["campaign_id"]

    with app.app_context():
        query = Webhook.query.filter_by(is_active=True)
        if campaign_id:
            # Global webhooks (campaign_id IS NULL) plus campaign-specific ones.
            query = query.filter(
                (Webhook.campaign_id == campaign_id) | (Webhook.campaign_id.is_(None))
            )
        else:
            query = query.filter(Webhook.campaign_id.is_(None))

        webhooks = [w for w in query.all() if w.matches(event_type)]
        for webhook in webhooks:
            _post_webhook(webhook, payload)

        try:
            db.session.commit()
        except Exception:
            pass


def dispatch_event(event, app):
    """Queue webhook dispatches for a newly created event.

    Called from the SQLAlchemy after_insert listener with a detached event
    instance. We capture the payload synchronously and hand it off to a worker
    so the listener does not touch the request session.
    """
    payload = _serialize_event(event)
    _dispatch_pool.submit(_dispatch_single, payload, app)
