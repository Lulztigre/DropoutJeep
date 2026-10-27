"""Breach-data lookup and password-compromise pretext generation.

Queries third-party breach databases (DeHashed or IntelX) for credentials
associated with a target email and generates a "password compromise" pretext
that references the actual leaked password — a high-yield phishing-simulation
lure, since seeing one's real password in an email is a strong urgency signal.

Intended for **authorized** red-team / phishing-simulation use only against
targets the operator has written permission to test. The operator must supply
their own API key for the chosen provider; nothing is sent without one.

Both providers are queried over plain HTTPS with ``requests`` and failures are
handled gracefully — any API error returns an empty result set rather than
raising, so callers can treat the module as best-effort enrichment.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("dropoutjeep")

# --- Configuration -----------------------------------------------------------

DEHASHED_API_URL = "https://api.dehashed.com/search"

# IntelX paid (primary) and free (fallback) endpoints.
# Paid keys work against 2.intelx.io; free keys are rejected there and
# must use free.intelx.io instead.  We try the paid endpoint first and
# fall back automatically when the key is not recognised.
INTELX_PAID_BASE = "https://2.intelx.io"
INTELX_FREE_BASE = "https://free.intelx.io"
INTELX_USER_AGENT = "IX-Python/0.8"

# Paid keys use the phonebook endpoints; free keys only have access to
# the intelligent-search endpoints (see /authenticate/info capabilities).
INTELX_PATHS = {
    "paid": {
        "search": "/phonebook/search",
        "result": "/phonebook/search/result",
    },
    "free": {
        "search": "/intelligent/search",
        "result": "/intelligent/search/result",
    },
}

DEFAULT_TIMEOUT = 15
INTELX_POLL_SECONDS = 3
INTELX_MAX_POLLS = 10


def _api_key(name: str) -> Optional[str]:
    """Resolve a setting from the DB-backed settings helper, then env."""
    try:
        from dropoutjeep_lib.utils.settings import get_setting  # type: ignore
        value = get_setting(name)
        if value:
            return value
    except Exception:
        # No Flask app context — fall through to env.
        pass
    return os.environ.get(name.upper())


def _empty_result(email: str, error: Optional[str] = None) -> Dict[str, Any]:
    """Return a normalized empty result dict."""
    return {
        "found": False,
        "passwords": [],
        "breach_sources": [],
        "raw_results": None,
        "email": email,
        "error": error,
    }


# --- DeHashed ---------------------------------------------------------------

def _query_dehashed(email: str, api_key: str) -> Dict[str, Any]:
    """Query the DeHashed API for credentials tied to ``email``.

    DeHashed uses HTTP Basic auth with the API key as both the username and
    password (per their public docs) and returns JSON with a ``balance`` field
    and a ``dehashed_items`` (or legacy ``entries``) list of records.
    """
    if not api_key:
        return _empty_result(email, "No DeHashed API key provided.")

    url = f"{DEHASHED_API_URL}?query=email:{email}"
    try:
        resp = requests.get(
            url,
            auth=(api_key, api_key),
            headers={"Accept": "application/json"},
            timeout=DEFAULT_TIMEOUT,
        )
    except requests.RequestException as exc:
        logger.warning("DeHashed request failed for %s: %s", email, exc)
        return _empty_result(email, f"Request error: {exc}")

    if resp.status_code == 401:
        return _empty_result(email, "DeHashed API key rejected (401).")
    if resp.status_code == 402:
        return _empty_result(email, "DeHashed account has insufficient credits (402).")
    if resp.status_code == 429:
        return _empty_result(email, "DeHashed rate limit hit (429).")
    if resp.status_code >= 400:
        logger.warning("DeHashed HTTP %s for %s: %s",
                       resp.status_code, email, resp.text[:200])
        return _empty_result(email, f"DeHashed HTTP {resp.status_code}.")

    try:
        payload = resp.json()
    except ValueError:
        return _empty_result(email, "DeHashed returned non-JSON response.")

    items = payload.get("dehashed_items") or payload.get("entries") or []
    return _normalize_dehashed(email, payload, items)


def _normalize_dehashed(
    email: str, payload: Dict[str, Any], items: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Normalize DeHashed records into the standard result shape."""
    passwords: List[str] = []
    breach_sources: List[Dict[str, str]] = []
    seen_pw = set()
    seen_src = set()

    for item in items or []:
        # DeHashed records vary; password may be in ``password`` or ``@password``.
        pw = item.get("password") or item.get("@password")
        if pw and pw not in seen_pw:
            seen_pw.add(pw)
            passwords.append(str(pw))

        # Breach source / database name and date.
        src_name = (
            item.get("database")
            or item.get("database_name")
            or item.get("source")
            or item.get("@database")
            or ""
        )
        breach_date = (
            item.get("date_breached")
            or item.get("date")
            or item.get("breach_date")
            or ""
        )
        key = (src_name, breach_date)
        if src_name and key not in seen_src:
            seen_src.add(key)
            breach_sources.append({
                "name": str(src_name),
                "date": str(breach_date) if breach_date else "",
            })

    return {
        "found": bool(passwords or breach_sources),
        "passwords": passwords,
        "breach_sources": breach_sources,
        "raw_results": payload,
        "email": email,
        "error": None,
    }


# --- IntelX -----------------------------------------------------------------

def _intelx_start_search(base: str, tier: str, email: str, api_key: str):
    """POST a search to ``base`` and return (search_id, error).

    ``tier`` is ``"paid"`` (phonebook endpoints) or ``"free"`` (intelligent
    search endpoints).  On success ``search_id`` is a string and ``error`` is
    ``None``.  On failure ``search_id`` is ``None`` and ``error`` is a human-
    readable string.  A 401 specifically signals that the endpoint does not
    recognise the key (caller should retry against the other base).
    """
    search_path = INTELX_PATHS[tier]["search"]
    url = f"{base}{search_path}"
    try:
        resp = requests.post(
            url,
            json={
                "term": email,
                "buckets": [],
                "lookuplevel": 0,
                "maxresults": 100,
                "timeout": 5,
                "datefrom": "",
                "dateto": "",
                "sort": 4,
                "media": 0,
                "terminate": [],
                "target": 1,  # 1 = credentials / leaks
            },
            headers={
                "X-Key": api_key,
                "Content-Type": "application/json",
                "User-Agent": INTELX_USER_AGENT,
            },
            timeout=DEFAULT_TIMEOUT,
        )
    except requests.RequestException as exc:
        logger.warning("IntelX start failed (%s) for %s: %s", base, email, exc)
        return None, f"Request error: {exc}"

    if resp.status_code == 401:
        return None, "auth_rejected"
    if resp.status_code >= 400:
        logger.warning("IntelX start HTTP %s (%s) for %s: %s",
                       resp.status_code, base, email, resp.text[:200])
        return None, f"IntelX HTTP {resp.status_code}."

    try:
        data = resp.json()
    except ValueError:
        return None, "IntelX returned non-JSON response."

    search_id = data.get("id")
    if not search_id:
        return None, "IntelX did not return a search id."
    return search_id, None


def _intelx_poll_results(base: str, tier: str, search_id: str, api_key: str, email: str) -> Dict[str, Any]:
    """Poll ``base`` result endpoint until the search completes.

    Returns the normalised result dict on success, or an empty-result dict
    on timeout/error.
    """
    import time

    result_path = INTELX_PATHS[tier]["result"]
    url = f"{base}{result_path}"
    payload: Dict[str, Any] = {}
    for _ in range(INTELX_MAX_POLLS):
        time.sleep(INTELX_POLL_SECONDS)
        try:
            r = requests.get(
                url,
                params={"id": search_id, "limit": 1000, "offset": -1},
                headers={"X-Key": api_key, "User-Agent": INTELX_USER_AGENT},
                timeout=DEFAULT_TIMEOUT,
            )
        except requests.RequestException as exc:
            logger.warning("IntelX poll error (%s) for %s: %s", base, email, exc)
            continue
        if r.status_code != 200:
            continue
        try:
            payload = r.json()
        except ValueError:
            continue
        # status: 0=success w/ results, 1=no more results, 2=id not found,
        # 3=no results yet (keep polling).
        status = payload.get("status")
        if status in (0, 1, 2):
            break

    if not payload:
        return _empty_result(email, "IntelX polling timed out with no results.")
    return _normalize_intelx(email, payload)


def _query_intelx(email: str, api_key: str) -> Dict[str, Any]:
    """Query IntelX for credentials tied to ``email``.

    IntelX works asynchronously: POST the search, receive an ``id``, then poll
    the result endpoint until ``status`` indicates completion. We poll
    up to :data:`INTELX_MAX_POLLS` times with :data:`INTELX_POLL_SECONDS` sleep.

    The key is tried against the **paid** endpoint (``2.intelx.io``) first,
    using the phonebook API.  If the paid endpoint rejects the key (401) we
    automatically fall back to the **free** endpoint (``free.intelx.io``),
    which uses the intelligent-search API (free tier has no phonebook access).
    This lets a single code path serve both paid and free IntelX keys without
    operator configuration.
    """
    if not api_key:
        return _empty_result(email, "No IntelX API key provided.")

    # Try paid endpoint first (phonebook API).
    search_id, err = _intelx_start_search(INTELX_PAID_BASE, "paid", email, api_key)
    base, tier = INTELX_PAID_BASE, "paid"

    if err == "auth_rejected":
        logger.info("IntelX paid key rejected; falling back to free endpoint for %s", email)
        search_id, err = _intelx_start_search(INTELX_FREE_BASE, "free", email, api_key)
        base, tier = INTELX_FREE_BASE, "free"

    if search_id is None:
        if err == "auth_rejected":
            return _empty_result(
                email,
                "IntelX API key rejected by both paid and free endpoints (401).",
            )
        return _empty_result(email, err or "IntelX search failed to start.")

    return _intelx_poll_results(base, tier, search_id, api_key, email)


def _normalize_intelx(email: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize IntelX results into the standard result shape.

    Handles two response shapes:
    - Phonebook API (paid): ``{"selectors": [{"records": [...]}], ...}``
    - Intelligent search (free): ``{"records": [...], "status": N}``
    """
    passwords: List[str] = []
    breach_sources: List[Dict[str, str]] = []
    seen_pw = set()
    seen_src = set()

    # Collect records from both possible locations.
    hits: List[Dict[str, Any]] = []
    hits.extend(payload.get("records") or [])
    for sel in payload.get("selectors") or []:
        hits.extend(sel.get("records") or sel.get("hits") or [])

    for hit in hits:
        pw = hit.get("password") or hit.get("pass") or hit.get("@password")
        if pw and pw not in seen_pw:
            seen_pw.add(pw)
            passwords.append(str(pw))

        src_name = hit.get("storage") or hit.get("source") or hit.get("breach") or hit.get("bucket") or ""
        breach_date = hit.get("added") or hit.get("date") or hit.get("breach_date") or ""
        key = (src_name, breach_date)
        if src_name and key not in seen_src:
            seen_src.add(key)
            breach_sources.append({
                "name": str(src_name),
                "date": str(breach_date) if breach_date else "",
            })

    return {
        "found": bool(passwords or breach_sources),
        "passwords": passwords,
        "breach_sources": breach_sources,
        "raw_results": payload,
        "email": email,
        "error": None,
    }


# --- Public API --------------------------------------------------------------

def lookup_breach_data(
    email: str,
    api_key: str,
    provider: str = "dehashed",
) -> Dict[str, Any]:
    """Query a breach database for credentials tied to ``email``.

    Args:
        email: Target email address.
        api_key: API key for the chosen provider. Resolved from the
            DB settings helper (``dehashed_api_key`` / ``intelx_api_key``)
            or env (``DEHASHED_API_KEY`` / ``INTELX_API_KEY``) when not passed.
        provider: ``"dehashed"`` (default) or ``"intelx"``.

    Returns:
        Dict with keys ``found`` (bool), ``passwords`` (list[str]),
        ``breach_sources`` (list[{name, date}]), ``raw_results``, ``email``,
        ``error`` (Optional[str]).
    """
    if not email or "@" not in email:
        return _empty_result(email, "A valid email is required.")

    # Allow callers to pass provider=auto and resolve a key from settings/env.
    resolved_key = api_key
    if not resolved_key:
        if provider == "dehashed":
            resolved_key = _api_key("dehashed_api_key")
        elif provider == "intelx":
            resolved_key = _api_key("intelx_api_key")

    if not resolved_key:
        return _empty_result(
            email,
            f"No API key configured for provider '{provider}'.",
        )

    provider = (provider or "dehashed").lower()
    if provider == "dehashed":
        return _query_dehashed(email, resolved_key)
    if provider == "intelx":
        return _query_intelx(email, resolved_key)
    return _empty_result(email, f"Unknown provider '{provider}'.")


# --- Pretext generation -----------------------------------------------------

_PASSWORD_COMPROMISE_SUBJECT = "Action needed: your {domain} password was exposed"
_PASSWORD_COMPROMISE_BODY = (
    "Hi,\n\n"
    "Our security team found that the password for {email} was exposed "
    "in a known data breach{source}.\n\n"
    "Password found: {password}\n\n"
    "To keep your account safe, please reset your password now:\n\n"
    "    {link}\n\n"
    "This link will expire in 24 hours.\n\n"
    "Thanks,\n"
    "{domain} IT Security"
)


def generate_password_compromise_pretext(
    email: str,
    password: str,
    breach_sources: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, str]:
    """Generate a concise, non-technical 'password compromise' pretext.

    Instead of dumping every breach source, this picks the first credible
    source (if any) and keeps the message short and human-readable.

    Args:
        email: The target email whose password was leaked.
        password: The leaked plaintext password to reference in the message.
        breach_sources: Optional list of breach source dicts from
            :func:`lookup_breach_data`. Only the first source is used.

    Returns:
        Dict with ``subject`` and ``body_template`` keys. ``{PHISH_LINK}`` is
        left as a placeholder for the campaign layer to substitute the URL.
    """
    domain = email.split("@")[-1] if "@" in email else "your organization"

    # Pick one source if available. Keep the wording non-technical.
    source_phrase = ""
    if breach_sources:
        first = breach_sources[0]
        src_name = first.get("name", "").strip()
        if src_name:
            # Sanitize the source name so it cannot break the sentence.
            src_name = src_name.split(".")[0].split("/")[0].strip() or "a third-party service"
            source_phrase = f" from {src_name}"

    body = _PASSWORD_COMPROMISE_BODY.format(
        email=email,
        password=password,
        source=source_phrase,
        link="{PHISH_LINK}",
        domain=domain,
    )
    return {
        "subject": _PASSWORD_COMPROMISE_SUBJECT.format(domain=domain),
        "body_template": body,
    }
