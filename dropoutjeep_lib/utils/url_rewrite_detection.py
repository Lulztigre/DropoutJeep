"""Proofpoint and Mimecast URL-rewrite detection helpers.

Detects and decodes the URL-rewrite wrappers used by the two most common
secure email gateways (SEGs) that operate at the enterprise edge:

* **Proofpoint URL Defense** — wraps links as
  ``https://urldefense.proofpoint.com/v2/url?u=<encoded>&d=...&e=...``. The
  ``u`` parameter is URL-encoded *and* uses a Proofpoint-specific
  hyphen-hex substitution scheme (``-3A`` for ``:``, ``-2F`` for ``/`` etc.)
  that must be reversed before the original URL can be recovered.

* **Mimecast URL Protection** — wraps links as
  ``https://protect-us.mimecast.com/s/<token>?url=<encoded>`` (or the
  ``?u=`` variant). The ``url``/``u`` parameter is ordinary percent-encoding.

When a click arrives at the DropoutJeep landing page and the ``Referer``
header points at one of these gateway hosts, the click has already been
inspected (and likely sandbox-detonated) by the SEG before reaching the
victim browser. That is a strong signal that the target organisation is
behind a rewriting SEG and that *future* sends to that recipient should
switch to attachment-based delivery so the link never passes through the
rewrite pipeline.

Standalone — only stdlib (``urllib``, ``logging``, ``re``) is used.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

__all__ = [
    "PROOFPOINT_HOST_SUFFIXES",
    "MIMECAST_HOST_SUFFIXES",
    "is_proofpoint_referer",
    "is_mimecast_referer",
    "parse_proofpoint_url",
    "parse_mimecast_url",
    "detect_gateway",
    "attachment_delivery_warning",
    "log_gateway_rewrite",
]

logger = logging.getLogger("dropoutjeep")

# ---------------------------------------------------------------------------
# Host matchers.
# ---------------------------------------------------------------------------

#: Proofpoint URL Defense host suffixes. ``urldefense.proofpoint.com`` is the
#: canonical v2/v3 wrapper; some tenants also see ``*.proofpoint.com`` relay
#: hosts. We match the stable suffixes.
PROOFPOINT_HOST_SUFFIXES: Tuple[str, ...] = (
    "urldefense.proofpoint.com",
    ".proofpoint.com",
)

#: Mimecast URL Protection host suffixes. Regional hosts include
#: ``protect-us.mimecast.com``, ``protect-eu.mimecast.com``, etc.; the bare
#: ``.mimecast.com`` suffix catches all of them.
MIMECAST_HOST_SUFFIXES: Tuple[str, ...] = (
    ".mimecast.com",
    "mimecast.com",
)

_PROOFPOINT_HOST_RE = re.compile(
    r"(?i)(?:.*\.)?proofpoint\.com$|urldefense\.proofpoint\.com$"
)
_MIMECAST_HOST_RE = re.compile(r"(?i)(?:.*\.)?mimecast\.com$")


def _host_of(url: Optional[str]) -> Optional[str]:
    """Return the lowercased hostname of ``url`` or ``None``."""
    if not url:
        return None
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Referer detection.
# ---------------------------------------------------------------------------


def is_proofpoint_referer(referer: Optional[str]) -> bool:
    """Return True if ``referer`` points at a Proofpoint URL Defense host."""
    if not referer:
        return False
    host = _host_of(referer)
    if not host:
        return False
    return bool(_PROOFPOINT_HOST_RE.search(host))


def is_mimecast_referer(referer: Optional[str]) -> bool:
    """Return True if ``referer`` points at a Mimecast URL Protection host."""
    if not referer:
        return False
    host = _host_of(referer)
    if not host:
        return False
    return bool(_MIMECAST_HOST_RE.search(host))


# ---------------------------------------------------------------------------
# Proofpoint URL decoding.
# ---------------------------------------------------------------------------

#: Proofpoint v2/v3 substitution map. In the ``u`` parameter, Proofpoint
#: replaces each byte with ``-`` + two hex digits. A literal hyphen in the
#: original URL is encoded as ``--`` (i.e. ``-2D``). We reverse this with a
#: regex over the already-percent-decoded string.
_PP_HEX_ESCAPE = re.compile(r"-([0-9A-Fa-f]{2})")


def _decode_proofpoint_u(value: str) -> str:
    """Reverse Proofpoint's ``u``-parameter encoding.

    Proofpoint URL Defense v2 encodes the destination URL in its ``u`` query
    parameter using two layered substitutions on top of ordinary
    percent-encoding:

    * ``/`` (slash) is written as ``_`` (underscore).
    * Every other non-alphanumeric byte is written as ``-XX`` (hyphen + two
      hex digits). A literal underscore in the *original* URL is encoded as
      ``-5F``; a literal hyphen is ``-2D``.

    Recovery order is critical and order-sensitive:

    1. Percent-decode once (``parse_qs`` already did this; we repeat
       defensively in case the caller passed the raw param value).
    2. Replace every remaining ``_`` with ``/``. These are Proofpoint's
       slash substitutes. Literal underscores from the original URL are
       still safely hidden as ``-5F`` at this point, so they survive.
    3. Expand ``-XX`` hex escapes into their bytes. This converts ``-3A``
       back to ``:``, ``-5F`` back to a real ``_``, ``-2D`` to ``-``, etc.

    Args:
        value: The raw ``u`` query parameter value.

    Returns:
        The decoded original URL.
    """
    if not value:
        return value
    # Step 1: defensive percent-decode (parse_qs already unquotes once).
    decoded = unquote(value)
    # Step 2: Proofpoint slash substitution. Done before hex expansion so a
    # literal underscore (encoded as -5F) is not mistaken for a slash.
    decoded = decoded.replace("_", "/")
    # Step 3: expand -XX hex escapes into the byte they represent.
    def _sub(match: "re.Match[str]") -> str:
        hex_pair = match.group(1)
        try:
            return chr(int(hex_pair, 16))
        except (ValueError, OverflowError):
            # Not a valid byte escape — leave untouched.
            return match.group(0)

    decoded = _PP_HEX_ESCAPE.sub(_sub, decoded)
    return decoded


def parse_proofpoint_url(url: str) -> Optional[Dict[str, str]]:
    """Parse a Proofpoint URL Defense wrapper URL.

    Handles the v2 format::

        https://urldefense.proofpoint.com/v2/url?u=<encoded>&d=DwMF...&e=...&r=...

    Args:
        url: The full Proofpoint wrapper URL.

    Returns:
        A dict with keys ``host``, ``original_url`` (decoded destination),
        ``d`` (data token), ``e`` (envelope), ``r`` (recipient token), or
        ``None`` if ``url`` is not a Proofpoint wrapper.
    """
    if not url:
        return None
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    host = parsed.hostname
    if not host or not _PROOFPOINT_HOST_RE.search(host):
        return None

    qs = parse_qs(parsed.query, keep_blank_values=True)
    u_values = qs.get("u") or []
    original_url: Optional[str] = None
    if u_values:
        original_url = _decode_proofpoint_u(u_values[0])

    return {
        "host": host,
        "original_url": original_url,
        "d": (qs.get("d") or [""])[0],
        "e": (qs.get("e") or [""])[0],
        "r": (qs.get("r") or [""])[0],
    }


# ---------------------------------------------------------------------------
# Mimecast URL decoding.
# ---------------------------------------------------------------------------


def parse_mimecast_url(url: str) -> Optional[Dict[str, str]]:
    """Parse a Mimecast URL Protection wrapper URL.

    Handles both the ``?url=`` and ``?u=`` parameter variants used by
    different Mimecast regional deployments::

        https://protect-us.mimecast.com/s/<token>?url=https%3A%2F%2Fexample.com
        https://protect-eu.mimecast.com/u/<token>?u=https%3A%2F%2Fexample.com

    Args:
        url: The full Mimecast wrapper URL.

    Returns:
        A dict with keys ``host``, ``path_token`` (the ``/s/<id>`` or
        ``/u/<id>`` path segment, if present), ``original_url`` (decoded),
        or ``None`` if ``url`` is not a Mimecast wrapper.
    """
    if not url:
        return None
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    host = parsed.hostname
    if not host or not _MIMECAST_HOST_RE.search(host):
        return None

    qs = parse_qs(parsed.query, keep_blank_values=True)
    # Mimecast uses 'url' on US/EMEA protect hosts and 'u' elsewhere.
    encoded = (qs.get("url") or qs.get("u") or [""])
    original_url: Optional[str] = None
    if encoded and encoded[0]:
        original_url = unquote(encoded[0])

    # Capture the /s/<id> or /u/<id> token segment if present.
    path = parsed.path or ""
    path_token = ""
    token_match = re.match(r"/(?:s|u)/([A-Za-z0-9_-]+)", path)
    if token_match:
        path_token = token_match.group(1)

    return {
        "host": host,
        "path_token": path_token,
        "original_url": original_url,
    }


# ---------------------------------------------------------------------------
# Unified gateway detection.
# ---------------------------------------------------------------------------

#: Sentinel returned by :func:`detect_gateway` when no rewrite is observed.
GATEWAY_NONE: str = ""

#: Gateway type strings returned by :func:`detect_gateway`.
GATEWAY_PROOFPOINT: str = "proofpoint"
GATEWAY_MIMECAST: str = "mimecast"
GATEWAY_SAFELINKS: str = "safelinks"


def detect_gateway(
    referer: Optional[str],
    current_url: Optional[str] = None,
) -> Optional[str]:
    """Detect which (if any) secure-email-gateway rewrote the click URL.

    Inspects the ``Referer`` header first (the strongest signal — the victim
    browser was just on the gateway's wrapper page), then falls back to
    inspecting ``current_url`` itself in case the click is still on a wrapper
    URL the gateway redirected through rather than away from.

    Args:
        referer: Raw ``Referer`` header value on the inbound click.
        current_url: The URL the click is currently arriving at, if
            available. Used as a secondary signal when the referer is empty
            but the click is sitting on a wrapper URL.

    Returns:
        One of ``"proofpoint"``, ``"mimecast"``, ``"safelinks"`` when a
        gateway rewrite is detected, or ``None`` when no rewrite is
        detected on either input.
    """
    # Prefer the referer — if present, it is the authoritative signal that
    # the victim just came from the gateway's wrapper page.
    if referer:
        if is_proofpoint_referer(referer):
            return GATEWAY_PROOFPOINT
        if is_mimecast_referer(referer):
            return GATEWAY_MIMECAST
        # Late import to keep this module standalone w.r.t. safelinks.py
        # even if the O365 helper is not on the path.
        try:
            from dropoutjeep_lib.utils.safelinks import is_safelinks_referer

            if is_safelinks_referer(referer):
                return GATEWAY_SAFELINKS
        except Exception:  # pragma: no cover - defensive
            pass

    # Fall back to the current URL — the click may still be on the wrapper.
    if current_url:
        try:
            if parse_proofpoint_url(current_url) is not None:
                return GATEWAY_PROOFPOINT
            if parse_mimecast_url(current_url) is not None:
                return GATEWAY_MIMECAST
            from dropoutjeep_lib.utils.safelinks import parse_safelinks_url

            if parse_safelinks_url(current_url) is not None:
                return GATEWAY_SAFELINKS
        except Exception:  # pragma: no cover - defensive
            pass

    return None


# ---------------------------------------------------------------------------
# Logging + operator guidance.
# ---------------------------------------------------------------------------


def log_gateway_rewrite(
    gateway_type: str,
    wrapper_url: Optional[str],
    *,
    recipient: Optional[str] = None,
    campaign: Optional[str] = None,
) -> None:
    """Log a gateway rewrite observation as an operational warning.

    Args:
        gateway_type: One of the ``GATEWAY_*`` constants (or the bare
            string ``"proofpoint"`` / ``"mimecast"`` / ``"safelinks"``).
        wrapper_url: The wrapper URL that was observed, if known.
        recipient: Optional recipient identifier for log correlation.
        campaign: Optional campaign identifier for log correlation.
    """
    logger.warning(
        "gateway_rewrite detected gateway=%s recipient=%s campaign=%s wrapper_url=%s",
        gateway_type,
        recipient,
        campaign,
        wrapper_url,
    )


def attachment_delivery_warning(gateway_type: str) -> str:
    """Return an operator-facing warning recommending attachment delivery.

    When a gateway rewrite is detected for a recipient, continuing to send
    inline clickable HTTP(S) links means every future click is again
    observed — and likely sandbox-detonated — by the SEG before it reaches
    the victim. The robust pivot is to switch that recipient's delivery to
    an attachment-borne payload (DOCX with embedded link, LNK, ISO, etc.)
    so the payload URL never enters the gateway's rewrite pipeline.

    Args:
        gateway_type: Gateway string as returned by :func:`detect_gateway`.

    Returns:
        A human-readable warning string suitable for surfacing in the
        campaign dashboard / event-triage UI.
    """
    pretty = {
        GATEWAY_PROOFPOINT: "Proofpoint URL Defense",
        GATEWAY_MIMECAST: "Mimecast URL Protection",
        GATEWAY_SAFELINKS: "Microsoft Defender for O365 Safe Links",
    }.get(gateway_type, gateway_type or "unknown gateway")

    return (
        f"Target behind {pretty}: link-rewrite detected. Future inline "
        f"HTTP(S) links will be re-wrapped, inspected, and likely "
        f"sandbox-detonated before reaching the recipient. Switch this "
        f"recipient to attachment-based delivery (DOCX-embedded link, LNK, "
        f"ISO/searchConnector-ms) so the payload URL never enters the "
        f"gateway rewrite pipeline."
    )


def recommended_delivery_vectors(gateway_type: str) -> List[str]:
    """Return a short list of suggested attachment-delivery vectors.

    The list is gateway-aware: Safe Links has a few additional non-rewritten
    formats (UNC, MAPI-embedded, .searchConnector-ms) that the operator can
    use without switching to an attachment at all, so for Safe Links we
    surface those first.

    Args:
        gateway_type: Gateway string as returned by :func:`detect_gateway`.

    Returns:
        Ordered list of recommended delivery vectors, most-preferred first.
    """
    base_vectors = [
        "DOCX with embedded link (link inside the document, not the email body)",
        "LNK / .url shortcut pointing at the operator's WebDAV",
        "ISO / IMG container with payload DLL + LNK",
        ".searchConnector-ms pointing at operator WebDAV (no MOTW)",
    ]
    if gateway_type == GATEWAY_SAFELINKS:
        # Safe Links has extra non-rewritten formats worth surfacing first.
        return [
            "UNC path (\\\\server\\share\\file) — not rewritten by Safe Links",
            "MAPI-embedded inline OLE / RTF object — not in the HTML href set",
            ".searchConnector-ms file — not rewritten by Safe Links",
            *base_vectors,
        ]
    return base_vectors
