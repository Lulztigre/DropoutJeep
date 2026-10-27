"""O365 Safe Links detection and bypass helpers.

Detects and decodes Microsoft Defender for Office 365 "Safe Links" URL rewrites
that wrap outbound phishing-simulation links the moment a mailbox on an O365
tenant protected by Defender receives a message containing a clickable URL.

Safe Links wraps links like this::

    https://nam01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fphish.example.com%2Flanding&data=...&reserved=0

When the recipient clicks the wrapped link, the click is sent to Microsoft
first (which records and inspects it) and only then is the user redirected to
the original URL — but by then the click has already been observed, scanned,
and potentially detonated in a sandbox by Defender. Detecting this wrapper on
the inbound side tells DropoutJeep two things:

1. The target mailbox is on O365 *and* Defender for Office 365 is enabled.
2. Any future click against the same campaign that arrives via a Safe Links
   referer should be treated as having already passed through Microsoft's
   inspection pipeline (likely detonated), not as a clean victim click.

The module also documents URL formats that Safe Links deliberately does *not*
rewrite, so operators who detect Safe Links on a tenant can switch future
sends to those formats to retain stealth.

Standalone — only stdlib (``urllib``, ``logging``, ``re``) is used.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

__all__ = [
    "SAFELINKS_HOST_SUFFIX",
    "is_safelinks_referer",
    "parse_safelinks_url",
    "extract_original_url",
    "safelinks_bypass_formats",
    "log_safelinks_rewrite",
]

logger = logging.getLogger("dropoutjeep")

# Host suffix that identifies a Safe Links wrapper. The leading subdomain
# varies by tenant region (nam01, eu01, emea01, etc.) so we only anchor on
# the stable trailing host.
SAFELINKS_HOST_SUFFIX: str = ".safelinks.protection.outlook.com"

# Pre-compiled host matcher — case-insensitive, suffix-anchored.
_SAFELINKS_HOST_RE = re.compile(
    r"(?i)[A-Za-z0-9.-]+" + re.escape(SAFELINKS_HOST_SUFFIX) + r"$"
)


def _normalize_referer(referer: Optional[str]) -> str:
    """Return a trimmed, non-None copy of a Referer header value."""
    if not referer:
        return ""
    return referer.strip()


def is_safelinks_referer(referer: Optional[str]) -> bool:
    """Return True if ``referer`` points at a Safe Links protection host.

    Args:
        referer: Raw value of the HTTP ``Referer`` header on the inbound
            click, or ``None`` / empty if absent.

    Returns:
        ``True`` when the referer host ends with
        ``.safelinks.protection.outlook.com`` (any regional subdomain),
        ``False`` otherwise (including for malformed URLs).
    """
    ref = _normalize_referer(referer)
    if not ref:
        return False
    try:
        host = urlparse(ref).hostname
    except ValueError:
        # Malformed referer — treat conservatively as non-safelinks.
        return False
    if not host:
        return False
    return bool(_SAFELINKS_HOST_RE.match(host))


def parse_safelinks_url(safelinks_url: str) -> Optional[Dict[str, str]]:
    """Parse a Safe Links wrapper URL into its component parts.

    A Safe Links URL looks like::

        https://nam01.safelinks.protection.outlook.com/?url=<encoded>&data=<...>&reserved=0

    This function extracts the wrapper host, the original (decoded) URL the
    wrapper will redirect to, and any data/reserved metadata.

    Args:
        safelinks_url: The full Safe Links wrapper URL as observed in a
            Referer header or as the URL a recipient was redirected through.

    Returns:
        A dict with keys ``host``, ``original_url`` (decoded), ``data``,
        and ``reserved``. ``original_url`` is ``None`` when the ``url`` query
        parameter is absent or unparseable. Returns ``None`` when the input is
        not a Safe Links URL at all.
    """
    if not safelinks_url:
        return None
    try:
        parsed = urlparse(safelinks_url)
    except ValueError:
        return None
    host = parsed.hostname
    if not host or not _SAFELINKS_HOST_RE.match(host):
        return None

    qs = parse_qs(parsed.query, keep_blank_values=True)
    # Safe Links uses a single 'url' query parameter holding the encoded
    # destination. parse_qs decodes percent-encoding once already.
    url_values = qs.get("url") or []
    original_url: Optional[str] = None
    if url_values:
        # Take the first occurrence; further unquoting is a safety net —
        # parse_qs already unquotes, but double-encoding has been seen in
        # some regional variants.
        candidate = url_values[0]
        unquoted = unquote(candidate)
        original_url = unquoted if unquoted != candidate else candidate

    data_values = qs.get("data") or []
    reserved_values = qs.get("reserved") or []

    return {
        "host": host,
        "original_url": original_url,
        "data": data_values[0] if data_values else "",
        "reserved": reserved_values[0] if reserved_values else "",
    }


def log_safelinks_rewrite(
    safelinks_url: str,
    *,
    recipient: Optional[str] = None,
    campaign: Optional[str] = None,
) -> None:
    """Log a Safe Links rewrite observation as an operational warning.

    A rewrite observation is itself useful intelligence: it indicates the
    target mailbox is on O365 and that Defender for Office 365 is licensed
    and active for that tenant. Operators can use this to bias future sends
    for the same recipient toward attachment-based delivery or to formats
    Safe Links does not rewrite.

    Args:
        safelinks_url: The observed Safe Links wrapper URL.
        recipient: Optional recipient identifier for log correlation.
        campaign: Optional campaign identifier for log correlation.
    """
    parsed = parse_safelinks_url(safelinks_url)
    original = parsed["original_url"] if parsed else None
    logger.warning(
        "safelinks_rewrite detected target_on_o365_with_defender "
        "recipient=%s campaign=%s original_url=%s wrapper_host=%s",
        recipient,
        campaign,
        original,
        parsed["host"] if parsed else "?",
    )


def extract_original_url(safelinks_url: str) -> Optional[str]:
    """Return the original (decoded) destination URL from a Safe Links wrapper.

    Convenience wrapper around :func:`parse_safelinks_url` that returns only
    the decoded original URL the wrapper points at, logging the rewrite event
    at warning level so the operator sees the intelligence signal.

    Args:
        safelinks_url: The Safe Links wrapper URL.

    Returns:
        The decoded original URL, or ``None`` if the input is not a Safe
        Links URL or contains no ``url`` parameter.
    """
    parsed = parse_safelinks_url(safelinks_url)
    if parsed is None:
        return None
    original = parsed.get("original_url")
    if original:
        log_safelinks_rewrite(safelinks_url)
    return original


# ---------------------------------------------------------------------------
# Future-send guidance: URL formats Safe Links does not rewrite.
# ---------------------------------------------------------------------------

#: Each entry documents a URL / payload format that Safe Links leaves
#: unwrapped when delivered to an O365 + Defender mailbox, with a one-line
#: rationale an operator can use when planning future sends.
SAFELINKS_NON_REWRITTEN_FORMATS: List[Dict[str, str]] = [
    {
        "format": r"\\server\share\file (UNC)",
        "category": "internal relay",
        "rationale": (
            "Safe Links only rewrites HTTP(S) URLs. UNC paths (file:// or "
            "bare \\\\server\\share\\file) pass through untouched because "
            "Defender does not consider them clickable web links. Embed in "
            "the email body as a UNC reference to land a payload outside the "
            "rewrite pipeline."
        ),
    },
    {
        "format": "MAPI-embedded content (inline OLE / RTF objects)",
        "category": "mapi embedded",
        "rationale": (
            "Objects embedded directly in the MAPI message body (OLE "
            "attachments rendered inline, RTF-embedded objects) bypass the "
            "link-rewrite scan, which only walks the parsed href set of the "
            "HTML body. Inline OLE is delivered as-is to the Outlook client."
        ),
    },
    {
        "format": ".searchConnector-ms files (search-ms: protocol)",
        "category": "search connector",
        "rationale": (
            "A .searchConnector-ms XML file pointing at a search-ms:// "
            "query or a WebDAV location is not an http(s) link and is not "
            "rewritten. When the victim opens it Explorer connects to the "
            "operator's WebDAV without a Safe Links hop."
        ),
    },
    {
        "format": "Attachment-borne links (links inside an attached DOCX/PDF)",
        "category": "attachment delivery",
        "rationale": (
            "Safe Links rewrites links in the *email body*. Links embedded "
            "inside an attached document are only rewritten if the tenant "
            "has enabled Safe Links for Office documents AND the client "
            "performs the rewrite at open time. Many tenants do not, and "
            "document-internal links can be the URL of the operator's "
            "landing page unchanged."
        ),
    },
]


def safelinks_bypass_formats() -> List[Dict[str, str]]:
    """Return guidance on URL formats Safe Links does not rewrite.

    Use this when :func:`is_safelinks_referer` has fired for a recipient and
    the operator is planning the *next* send to the same mailbox — switching
    the delivery to one of these formats keeps the payload link out of the
    Microsoft inspection pipeline.

    Returns:
        A list of dicts, each with keys ``format``, ``category``, and
        ``rationale`` describing one non-rewritten delivery vector.
    """
    # Return copies so callers cannot mutate the module-level constant.
    return [dict(entry) for entry in SAFELINKS_NON_REWRITTEN_FORMATS]
