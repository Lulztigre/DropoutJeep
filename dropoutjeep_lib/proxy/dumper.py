"""Full HTTP request/response dumper for proxied traffic.

Matches goblin's -log-level 3 (dump matching rules) and -log-level 1 (dump all).
"""

import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger("proxy.dump")


def _safe_headers(headers: dict) -> dict:
    """Serialize header values to JSON-safe strings."""
    safe = {}
    for k, v in (headers or {}).items():
        if isinstance(v, bytes):
            safe[k] = v.decode("utf-8", errors="replace")
        elif isinstance(v, (list, tuple)):
            safe[k] = [str(i) for i in v]
        else:
            safe[k] = str(v)
    return safe


def dump_request_response(
    campaign_id: int,
    method: str,
    path: str,
    req_headers: dict,
    req_body: str | bytes | None,
    resp_status: int,
    resp_headers: dict,
    resp_body: str | bytes | None,
    dump_all: bool = False,
    matched_rule: str | None = None,
):
    """Write a structured dump entry to the proxy dump log."""
    if isinstance(req_body, bytes):
        req_body = req_body.decode("utf-8", errors="replace")
    if isinstance(resp_body, bytes):
        resp_body = resp_body.decode("utf-8", errors="replace")
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "campaign_id": campaign_id,
        "method": method,
        "path": path,
        "matched_rule": matched_rule,
        "request": {
            "headers": _safe_headers(req_headers),
            "body": req_body[:10000] if req_body else None,  # Truncate large bodies
        },
        "response": {
            "status": resp_status,
            "headers": _safe_headers(resp_headers),
            "body_preview": resp_body[:500] if resp_body else None,  # Preview only
        },
    }
    log_line = json.dumps(entry)
    if dump_all:
        logger.info(log_line)
    else:
        logger.debug(log_line)
