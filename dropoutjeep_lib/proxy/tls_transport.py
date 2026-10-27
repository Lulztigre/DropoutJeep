"""HTTP transport abstraction with optional JA3/TLS fingerprint spoofing.

The proxy code historically uses ``httpx.AsyncClient``.  This module keeps that
behaviour as the default, but swaps in ``curl_cffi.AsyncSession`` when a
campaign requests a browser TLS fingerprint.  If ``curl_cffi`` is not installed
we fall back to ``httpx`` and log a warning.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

try:
    from curl_cffi.requests import AsyncSession as CurlAsyncSession

    _CURL_CFFI_AVAILABLE = True
except Exception as exc:  # pragma: no cover - import may fail on some platforms
    logger.warning("curl_cffi is not available: %s. TLS fingerprint spoofing disabled.", exc)
    CurlAsyncSession = None  # type: ignore[misc, assignment]
    _CURL_CFFI_AVAILABLE = False

import httpx


class HttpxClientAdapter:
    """Adapter around ``httpx.AsyncClient`` exposing the unified request API."""

    def __init__(self, proxy_url: str | None = None, verify: bool = False, timeout: float = 30):
        kwargs: dict[str, Any] = dict(
            verify=verify,
            timeout=timeout,
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
        )
        if proxy_url:
            kwargs["proxy"] = proxy_url
        self._client = httpx.AsyncClient(**kwargs)

    async def request(self, method: str, url: str, **kwargs) -> Any:
        return await self._client.request(method, url, **kwargs)

    async def close(self):
        await self._client.aclose()


class CurlCffiClientAdapter:
    """Adapter around ``curl_cffi.AsyncSession`` for browser TLS impersonation."""

    def __init__(
        self,
        impersonate: str,
        proxy_url: str | None = None,
        verify: bool = False,
        timeout: float = 30,
    ):
        self._impersonate = impersonate
        kwargs: dict[str, Any] = dict(verify=verify, timeout=timeout)
        if proxy_url:
            kwargs["proxy"] = proxy_url
        self._client = CurlAsyncSession(**kwargs)

    async def request(self, method: str, url: str, **kwargs) -> Any:
        # httpx uses ``content`` for raw request bodies; curl_cffi uses ``data``.
        if "content" in kwargs:
            kwargs["data"] = kwargs.pop("content")
        # httpx uses ``follow_redirects``; curl_cffi uses ``allow_redirects``.
        if "follow_redirects" in kwargs:
            kwargs["allow_redirects"] = kwargs.pop("follow_redirects")
        # Never let curl_cffi inject its own Accept-Encoding handling; the proxy
        # forwards the victim's headers unchanged.
        kwargs.setdefault("accept_encoding", "identity")
        kwargs["impersonate"] = self._impersonate
        return await self._client.request(method, url, **kwargs)

    async def close(self):
        await self._client.close()


def build_async_client(
    tls_fingerprint: str | None,
    proxy_url: str | None,
    verify: bool = False,
    timeout: float = 30,
):
    """Return an async HTTP client adapter.

    ``tls_fingerprint`` examples: ``chrome120``, ``chrome124``, ``safari17_0``,
    ``firefox120``.  See curl_cffi docs for the full list of impersonation
    strings.  If blank/None or curl_cffi is unavailable, ``httpx`` is used.
    """
    fingerprint = (tls_fingerprint or "").strip().lower()
    if fingerprint and _CURL_CFFI_AVAILABLE:
        logger.debug("Using curl_cffi impersonation profile: %s", fingerprint)
        return CurlCffiClientAdapter(
            impersonate=fingerprint,
            proxy_url=proxy_url,
            verify=verify,
            timeout=timeout,
        )

    if fingerprint and not _CURL_CFFI_AVAILABLE:
        logger.warning(
            "Campaign requested TLS fingerprint %s but curl_cffi is not installed; "
            "falling back to httpx.",
            fingerprint,
        )

    return HttpxClientAdapter(proxy_url=proxy_url, verify=verify, timeout=timeout)
