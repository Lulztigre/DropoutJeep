"""Browser-in-the-Middle transport using Playwright.

This module provides an async HTTP client adapter that renders target pages in
a headless Chromium instance. It is selected per campaign by setting
``flow_config.renderer`` to ``"playwright"``.

When Playwright is not installed the adapter falls back to ``httpx`` and logs
a warning so the rest of the proxy keeps working.

Connection pooling
------------------
Launching a new Chromium process per request is too slow for production use.
``BrowserContextPool`` maintains a fixed set of persistent browser contexts.
Each incoming GET gets a fresh *page* (cheap) from a pooled *context* (expensive).
Contexts are selected round-robin and health-checked before use; crashed or
stale contexts are silently replaced.
"""

import asyncio
import itertools
import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)


try:
    from playwright.async_api import async_playwright

    _PLAYWRIGHT_AVAILABLE = True
except Exception as exc:  # pragma: no cover - import may fail until browsers installed
    logger.warning("Playwright is not available: %s. Browser-in-the-Middle disabled.", exc)
    async_playwright = None  # type: ignore[misc, assignment]
    _PLAYWRIGHT_AVAILABLE = False


# ---------------------------------------------------------------------------
# Browser context pool
# ---------------------------------------------------------------------------

class _PooledContext:
    """Wrapper around a Playwright BrowserContext with health metadata."""

    __slots__ = ("browser", "context", "created_at", "request_count")

    def __init__(self, browser, context):
        self.browser = browser
        self.context = context
        self.created_at = time.monotonic()
        self.request_count = 0

    async def is_healthy(self) -> bool:
        """Return True if the context is still usable."""
        try:
            # browser.is_connected() is the cheapest check.
            if not self.browser.is_connected():
                return False
            # Attempt a trivial evaluation to catch zombie contexts.
            page = await self.context.new_page()
            await page.close()
            return True
        except Exception:
            return False

    async def close(self):
        try:
            await self.context.close()
        except Exception:
            pass
        try:
            await self.browser.close()
        except Exception:
            pass


class BrowserContextPool:
    """Fixed-size pool of Playwright browser contexts with round-robin selection.

    Parameters
    ----------
    pool_size :
        Number of persistent browser contexts to maintain.  Each context runs
        inside its own Chromium process.  Default ``3`` balances memory usage
        against concurrency.
    proxy_url :
        Optional upstream proxy for all browser contexts.
    max_context_age_sec :
        Seconds after creation before a context is proactively recycled.
        Prevents memory leaks from long-running processes.  Default ``3600``
        (1 hour).
    max_requests_per_context :
        Request limit before a context is recycled.  Default ``500``.
    """

    def __init__(
        self,
        pool_size: int = 3,
        proxy_url: str | None = None,
        max_context_age_sec: float = 3600,
        max_requests_per_context: int = 500,
    ):
        self._pool_size = pool_size
        self._proxy_url = proxy_url
        self._max_age = max_context_age_sec
        self._max_requests = max_requests_per_context
        self._contexts: list[_PooledContext] = []
        self._round_robin = itertools.cycle(range(pool_size))
        self._lock = asyncio.Lock()
        self._playwright = None
        self._initialized = False

    async def _ensure_playwright(self):
        """Lazily start the Playwright runtime (once per pool lifetime)."""
        if self._playwright is None:
            self._playwright = await async_playwright().__aenter__()

    async def _create_context(self) -> _PooledContext:
        """Spin up a fresh Chromium process + browser context."""
        await self._ensure_playwright()
        proxy_cfg = {"server": self._proxy_url} if self._proxy_url else None
        launch_kwargs: dict[str, Any] = {"headless": True}
        if proxy_cfg:
            launch_kwargs["proxy"] = proxy_cfg
        browser = await self._playwright.chromium.launch(**launch_kwargs)
        context = await browser.new_context()
        pooled = _PooledContext(browser, context)
        logger.debug(
            "Created new browser context (pool size will be %d)", len(self._contexts) + 1
        )
        return pooled

    async def _replace_context(self, index: int):
        """Discard a stale context at *index* and create a fresh one."""
        old = self._contexts[index]
        await old.close()
        self._contexts[index] = await self._create_context()

    async def get_context(self) -> _PooledContext:
        """Return the next healthy context, creating the pool on first call.

        Selection is round-robin.  If the selected context is unhealthy or
        over its usage limits it is silently replaced before being returned.
        """
        async with self._lock:
            # Lazy init: fill the pool on first access.
            if not self._initialized:
                for _ in range(self._pool_size):
                    self._contexts.append(await self._create_context())
                self._initialized = True

            idx = next(self._round_robin)
            pooled = self._contexts[idx]

            # Check staleness by age or request count.
            age = time.monotonic() - pooled.created_at
            over_age = age > self._max_age
            over_count = pooled.request_count >= self._max_requests

            if over_age or over_count:
                logger.debug(
                    "Recycling context %d (age=%.0fs, requests=%d)",
                    idx, age, pooled.request_count,
                )
                await self._replace_context(idx)
                pooled = self._contexts[idx]
            elif not await pooled.is_healthy():
                logger.warning("Context %d unhealthy, replacing", idx)
                await self._replace_context(idx)
                pooled = self._contexts[idx]

            pooled.request_count += 1
            return pooled

    async def close(self):
        """Shut down all pooled contexts and the Playwright runtime."""
        async with self._lock:
            for pooled in self._contexts:
                await pooled.close()
            self._contexts.clear()
            self._initialized = False
        if self._playwright is not None:
            try:
                await self._playwright.__aexit__(None, None, None)
            except Exception:
                pass
            self._playwright = None
        logger.debug("BrowserContextPool closed")


# ---------------------------------------------------------------------------
# Module-level singleton pools, keyed by proxy URL.
# ---------------------------------------------------------------------------

_pools: dict[str | None, BrowserContextPool] = {}
_pool_lock = asyncio.Lock()


async def get_pool(
    proxy_url: str | None = None,
    pool_size: int = 3,
) -> BrowserContextPool:
    """Return (and lazily create) a shared pool for the given proxy URL."""
    async with _pool_lock:
        pool = _pools.get(proxy_url)
        if pool is None:
            pool = BrowserContextPool(pool_size=pool_size, proxy_url=proxy_url)
            _pools[proxy_url] = pool
        return pool


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class PlaywrightClientAdapter:
    """Adapter that renders pages with Playwright and returns a fake response.

    Instead of launching a fresh Chromium per request, this adapter borrows a
    ``BrowserContext`` from a shared :class:`BrowserContextPool`.  Each GET
    creates a disposable *page* (cheap) inside the pooled context (expensive).
    """

    def __init__(
        self,
        proxy_url: str | None = None,
        verify: bool = False,
        timeout: float = 30,
        pool_size: int = 3,
    ):
        self.proxy_url = proxy_url
        self.verify = verify
        self.timeout = timeout
        self._pool_size = pool_size
        self._pool: BrowserContextPool | None = None
        self._fallback = httpx.AsyncClient(
            verify=verify,
            timeout=timeout,
            proxy=proxy_url,
            follow_redirects=False,
        )

    async def _ensure_pool(self) -> BrowserContextPool:
        if self._pool is None:
            self._pool = await get_pool(self.proxy_url, self._pool_size)
        return self._pool

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        params: dict | None = None,
        content: bytes | None = None,
        follow_redirects: bool = False,
        timeout: float | None = None,
        ctx: dict | None = None,
        plugins: list | None = None,
    ) -> Any:
        """Render ``url`` with Playwright for GET; fall back to httpx otherwise."""
        if method.upper() != "GET" or not _PLAYWRIGHT_AVAILABLE:
            if not _PLAYWRIGHT_AVAILABLE:
                logger.warning(
                    "Campaign requested Playwright renderer but Playwright is not available; "
                    "falling back to httpx."
                )
            return await self._fallback.request(
                method,
                url,
                headers=headers,
                params=params,
                content=content,
                follow_redirects=follow_redirects,
                timeout=timeout or self.timeout,
            )

        return await self._render_page(
            url,
            headers=headers,
            timeout=timeout or self.timeout,
            ctx=ctx or {},
            plugins=plugins or [],
        )

    async def _render_page(
        self,
        url: str,
        headers: dict | None,
        timeout: float,
        ctx: dict,
        plugins: list,
    ) -> Any:
        """Borrow a pooled context, open a page, navigate, and return DOM."""
        from .plugin_system import apply_plugin_playwright_hooks

        rendered_headers = {"content-type": "text/html; charset=utf-8"}

        try:
            pool = await self._ensure_pool()
            pooled = await pool.get_context()

            # Create a disposable page inside the pooled context.
            page = await pooled.context.new_page()

            if headers:
                clean_headers = {
                    k: v for k, v in headers.items()
                    if k.lower() not in {
                        "connection", "keep-alive", "transfer-encoding",
                        "content-length", "host", "cookie",
                    }
                }
                await pooled.context.set_extra_http_headers(clean_headers)

            await page.goto(url, wait_until="networkidle", timeout=timeout * 1000)

            await apply_plugin_playwright_hooks(page, ctx, plugins)
            await self._handle_captcha(page, ctx)

            # Reflect the real HTTP status of the navigation.
            status = 200
            try:
                main_response = await page.evaluate(
                    """() => {
                        const entries = window.performance.getEntriesByType('navigation');
                        if (entries && entries.length) {
                            return entries[0].responseStatus || 200;
                        }
                        return 200;
                    }"""
                )
                status = int(main_response or 200)
            except Exception:
                status = 200

            body = await page.content()
            await page.close()

            fake_response = _FakeResponse(status, rendered_headers, body.encode("utf-8"))
            return fake_response
        except Exception as exc:
            logger.exception("Playwright render failed for %s: %s", url, exc)
            # Fall back to httpx so the proxy stays up.
            return await self._fallback.request(
                "GET", url, headers=headers, follow_redirects=False, timeout=timeout
            )

    async def _handle_captcha(self, page, ctx: dict):
        """Detect common CAPTCHA services and log; solving is plugin-extensible."""
        config = ctx.get("flow_config", {})
        captcha_solver = config.get("captcha_solver")
        selectors = [
            ".g-recaptcha",
            "[data-sitekey]",
            ".h-captcha",
            "[class*='turnstile']",
            "iframe[src*='recaptcha']",
            "iframe[src*='hcaptcha']",
        ]
        detected = []
        for selector in selectors:
            try:
                if await page.locator(selector).count() > 0:
                    detected.append(selector)
            except Exception:
                pass
        if detected:
            logger.warning("Playwright detected CAPTCHA selectors: %s", detected)
            if captcha_solver:
                logger.info("CAPTCHA solver configured: %s", captcha_solver)
            else:
                logger.info("No captcha_solver configured; returning challenge page as-is")

    async def close(self):
        """Close the pooled contexts and the httpx fallback."""
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
        await self._fallback.aclose()


class _FakeResponse:
    """Minimal response object shaped like httpx.Response."""

    def __init__(self, status_code: int, headers: dict, content: bytes):
        self.status_code = status_code
        self.headers = headers
        self.content = content

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")


def build_playwright_client(
    proxy_url: str | None,
    verify: bool = False,
    timeout: float = 30,
    pool_size: int = 3,
):
    """Return a Playwright adapter. If Playwright is unavailable, returns None."""
    if not _PLAYWRIGHT_AVAILABLE:
        return None
    return PlaywrightClientAdapter(
        proxy_url=proxy_url, verify=verify, timeout=timeout, pool_size=pool_size,
    )
