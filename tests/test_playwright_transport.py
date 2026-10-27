"""Tests for the Browser-in-the-Middle Playwright transport."""

import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dropoutjeep_lib.proxy.playwright_transport import (
    BrowserContextPool,
    PlaywrightClientAdapter,
    _FakeResponse,
    _PooledContext,
    build_playwright_client,
)


def _make_mock_pooled_context():
    """Build a _PooledContext backed by MagicMock objects."""
    fake_page = MagicMock()
    fake_page.goto = AsyncMock()
    fake_page.content = AsyncMock(return_value="<html></html>")
    fake_page.evaluate = AsyncMock(return_value=200)
    fake_page.locator.return_value.count = AsyncMock(return_value=0)
    fake_page.close = AsyncMock()

    fake_context = MagicMock()
    fake_context.new_page = AsyncMock(return_value=fake_page)
    fake_context.set_extra_http_headers = AsyncMock()
    fake_context.close = AsyncMock()

    fake_browser = MagicMock()
    fake_browser.is_connected = MagicMock(return_value=True)
    fake_browser.new_context = AsyncMock(return_value=fake_context)
    fake_browser.close = AsyncMock()

    pooled = _PooledContext(fake_browser, fake_context)
    return pooled, fake_page, fake_context


def _inject_mock_pool(adapter, pooled_ctx):
    """Wire a mock pool into an adapter so _render_page skips real Playwright."""
    mock_pool = MagicMock(spec=BrowserContextPool)
    mock_pool.get_context = AsyncMock(return_value=pooled_ctx)
    adapter._pool = mock_pool
    return mock_pool


def test_build_playwright_client_returns_none_when_unavailable(monkeypatch):
    monkeypatch.setattr(
        "dropoutjeep_lib.proxy.playwright_transport._PLAYWRIGHT_AVAILABLE", False
    )
    assert build_playwright_client(None) is None


def test_build_playwright_client_accepts_pool_size(monkeypatch):
    monkeypatch.setattr(
        "dropoutjeep_lib.proxy.playwright_transport._PLAYWRIGHT_AVAILABLE", True
    )
    client = build_playwright_client(None, pool_size=5)
    assert client is not None
    assert client._pool_size == 5


def test_adapter_falls_back_to_httpx_when_playwright_unavailable(monkeypatch):
    monkeypatch.setattr(
        "dropoutjeep_lib.proxy.playwright_transport._PLAYWRIGHT_AVAILABLE", False
    )

    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.content = b"fallback"
    fake_response.headers = {}

    adapter = PlaywrightClientAdapter()
    adapter._fallback = MagicMock()
    adapter._fallback.request = AsyncMock(return_value=fake_response)

    resp = asyncio.run(adapter.request("GET", "https://example.com/"))
    assert resp.status_code == 200
    adapter._fallback.request.assert_awaited_once()


def test_adapter_falls_back_to_httpx_for_non_get(monkeypatch):
    monkeypatch.setattr(
        "dropoutjeep_lib.proxy.playwright_transport._PLAYWRIGHT_AVAILABLE", True
    )

    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.content = b"post-response"

    adapter = PlaywrightClientAdapter()
    adapter._fallback = MagicMock()
    adapter._fallback.request = AsyncMock(return_value=fake_response)

    resp = asyncio.run(
        adapter.request("POST", "https://example.com/login", content=b"x=1")
    )
    assert resp.status_code == 200
    adapter._fallback.request.assert_awaited_once()


def test_adapter_renders_page_with_playwright(monkeypatch):
    monkeypatch.setattr(
        "dropoutjeep_lib.proxy.playwright_transport._PLAYWRIGHT_AVAILABLE", True
    )

    pooled_ctx, fake_page, _fake_context = _make_mock_pooled_context()
    fake_page.content = AsyncMock(return_value="<html>rendered</html>")

    adapter = PlaywrightClientAdapter()
    _inject_mock_pool(adapter, pooled_ctx)

    resp = asyncio.run(adapter.request("GET", "https://example.com/"))

    assert isinstance(resp, _FakeResponse)
    assert resp.status_code == 200
    assert b"rendered" in resp.content
    fake_page.goto.assert_awaited_once_with(
        "https://example.com/", wait_until="networkidle", timeout=30000
    )
    # Page should be closed after content extraction (not left dangling).
    fake_page.close.assert_awaited_once()


def test_adapter_reuses_pool_context(monkeypatch):
    """Multiple GETs borrow from the same pool instead of launching new browsers."""
    monkeypatch.setattr(
        "dropoutjeep_lib.proxy.playwright_transport._PLAYWRIGHT_AVAILABLE", True
    )

    pooled_ctx, fake_page, _ = _make_mock_pooled_context()
    fake_page.content = AsyncMock(return_value="<html>ok</html>")

    adapter = PlaywrightClientAdapter()
    mock_pool = _inject_mock_pool(adapter, pooled_ctx)

    asyncio.run(adapter.request("GET", "https://a.example.com/"))
    asyncio.run(adapter.request("GET", "https://b.example.com/"))
    asyncio.run(adapter.request("GET", "https://c.example.com/"))

    # Pool's get_context called 3 times, but same context returned each time.
    assert mock_pool.get_context.await_count == 3
    # Chromium launch only happens once during pool creation (mocked here).
    assert fake_page.goto.await_count == 3


def test_adapter_forwards_headers_to_playwright(monkeypatch):
    monkeypatch.setattr(
        "dropoutjeep_lib.proxy.playwright_transport._PLAYWRIGHT_AVAILABLE", True
    )

    pooled_ctx, fake_page, fake_context = _make_mock_pooled_context()
    fake_page.content = AsyncMock(return_value="<html></html>")

    adapter = PlaywrightClientAdapter()
    _inject_mock_pool(adapter, pooled_ctx)

    asyncio.run(
        adapter.request(
            "GET",
            "https://example.com/",
            headers={"X-Custom": "1", "Connection": "keep-alive"},
        )
    )

    assert fake_context.set_extra_http_headers.awaited
    headers = fake_context.set_extra_http_headers.await_args.args[0]
    assert headers.get("X-Custom") == "1"
    assert "Connection" not in headers


def test_adapter_falls_back_on_playwright_error(monkeypatch):
    monkeypatch.setattr(
        "dropoutjeep_lib.proxy.playwright_transport._PLAYWRIGHT_AVAILABLE", True
    )

    pooled_ctx, fake_page, _ = _make_mock_pooled_context()
    fake_page.goto = AsyncMock(side_effect=Exception("navigation timeout"))

    adapter = PlaywrightClientAdapter()
    _inject_mock_pool(adapter, pooled_ctx)

    fallback_response = MagicMock()
    fallback_response.status_code = 200
    fallback_response.content = b"httpx-fallback"
    adapter._fallback = MagicMock()
    adapter._fallback.request = AsyncMock(return_value=fallback_response)

    resp = asyncio.run(adapter.request("GET", "https://example.com/"))
    assert resp.status_code == 200
    assert resp.content == b"httpx-fallback"
    adapter._fallback.request.assert_awaited_once()


def test_plugin_playwright_hook_runs(monkeypatch):
    from dropoutjeep_lib.proxy.plugin_system import (
        ProxyPlugin,
        apply_plugin_playwright_hooks,
    )

    class TestPlugin(ProxyPlugin):
        name = "test"

        def on_playwright_page(self, page, ctx):
            return page.evaluate("() => { window.hooked = true; }")

    fake_page = MagicMock()
    fake_page.evaluate = AsyncMock()

    plugin = TestPlugin()
    asyncio.run(apply_plugin_playwright_hooks(fake_page, {"campaign_id": 1}, [plugin]))
    fake_page.evaluate.assert_awaited_once_with("() => { window.hooked = true; }")


# ---------------------------------------------------------------------------
# BrowserContextPool unit tests
# ---------------------------------------------------------------------------

def test_pool_is_healthy_returns_true_for_connected_browser():
    fake_browser = MagicMock()
    fake_browser.is_connected = MagicMock(return_value=True)
    fake_context = MagicMock()
    fake_page = MagicMock()
    fake_page.close = AsyncMock()
    fake_context.new_page = AsyncMock(return_value=fake_page)

    pooled = _PooledContext(fake_browser, fake_context)
    assert asyncio.run(pooled.is_healthy()) is True
    fake_page.close.assert_awaited_once()


def test_pool_is_healthy_returns_false_for_disconnected_browser():
    fake_browser = MagicMock()
    fake_browser.is_connected = MagicMock(return_value=False)

    pooled = _PooledContext(fake_browser, MagicMock())
    assert asyncio.run(pooled.is_healthy()) is False


def test_pool_recycles_aged_contexts(monkeypatch):
    """Context exceeding max_context_age_sec is replaced."""
    monkeypatch.setattr(
        "dropoutjeep_lib.proxy.playwright_transport._PLAYWRIGHT_AVAILABLE", True
    )

    fake_page = MagicMock()
    fake_page.goto = AsyncMock()
    fake_page.content = AsyncMock(return_value="<html></html>")
    fake_page.evaluate = AsyncMock(return_value=200)
    fake_page.locator.return_value.count = AsyncMock(return_value=0)
    fake_page.close = AsyncMock()

    fake_context = MagicMock()
    fake_context.new_page = AsyncMock(return_value=fake_page)
    fake_context.set_extra_http_headers = AsyncMock()
    fake_context.close = AsyncMock()

    fake_browser = MagicMock()
    fake_browser.is_connected = MagicMock(return_value=True)
    fake_browser.new_context = AsyncMock(return_value=fake_context)
    fake_browser.close = AsyncMock()

    fake_pw = MagicMock()
    fake_pw.chromium.launch = AsyncMock(return_value=fake_browser)

    async_cm = MagicMock()
    async_cm.__aenter__ = AsyncMock(return_value=fake_pw)
    async_cm.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(
        sys.modules["dropoutjeep_lib.proxy.playwright_transport"],
        "async_playwright",
        lambda: async_cm,
    )

    pool = BrowserContextPool(pool_size=1, max_context_age_sec=0.001)
    ctx1 = asyncio.run(pool.get_context())
    assert ctx1.request_count == 1

    import time as _time
    _time.sleep(0.01)  # ensure monotonic clock advances past max_context_age_sec

    ctx2 = asyncio.run(pool.get_context())
    assert ctx2.request_count == 1  # fresh context after recycle
    assert fake_browser.close.await_count >= 1  # old browser was closed

    asyncio.run(pool.close())
