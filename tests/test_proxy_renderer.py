"""Integration tests for proxy renderer wiring (Playwright BitM vs httpx)."""

import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import Campaign
from dropoutjeep_lib.proxy.engine import close_all_proxy_workers
from dropoutjeep_lib.proxy.playwright_transport import PlaywrightClientAdapter, _FakeResponse
from dropoutjeep_lib.proxy.plugin_system import ProxyPlugin


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()
        close_all_proxy_workers()


def _make_proxy_campaign(renderer=None):
    flow_config = {"target_url": "https://example.com"}
    if renderer:
        flow_config["renderer"] = renderer
    campaign = Campaign(
        name="Proxy Campaign",
        subject="s",
        body_html="b",
        landing_html="l",
        flow_type="reverse_proxy",
        flow_config=json.dumps(flow_config),
    )
    db.session.add(campaign)
    db.session.commit()
    return campaign


def _fake_html_response(url):
    fake = MagicMock()
    fake.status_code = 200
    fake.headers = {"content-type": "text/html; charset=utf-8"}
    fake.content = f"<html>rendered for {url}</html>".encode()
    fake.text = fake.content.decode()
    return fake


def test_proxy_uses_playwright_renderer(client):
    """A campaign with renderer='playwright' reaches the Playwright adapter."""
    campaign = _make_proxy_campaign(renderer="playwright")
    mock_adapter = MagicMock()
    mock_adapter.request = AsyncMock(return_value=_fake_html_response("https://example.com/page"))

    with patch("dropoutjeep_lib.proxy.engine.build_playwright_client", return_value=mock_adapter):
        resp = client.get(f"/proxy/{campaign.id}/page")

    assert resp.status_code == 200
    assert b"rendered for https://example.com/page" in resp.data
    mock_adapter.request.assert_awaited_once()
    call_kwargs = mock_adapter.request.await_args.kwargs
    assert call_kwargs["url"] == "https://example.com/page"


def test_proxy_uses_httpx_without_renderer(client):
    """A campaign without renderer uses the normal async httpx path."""
    campaign = _make_proxy_campaign()
    mock_adapter = MagicMock()
    mock_adapter.request = AsyncMock(return_value=_fake_html_response("https://example.com/page"))

    with patch("dropoutjeep_lib.proxy.engine.build_async_client", return_value=mock_adapter):
        resp = client.get(f"/proxy/{campaign.id}/page")

    assert resp.status_code == 200
    assert b"rendered for https://example.com/page" in resp.data
    mock_adapter.request.assert_awaited_once()
    call_kwargs = mock_adapter.request.await_args.kwargs
    assert call_kwargs["url"] == "https://example.com/page"


def test_proxy_uses_httpx_with_renderer_httpx(client):
    """An explicit renderer='httpx' still uses the httpx adapter."""
    campaign = _make_proxy_campaign(renderer="httpx")
    mock_adapter = MagicMock()
    mock_adapter.request = AsyncMock(return_value=_fake_html_response("https://example.com/page"))

    with patch("dropoutjeep_lib.proxy.engine.build_async_client", return_value=mock_adapter):
        resp = client.get(f"/proxy/{campaign.id}/page")

    assert resp.status_code == 200
    mock_adapter.request.assert_awaited_once()
    assert mock_adapter.request.await_args.kwargs["url"] == "https://example.com/page"


def test_proxy_playwright_adapter_receives_context_and_plugins(client):
    """Playwright renderer passes campaign context and loaded plugins to the adapter."""

    class TestPlugin(ProxyPlugin):
        name = "test-playwright"

    campaign = _make_proxy_campaign(renderer="playwright")

    class RecordingAdapter(PlaywrightClientAdapter):
        """Capture the arguments PlaywrightClientAdapter.request receives."""

        def __init__(self):
            # Intentionally skip super().__init__ so no real fallback client is created.
            self.calls = []
            self.proxy_url = None
            self.verify = False
            self.timeout = 30

        async def request(self, method, url, *, ctx=None, plugins=None, **kwargs):
            self.calls.append({"method": method, "url": url, "ctx": ctx, "plugins": plugins})
            return _FakeResponse(200, {"content-type": "text/html"}, b"<html></html>")

        async def close(self):
            pass

    adapter = RecordingAdapter()
    test_plugin = TestPlugin()

    with patch("dropoutjeep_lib.proxy.engine.build_playwright_client", return_value=adapter):
        with patch("dropoutjeep_lib.proxy.manager._load_python_plugins", return_value=[test_plugin]):
            resp = client.get(f"/proxy/{campaign.id}/page")

    assert resp.status_code == 200
    assert len(adapter.calls) == 1
    call = adapter.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == "https://example.com/page"
    assert call["ctx"]["campaign_id"] == campaign.id
    assert test_plugin in call["plugins"]


