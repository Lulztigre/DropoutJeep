"""Tests for the TLS fingerprint transport abstraction."""

import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch

from dropoutjeep_lib.proxy.tls_transport import (
    build_async_client,
    HttpxClientAdapter,
    CurlCffiClientAdapter,
)


def test_blank_fingerprint_uses_httpx():
    client = build_async_client(None, None)
    assert isinstance(client, HttpxClientAdapter)


def test_unsupported_fingerprint_still_uses_httpx(monkeypatch):
    """A fingerprint string with no curl_cffi available must not crash."""
    monkeypatch.setattr(
        "dropoutjeep_lib.proxy.tls_transport._CURL_CFFI_AVAILABLE", False
    )
    client = build_async_client("chrome120", None)
    assert isinstance(client, HttpxClientAdapter)


def test_fingerprint_uses_curl_cffi_when_available():
    client = build_async_client("chrome120", None)
    assert isinstance(client, CurlCffiClientAdapter)


def test_curl_adapter_maps_content_and_follow_redirects():
    """curl_cffi uses ``data`` and ``allow_redirects`` instead of httpx kwargs."""
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.content = b"ok"
    fake_response.headers = {}

    mock_session = MagicMock()
    mock_session.request = AsyncMock(return_value=fake_response)

    with patch.object(
        sys.modules["dropoutjeep_lib.proxy.tls_transport"],
        "CurlAsyncSession",
        return_value=mock_session,
    ):
        adapter = CurlCffiClientAdapter(impersonate="chrome120")
        resp = asyncio.run(adapter.request(
            "POST",
            "https://example.com/login",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            content=b"user=alice&pass=secret",
            follow_redirects=False,
            timeout=15,
        ))

    assert resp.status_code == 200
    mock_session.request.assert_awaited_once()
    call_kwargs = mock_session.request.call_args.kwargs
    assert call_kwargs["data"] == b"user=alice&pass=secret"
    assert call_kwargs["allow_redirects"] is False
    assert call_kwargs["impersonate"] == "chrome120"
    assert call_kwargs["timeout"] == 15


def test_httpx_adapter_forwards_kwargs():
    """The httpx adapter should forward ``content`` and ``follow_redirects``."""
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.content = b"ok"
    fake_response.headers = {}

    mock_client = MagicMock()
    mock_client.request = AsyncMock(return_value=fake_response)

    adapter = HttpxClientAdapter()
    adapter._client = mock_client

    resp = asyncio.run(adapter.request(
        "POST",
        "https://example.com/login",
        content=b"data",
        follow_redirects=False,
    ))

    assert resp.status_code == 200
    call_kwargs = mock_client.request.call_args.kwargs
    assert call_kwargs["content"] == b"data"
    assert call_kwargs["follow_redirects"] is False
