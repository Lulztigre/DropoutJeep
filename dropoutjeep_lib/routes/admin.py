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
    CapturedCredential, CapturedCookie, SuppressedEmail
)
from dropoutjeep_lib.utils.suppression import (
    list_suppressions, suppress, remove_suppression,
    import_suppressions, export_suppressions
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
from dropoutjeep_lib.utils.credential_format import decrypt_credential_meta
from dropoutjeep_lib.utils.settings import get_setting_int

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') in ('on', '1', 'true', 'yes')
        user = User.query.filter_by(username=username).first()
        if user and user.is_active and user.check_password(password):
            session['user_id'] = user.id
            # Only make the session persistent (survives browser restarts)
            # when the user explicitly opts in.  Otherwise it is a browser-
            # session cookie and expires when the browser is closed.
            session.permanent = remember
            log_audit('login', f'user={username} role={user.role} remember={remember}')
            return redirect(url_for('admin_index'))
        log_audit('login_failed', f'user={username}')
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')


@admin_bp.route('/logout')
@login_required
def admin_logout():
    session.pop('user_id', None)
    return redirect(url_for('admin_login'))


@admin_bp.route('/')
@admin_bp.route('/page/<int:page>')
@viewer_required
def admin_index(page=1):
    per_page = 10
    if page < 1:
        page = 1

    total_campaigns = Campaign.query.count()
    total_pages = max(1, (total_campaigns + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages

    offset = (page - 1) * per_page
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()) \
        .limit(per_page).offset(offset).all()

    stats = []
    for c in campaigns:
        recipients = Recipient.query.filter_by(campaign_id=c.id).all()
        sent = sum(1 for r in recipients if r.sent_at)
        clicks = Event.query.filter_by(campaign_id=c.id, event_type='click').count()
        opens = Event.query.filter_by(campaign_id=c.id, event_type='open').count()
        creds = Event.query.filter_by(campaign_id=c.id, event_type='credential_attempt').count()
        mfa = Event.query.filter_by(campaign_id=c.id, event_type='mfa_attempt').count()
        flow_complete = Event.query.filter_by(campaign_id=c.id, event_type='flow_complete').count()
        calendar_downloads = Event.query.filter_by(campaign_id=c.id, event_type='calendar_download').count()
        training_started = Event.query.filter_by(campaign_id=c.id, event_type='training_started').count()
        training_completed = Event.query.filter_by(campaign_id=c.id, event_type='training_completed').count()
        risk = campaign_risk_summary(c.id)
        stats.append({'campaign': c, 'sent': sent, 'clicks': clicks,
                      'opens': opens, 'creds': creds, 'mfa': mfa,
                      'flow_complete': flow_complete,
                      'calendar_downloads': calendar_downloads,
                      'training_started': training_started,
                      'training_completed': training_completed,
                      'avg_risk': risk['avg_score'],
                      'high_risk_count': risk['high_risk_count']})
    overall_avg_risk = round(sum(s['avg_risk'] for s in stats) / len(stats), 1) if stats else 0
    return render_template('admin_index.html', stats=stats, overall_avg_risk=overall_avg_risk,
                           page=page, total_pages=total_pages, total_campaigns=total_campaigns)


@admin_bp.route('/events')
@viewer_required
def admin_events():
    events = Event.query.order_by(Event.created_at.desc()).limit(500).all()
    return render_template('events.html', events=events)


@admin_bp.route('/purge', methods=['GET', 'POST'])
@admin_required
def admin_purge():
    from sqlalchemy import func as sa_func
    campaigns = Campaign.query.order_by(Campaign.name).all()

    # Build summary of events by type for the UI.
    summary = db.session.query(
        Event.event_type, sa_func.count(Event.id)
    ).group_by(Event.event_type).order_by(sa_func.count(Event.id).desc()).all()
    total_events = Event.query.count()

    if request.method == 'POST':
        mode = request.form.get('mode', 'retention')
        campaign_id = request.form.get('campaign_id', '')
        event_type = request.form.get('event_type', '').strip()
        custom_days = request.form.get('custom_days', type=int)

        query = Event.query
        if campaign_id:
            query = query.filter_by(campaign_id=int(campaign_id))
        if event_type:
            query = query.filter_by(event_type=event_type)

        if mode == 'retention':
            default_retention = get_setting_int('retention_days', current_app.config['RETENTION_DAYS'])
            days = custom_days if custom_days is not None else default_retention
            cutoff = datetime.utcnow() - timedelta(days=days)
            query = query.filter(Event.created_at < cutoff)
            label = f"older than {days} days"
        elif mode == 'all':
            label = "all events"
        else:
            flash('Unknown purge mode', 'danger')
            return redirect(url_for('admin_purge'))

        deleted = query.delete(synchronize_session=False)
        db.session.commit()
        logging.info('PURGE mode=%s campaign_id=%s event_type=%s deleted=%s',
                     mode, campaign_id or '-', event_type or '-', deleted)
        flash(f'Purged {deleted} events ({label})', 'success')
        return redirect(url_for('admin_purge'))

    # Compute how many events the default retention would delete.
    retention_days = get_setting_int('retention_days', current_app.config['RETENTION_DAYS'])
    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    retention_count = Event.query.filter(Event.created_at < cutoff).count()

    return render_template(
        'purge.html',
        campaigns=campaigns,
        summary=summary,
        total_events=total_events,
        retention_days=retention_days,
        retention_count=retention_count,
    )


@admin_bp.route('/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    from dropoutjeep_lib.models import Setting
    keys = [
        'base_url', 'retention_days',
        'smtp_host', 'smtp_port', 'return_path', 'dialer_pool_size', 'use_enterprise_mailer',
        'imap_host', 'imap_port', 'imap_user', 'imap_pass',
        'virustotal_api_key', 'ipapi_api_key',
        'bulk_import_max_rows', 'enable_plugins_ui',
        'dkim_selector',
    ]
    if request.method == 'POST':
        for key in keys:
            value = request.form.get(key, '').strip()
            row = Setting.query.filter_by(key=key).first()
            if row:
                row.value = value
            else:
                db.session.add(Setting(key=key, value=value))
        db.session.commit()
        flash('Settings saved', 'success')
        return redirect(url_for('admin.admin_settings'))

    settings = {s.key: s.value for s in Setting.query.filter(Setting.key.in_(keys)).all()}
    return render_template('settings.html', settings=settings)


@admin_bp.route('/users')
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('users.html', users=users)


@admin_bp.route('/users/new', methods=['GET', 'POST'])
@admin_required
def admin_user_new():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'viewer')
        if not username or not password or role not in ('admin', 'operator', 'viewer'):
            flash('Invalid input', 'danger')
            return redirect(url_for('admin_user_new'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('admin_user_new'))
        user = User(username=username, role=role, is_active=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash(f'User {username} created', 'success')
        return redirect(url_for('admin_users'))
    return render_template('user_new.html')


@admin_bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@admin_required
def admin_user_toggle(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == g.current_user.id:
        flash('Cannot disable yourself', 'danger')
        return redirect(url_for('admin_users'))
    user.is_active = not user.is_active
    db.session.commit()
    flash(f'User {user.username} {"enabled" if user.is_active else "disabled"}', 'success')
    return redirect(url_for('admin_users'))


@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_user_delete(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == g.current_user.id:
        flash('Cannot delete yourself', 'danger')
        return redirect(url_for('admin_users'))
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} deleted', 'success')
    return redirect(url_for('admin_users'))


ALL_TOKEN_SCOPES = [
    ('campaigns:read', 'Read campaigns'),
    ('campaigns:write', 'Create/clone/update campaigns'),
    ('recipients:read', 'Read recipients'),
    ('recipients:write', 'Import recipients'),
    ('sending_profiles:read', 'Read sending profiles'),
    ('sending_profiles:write', 'Create/update sending profiles'),
    ('results:read', 'Read campaign results'),
    ('templates:read', 'Read templates'),
    ('templates:write', 'Create/import templates'),
]


@admin_bp.route('/api-tokens')
@admin_required
def admin_api_tokens():
    tokens = ApiToken.query.order_by(ApiToken.created_at.desc()).all()
    return render_template('api_tokens.html', tokens=tokens, scopes=ALL_TOKEN_SCOPES)


@admin_bp.route('/api-tokens/new', methods=['POST'])
@admin_required
def admin_api_token_new():
    name = request.form.get('name', '').strip()
    if not name:
        flash('Token name is required', 'danger')
        return redirect(url_for('admin_api_tokens'))
    expires_days = request.form.get('expires_days', type=int)
    selected = request.form.getlist('scopes')
    import secrets, hashlib
    from datetime import datetime, timedelta
    plain = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(plain.encode()).hexdigest()
    expires_at = None
    if expires_days:
        expires_at = datetime.utcnow() + timedelta(days=expires_days)
    t = ApiToken(name=name, token_hash=token_hash, created_by_user_id=g.current_user.id,
                 expires_at=expires_at, is_active=True)
    t.set_scopes(selected)
    db.session.add(t)
    db.session.commit()
    flash(f'API token created. Copy it now: {plain}', 'success')
    return redirect(url_for('admin_api_tokens'))


@admin_bp.route('/api-tokens/<int:token_id>/revoke', methods=['POST'])
@admin_required
def admin_api_token_revoke(token_id):
    t = ApiToken.query.get_or_404(token_id)
    t.is_active = False
    db.session.commit()
    flash(f'Token "{t.name}" revoked', 'success')
    return redirect(url_for('admin_api_tokens'))


@admin_bp.route('/api-tokens/<int:token_id>/delete', methods=['POST'])
@admin_required
def admin_api_token_delete(token_id):
    t = ApiToken.query.get_or_404(token_id)
    db.session.delete(t)
    db.session.commit()
    flash(f'Token "{t.name}" deleted', 'success')
    return redirect(url_for('admin_api_tokens'))


LOG_TYPE_MAP = {
    'campaign': ['sent', 'open', 'click', 'visit'],
    'replies': ['auto_reply'],
    'errors': ['bounce', 'send_failed', 'credential_attempt'],
}


@admin_bp.route('/logs')
@viewer_required
def admin_logs():
    return render_template('logs.html')


@admin_bp.route('/logs/<log_type>')
@viewer_required
def admin_logs_json(log_type):
    types = LOG_TYPE_MAP.get(log_type, ['sent'])
    events = Event.query.filter(Event.event_type.in_(types)) \
        .order_by(Event.created_at.desc()).limit(500).all()

    def _meta_for_display(e):
        if e.event_type == 'credential_attempt':
            return decrypt_credential_meta(e.meta)
        return e.meta

    return jsonify([{
        'id': e.id,
        'time': e.created_at.isoformat() if e.created_at else None,
        'type': e.event_type,
        'campaign_id': e.campaign_id,
        'recipient_id': e.recipient_id,
        'message': f'{e.event_type} campaign={e.campaign_id} recipient={e.recipient_id}',
        'meta': _meta_for_display(e),
    } for e in events])


@admin_bp.route('/logs/export/<log_type>')
@viewer_required
def admin_logs_export(log_type):
    import csv
    import io
    types = LOG_TYPE_MAP.get(log_type, ['sent'])
    events = Event.query.filter(Event.event_type.in_(types)) \
        .order_by(Event.created_at.desc()).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['time', 'type', 'campaign_id', 'recipient_id', 'meta'])
    for e in events:
        meta = decrypt_credential_meta(e.meta) if e.event_type == 'credential_attempt' else (e.meta or '')
        writer.writerow([
            e.created_at.isoformat() if e.created_at else '',
            e.event_type,
            e.campaign_id or '',
            e.recipient_id or '',
            meta
        ])
    buf.seek(0)
    filename = f'{log_type}_logs.csv'
    return send_file(
        io.BytesIO(buf.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )


@admin_bp.route('/logs/clear/<log_type>', methods=['POST'])
@admin_required
def admin_logs_clear(log_type):
    types = LOG_TYPE_MAP.get(log_type, [])
    if types:
        Event.query.filter(Event.event_type.in_(types)).delete(synchronize_session=False)
        db.session.commit()
        flash(f'{log_type.capitalize()} logs cleared', 'success')
    return redirect(url_for('admin_logs'))


@admin_bp.route('/suppressions')
@admin_required
def admin_suppressions():
    page = request.args.get('page', 1, type=int)
    per_page = 100
    query = SuppressedEmail.query.order_by(SuppressedEmail.created_at.desc())
    total = query.count()
    rows = query.offset((page - 1) * per_page).limit(per_page).all()
    return render_template('suppressions.html', rows=rows, page=page,
                           per_page=per_page, total=total)


@admin_bp.route('/suppressions/add', methods=['POST'])
@admin_required
def admin_suppressions_add():
    value = request.form.get('email', '').strip().lower()
    if not value or ('@' not in value and '.' not in value):
        flash('Enter a valid email or domain', 'danger')
        return redirect(url_for('admin_suppressions'))
    suppress(value, source='manual')
    flash(f'Added {value} to suppression list', 'success')
    return redirect(url_for('admin_suppressions'))


@admin_bp.route('/suppressions/<int:suppression_id>/delete', methods=['POST'])
@admin_required
def admin_suppressions_delete(suppression_id):
    row = SuppressedEmail.query.get_or_404(suppression_id)
    db.session.delete(row)
    db.session.commit()
    flash(f'Removed {row.email} from suppression list', 'success')
    return redirect(url_for('admin_suppressions'))


@admin_bp.route('/suppressions/import', methods=['POST'])
@admin_required
def admin_suppressions_import():
    uploaded = request.files.get('file')
    if not uploaded or not uploaded.filename:
        flash('Upload a CSV or plain text file', 'danger')
        return redirect(url_for('admin_suppressions'))
    try:
        text = uploaded.read().decode('utf-8-sig')
        result = import_suppressions(text.splitlines(), source='import')
        flash(
            f"Imported {result['added']} entries; {result['duplicates']} duplicates; "
            f"{len(result['errors'])} errors",
            'success' if result['added'] else 'info',
        )
    except Exception as exc:
        flash(f'Import failed: {exc}', 'danger')
    return redirect(url_for('admin_suppressions'))


@admin_bp.route('/suppressions/export')
@admin_required
def admin_suppressions_export():
    csv_data = export_suppressions()
    response = make_response(csv_data)
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=suppressions.csv'
    return response


# ---------------------------------------------------------------------------
# Exfiltration data viewer
# ---------------------------------------------------------------------------
@admin_bp.route('/exfil')
@viewer_required
def admin_exfil():
    """Display all HTTP and DNS exfiltration events across campaigns."""
    page = request.args.get('page', 1, type=int)
    per_page = 50
    event_type = request.args.get('type', '')

    query = Event.query.filter(
        Event.event_type.in_(['exfil_http', 'exfil_dns'])
    )
    if event_type in ('exfil_http', 'exfil_dns'):
        query = query.filter(Event.event_type == event_type)

    total = query.count()
    events = query.order_by(Event.created_at.desc()) \
        .offset((page - 1) * per_page) \
        .limit(per_page).all()

    results = []
    for ev in events:
        meta = {}
        try:
            meta = json.loads(ev.meta) if ev.meta else {}
        except Exception:
            meta = {'raw': ev.meta}
        recipient = Recipient.query.get(ev.recipient_id) if ev.recipient_id else None
        campaign = Campaign.query.get(ev.campaign_id) if ev.campaign_id else None
        results.append({
            'event': ev,
            'meta': meta,
            'recipient': recipient,
            'campaign': campaign,
        })

    return render_template(
        'exfil_viewer.html',
        results=results,
        total=total,
        page=page,
        per_page=per_page,
        event_type=event_type,
    )


# ---------------------------------------------------------------------------
# Python plugin manager
# ---------------------------------------------------------------------------
def _plugins_ui_enabled():
    """Return True when the plugins UI is explicitly enabled."""
    from dropoutjeep_lib.utils.settings import get_setting_bool
    return get_setting_bool('enable_plugins_ui', current_app.config.get('ENABLE_PLUGINS_UI', False))


@admin_bp.route('/plugins')
@admin_required
def admin_plugins():
    """List loaded Python proxy plugins and allow reload."""
    if not _plugins_ui_enabled():
        abort(404)
    from dropoutjeep_lib.proxy.plugin_system import (
        load_python_plugins, reload_python_plugins, DEFAULT_PLUGINS_DIR
    )
    plugins_dir = DEFAULT_PLUGINS_DIR
    plugins = load_python_plugins(plugins_dir)
    plugin_info = []
    for p in plugins:
        plugin_info.append({
            'name': p.name,
            'class': p.__class__.__name__,
            'module': p.__class__.__module__,
            'has_on_request': p.__class__.on_request is not type(p).on_request,
            'has_on_response': p.__class__.on_response is not type(p).on_response,
            'has_on_exchange': p.__class__.on_exchange is not type(p).on_exchange,
            'has_on_playwright': p.__class__.on_playwright_page is not type(p).on_playwright_page,
        })

    # Also list .py files on disk
    disk_files = []
    if plugins_dir.exists():
        for f in sorted(plugins_dir.glob('*.py')):
            disk_files.append({
                'name': f.name,
                'size': f.stat().st_size,
                'modified': datetime.fromtimestamp(f.stat().st_mtime),
            })

    return render_template(
        'plugins.html',
        plugins=plugin_info,
        disk_files=disk_files,
        plugins_dir=str(plugins_dir),
    )


@admin_bp.route('/plugins/reload', methods=['POST'])
@admin_required
def admin_plugins_reload():
    """Clear the plugin cache and reload from disk."""
    if not _plugins_ui_enabled():
        abort(404)
    from dropoutjeep_lib.proxy.plugin_system import reload_python_plugins
    plugins = reload_python_plugins()
    log_audit('plugins_reload', details={'count': len(plugins)})
    flash(f'Reloaded {len(plugins)} Python plugin(s).', 'success')
    return redirect(url_for('admin_plugins'))


# ---------------------------------------------------------------------------
# Domain routing config
# ---------------------------------------------------------------------------
@admin_bp.route('/domain-routing')
@viewer_required
def admin_domain_routing():
    """Preview per-recipient proxy URLs for all campaigns with wildcard domains."""
    from dropoutjeep_lib.utils.domain_routing import get_campaign_wildcard_domain
    from flask import current_app

    from dropoutjeep_lib.utils.settings import get_base_url
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()
    base_url = get_base_url()

    routing_data = []
    for c in campaigns:
        pd = get_campaign_wildcard_domain(c.id)
        sample_recipients = Recipient.query.filter_by(campaign_id=c.id).limit(3).all()
        urls = []
        for r in sample_recipients:
            if pd and pd.base_domain:
                url = f"https://{r.token}.{pd.base_domain}/"
            else:
                url = f"{base_url}/proxy/{c.id}/t/{r.token}/"
            urls.append({'token': r.token, 'email': r.email, 'url': url})
        routing_data.append({
            'campaign': c,
            'wildcard_domain': pd,
            'sample_urls': urls,
            'recipient_count': Recipient.query.filter_by(campaign_id=c.id).count(),
        })

    return render_template(
        'domain_routing.html',
        routing_data=routing_data,
        base_url=base_url,
    )


# ---------------------------------------------------------------------------
# Domain Health Dashboard
# ---------------------------------------------------------------------------
@admin_bp.route('/domain-health')
@viewer_required
def admin_domain_health():
    """Unified view of all sending domain health: SPF, DKIM, DMARC, reputation, warmup."""
    from dropoutjeep_lib.utils.dkim_utils import check_spf, check_dkim_selector, check_dmarc
    from dropoutjeep_lib.utils.domain_reputation import get_or_refresh_domain_reputation

    subsidiaries = Subsidiary.query.all()
    domain_data = []

    for sub in subsidiaries:
        domain = sub.sending_domain
        if not domain:
            continue

        # Check SPF
        spf_ok, spf_txt = check_spf(domain)

        # Check DKIM
        dkim_ok, dkim_txt = False, 'No selector configured'
        if sub.dkim_selector:
            dkim_ok, dkim_txt = check_dkim_selector(domain, sub.dkim_selector)

        # Check DMARC
        dmarc_ok, dmarc_txt = check_dmarc(domain)

        # Get reputation data
        reputation = DomainReputation.query.filter_by(domain=domain).first()
        rep_score = reputation.overall_score if reputation else None
        warmup_level = reputation.warmup_level if reputation else (sub.warmup_level or 0)
        virus_total = reputation.virus_total_score if reputation else None
        blacklist_flags = reputation.get_blacklist_flags() if reputation else []

        # Count campaigns using this domain
        campaign_count = Campaign.query.join(SendingProfile) \
            .filter(SendingProfile.subsidiary_id == sub.id).count()

        domain_data.append({
            'subsidiary': sub,
            'domain': domain,
            'spf_ok': spf_ok,
            'spf_txt': spf_txt,
            'dkim_ok': dkim_ok,
            'dkim_txt': dkim_txt,
            'dmarc_ok': dmarc_ok,
            'dmarc_txt': dmarc_txt,
            'rep_score': rep_score,
            'warmup_level': warmup_level,
            'virus_total': virus_total,
            'blacklist_flags': blacklist_flags,
            'campaign_count': campaign_count,
            'all_healthy': spf_ok and dkim_ok and dmarc_ok,
        })

    return render_template('domain_health.html', domain_data=domain_data)
