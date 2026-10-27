import os
import uuid
import json
import logging
import pathlib
import base64
from io import BytesIO
from datetime import datetime, timedelta
from urllib.parse import urlparse

from flask import (
    Flask, request, redirect, url_for, render_template, session,
    send_file, jsonify, abort, flash, g, make_response
)
from flask_wtf.csrf import CSRFProtect
from flask_sock import Sock

# ---------------------------------------------------------------------------
# Flask setup
# ---------------------------------------------------------------------------
app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('FLASK_SECRET', uuid.uuid4().hex)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///phish.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True
# Session cookie: HTTPS only, not readable from JavaScript, and not sent on
# cross-site requests. Set SESSION_COOKIE_SECURE=0 only for local HTTP testing.
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', '1') == '1'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SOCK_SERVER_OPTIONS'] = {'ping_interval': 25}
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(
    hours=int(os.environ.get('SESSION_LIFETIME_HOURS', '8'))
)
app.url_map.strict_slashes = False

# WAL + busy timeout on every SQLite connection, so the app and the standalone
# proxy can write to the same file without losing events.
from dropoutjeep_lib.utils.db_pragmas import install_sqlite_pragmas
install_sqlite_pragmas()

sock = Sock(app)

BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000')
app.config['BASE_URL'] = BASE_URL
RETENTION_DAYS = int(os.environ.get('RETENTION_DAYS', '90'))
app.config['ENABLE_PLUGINS_UI'] = os.environ.get('ENABLE_PLUGINS_UI', '').lower() in ('1', 'true', 'yes')

csrf = CSRFProtect(app)

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


def _default_rate_limits():
    """Return rate limits based on request path and method."""
    if app.config.get('TESTING'):
        return ''
    method = request.method.upper()
    path = request.path or ''
    if method == 'GET':
        return ''
    if path == '/admin/login' or path.rstrip('/') == '/admin/login':
        return os.environ.get('LOGIN_RATE_LIMIT', '5 per minute')
    if path.startswith('/api/'):
        return '30 per minute'
    if path.startswith('/admin/'):
        return '60 per minute'
    return ''


limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[_default_rate_limits],
    storage_uri='memory://',
    strategy='fixed-window',
)


@app.context_processor
def inject_current_user():
    """Make the logged-in user available in all templates as ``current_user``."""
    user = getattr(g, 'current_user', None)
    if user is None:
        from dropoutjeep_lib.utils.auth import get_current_user
        user = get_current_user()
    return {'current_user': user}


@app.context_processor
def inject_settings_flags():
    """Expose runtime setting flags to all templates."""
    from dropoutjeep_lib.utils.settings import get_setting_bool
    return {
        'enable_plugins_ui': get_setting_bool(
            'enable_plugins_ui',
            app.config.get('ENABLE_PLUGINS_UI', False),
        ),
    }


@app.template_filter('decrypt_credential_meta')
def _decrypt_credential_meta_filter(value):
    """Decrypt enc:: values inside credential_attempt event metadata for display."""
    from dropoutjeep_lib.utils.credential_format import decrypt_credential_meta
    return decrypt_credential_meta(value)


# ---------------------------------------------------------------------------
# Trusted upstream proxy / CDN support
# ---------------------------------------------------------------------------
# Enable ProxyFix when DropoutJeep sits behind Cloudflare, a load balancer, or
# another reverse proxy. Without this, request.remote_addr shows the proxy IP
# instead of the victim's IP, and HTTPS detection breaks.
# USE_PROXYFIX=1 to enable; TRUSTED_PROXIES=1.2.3.4,5.6.7.8 to restrict.
if os.environ.get('USE_PROXYFIX', '').lower() in ('1', 'true', 'yes'):
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=int(os.environ.get('PROXYFIX_X_FOR', '1')),
        x_proto=int(os.environ.get('PROXYFIX_X_PROTO', '1')),
        x_host=int(os.environ.get('PROXYFIX_X_HOST', '0')),
        x_port=int(os.environ.get('PROXYFIX_X_PORT', '0')),
        x_prefix=int(os.environ.get('PROXYFIX_X_PREFIX', '0')),
    )
    if os.environ.get('TRUSTED_PROXIES'):
        print('[config] ProxyFix enabled; TRUSTED_PROXIES is set but must be enforced by your upstream proxy/CDN')
    else:
        print('[config] ProxyFix enabled for upstream CDN/proxy support')

# ---------------------------------------------------------------------------
# Shared db + models
# ---------------------------------------------------------------------------
from dropoutjeep_lib import db, init_app
from dropoutjeep_lib.models import (
    Subsidiary, SendingProfile, Campaign, Recipient, Event, Target,
    CampaignJob, RateProfile, AutoReplyRule, PendingReply, User, AuditLog,
    TrainingCompletion, ApiToken, EmailTemplate, CampaignVersion, CanaryToken,
    Webhook, ProxyDomain, DomainReputation, SenderRotationPool,
    SenderRotationEntry, RecipientFingerprint, Redirector
)
from dropoutjeep_lib.utils.auth import (
    operator_required, viewer_required, get_current_user
)
from dropoutjeep_lib.utils.dialer import Dialer
from dropoutjeep_lib.utils.dkim_utils import check_dmarc
from dropoutjeep_lib.utils.validator import (
    validate_smtp_relay, check_spf, check_dkim_selector, check_spoof_alignment
)
from dropoutjeep_lib.utils.risk import recipient_risk_score
from dropoutjeep_lib.utils.scheduler import init_scheduler
from dropoutjeep_lib.utils.template_marketplace import seed_builtin_templates
from dropoutjeep_lib.utils.live import start_broadcaster
from dropoutjeep_lib.utils.suppression import is_suppressed

init_app(app)


from dropoutjeep_lib.migrations import (
    _ensure_campaign_schedule_columns, _run_inline_upgrades
)

_ensure_campaign_schedule_columns(app)
_run_inline_upgrades(app)
# ---------------------------------------------------------------------------
# Seed default provider rate profiles
# ---------------------------------------------------------------------------
DEFAULT_RATE_PROFILES = [
    {'name': 'Gmail', 'host_pattern': r'gmail\.com', 'hourly_limit': 500,
     'daily_limit': 2000, 'monthly_limit': 60000, 'delay_ms_min': 200,
     'delay_ms_max': 500, 'burst_size': 3},
    {'name': 'Outlook', 'host_pattern': r'outlook\.com', 'hourly_limit': 800,
     'daily_limit': 8000, 'monthly_limit': 240000, 'delay_ms_min': 150,
     'delay_ms_max': 400, 'burst_size': 4},
    {'name': 'Office 365', 'host_pattern': r'office365\.com',
     'hourly_limit': 1000, 'daily_limit': 10000, 'monthly_limit': 300000,
     'delay_ms_min': 100, 'delay_ms_max': 300, 'burst_size': 5},
    {'name': 'Custom', 'host_pattern': r'.*', 'hourly_limit': 2000,
     'daily_limit': 50000, 'monthly_limit': 1500000, 'delay_ms_min': 50,
     'delay_ms_max': 200, 'burst_size': 10, 'is_default': True},
]


def _seed_rate_profiles():
    with app.app_context():
        if RateProfile.query.first():
            return
        for spec in DEFAULT_RATE_PROFILES:
            db.session.add(RateProfile(**spec))
        db.session.commit()
        print('[seed] created default rate profiles')


def _seed_admin_user():
    with app.app_context():
        if User.query.first():
            return
        username = os.environ.get('ADMIN_USERNAME')
        password = os.environ.get('ADMIN_PASSWORD')
        if not username or not password:
            print('[seed] ADMIN_USERNAME and ADMIN_PASSWORD not set; no default admin user created')
            return
        if User.query.filter_by(username=username).first():
            return
        user = User(username=username, role='admin', is_active=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        print(f'[seed] created admin user {username}')


# Seed default data once at import time so it also works under WSGI.
_seed_rate_profiles()
_seed_admin_user()
with app.app_context():
    seed_builtin_templates()


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
# Rotating handler: an engagement runs for weeks and the audit log is written on
# every authenticated request. Without a cap it fills the volume mid-campaign.
from logging.handlers import RotatingFileHandler

_log_path = os.environ.get('AUDIT_LOG', 'audit.log')
try:
    _audit_handler = RotatingFileHandler(
        _log_path,
        maxBytes=int(os.environ.get('AUDIT_LOG_MAX_BYTES', str(20 * 1024 * 1024))),
        backupCount=int(os.environ.get('AUDIT_LOG_BACKUPS', '3')),
        encoding='utf-8',
    )
    _audit_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
    logging.basicConfig(level=logging.INFO, handlers=[_audit_handler])
except OSError:
    # Read-only or missing path: fall back to console so the app still boots.
    logging.basicConfig(level=logging.INFO)
    logging.getLogger(__name__).warning('audit log %s not writable, logging to stderr', _log_path)

# ---------------------------------------------------------------------------
# Template handling
# ---------------------------------------------------------------------------
TEMPLATES_DIR = pathlib.Path('templates')
TEMPLATES_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(resp):
    # Proxied responses manage their own headers via the proxy rule engine.
    # Adding default security headers here would break MITM content manipulation.
    if request.path.startswith('/proxy/'):
        return resp
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline' "
        "https://cdn.tailwindcss.com https://cdn.jsdelivr.net "
        "https://cdn.tiny.cloud https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net "
        "https://cdnjs.cloudflare.com; "
        "frame-src 'self' https:; "
        "frame-ancestors 'none';"
    )
    resp.headers['X-Frame-Options'] = 'DENY'
    # Recipient-facing pages must not leak the campaign URL to the real site when
    # someone clicks through. Everything else, /spoof-check included, needs
    # same-origin: Flask-WTF's SSL-strict CSRF check rejects an HTTPS POST that
    # arrives without a Referer, and the app screens are not all under /admin.
    _public_prefixes = (
        '/l/', '/landing/', '/pixel/', '/track/', '/drop/', '/unsubscribe/',
        '/canary/', '/loot/', '/proxy/', '/payload/', '/saml/', '/oauth/',
        '/ws/', '/calendar/', '/dns-exfil',
    )
    if request.path.startswith(_public_prefixes):
        resp.headers['Referrer-Policy'] = 'no-referrer'
    else:
        resp.headers['Referrer-Policy'] = 'same-origin'
    resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.after_request
def _audit_request(resp):
    user = get_current_user()
    if user and not request.path.startswith('/static') and not request.path.startswith('/proxy/'):
        try:
            entry = AuditLog(
                user_id=user.id,
                action='request',
                method=request.method,
                path=request.path,
                status_code=resp.status_code,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')[:512],
                details=None,
            )
            db.session.add(entry)
            db.session.commit()
        except Exception:
            db.session.rollback()
    return resp


# ---------------------------------------------------------------------------
# Public / dashboard routes
# ---------------------------------------------------------------------------
@app.route('/')
@viewer_required
def index():
    campaigns_count = Campaign.query.count()
    recipients_count = Recipient.query.count()
    recent_events = Event.query.filter(
        Event.created_at >= datetime.utcnow() - timedelta(hours=24)
    ).count()
    # Fetch active sending profiles for the launch console
    sending_profiles = SendingProfile.query.filter_by(is_active=True).all()
    return render_template('index.html',
                           campaigns_count=campaigns_count,
                           recipients_count=recipients_count,
                           recent_events=recent_events,
                           sending_profiles=sending_profiles)


@app.route('/api/preflight/check', methods=['POST'])
@limiter.limit("30 per minute")
@operator_required
def api_preflight_check():
    data = request.get_json() or {}
    sp_id = data.get('sending_profile_id')
    if not sp_id:
        return jsonify({'error': 'Missing sending_profile_id'}), 400

    sp = SendingProfile.query.get(sp_id)
    if not sp:
        return jsonify({'error': 'Sending profile not found'}), 404

    sub = sp.subsidiary
    domain = sub.sending_domain if sub else None
    selector = sub.dkim_selector if sub else None

    # Run Checks
    spf_ok, spf_txt = check_spf(domain) if domain else (False, 'No domain configured')
    dkim_ok, dkim_txt = check_dkim_selector(domain, selector) if domain and selector else (False, 'No domain/selector configured')

    # Run SMTP check
    smtp_ok, smtp_txt = validate_smtp_relay(
        sp.smtp_host or '',
        sp.smtp_port or 587,
        sp.smtp_user,
        sp.get_smtp_pass()
    )

    # Run Blacklist check
    from dropoutjeep_lib.routes.urlcheck import check_blacklists
    blacklist_results = check_blacklists(domain) if domain else ['Clean']
    blacklist_ok = 'Clean' in blacklist_results or not blacklist_results
    blacklist_txt = ', '.join(blacklist_results) if not blacklist_ok else 'Clean'

    return jsonify({
        'smtp': {'ok': smtp_ok, 'txt': smtp_txt},
        'spf': {'ok': spf_ok, 'txt': spf_txt},
        'dkim': {'ok': dkim_ok, 'txt': dkim_txt},
        'blacklist': {'ok': blacklist_ok, 'txt': blacklist_txt}
    })


@app.route('/api/campaign/quick-launch', methods=['POST'])
@limiter.limit("30 per minute")
@operator_required
def api_quick_launch_campaign():
    data = request.get_json() or {}
    name = data.get('name')
    subject = data.get('subject')
    sending_profile_id = data.get('sending_profile_id')
    recipients_text = data.get('recipients', '')
    
    if not all([name, subject, sending_profile_id, recipients_text]):
        return jsonify({'error': 'Missing required fields'}), 400
        
    sp = SendingProfile.query.get(sending_profile_id)
    if not sp:
        return jsonify({'error': 'Sending profile not found'}), 404
        
    # Default template HTML for quick-launch campaigns
    default_body_html = """<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <h2>Security Alert: Unrecognized Device Login</h2>
    <p>Dear Employee,</p>
    <p>We detected a login to your account from a new location. If this was not you, please verify your credentials immediately:</p>
    <p style="text-align: center; margin: 30px 0;">
        <a href="{{TRACK_LINK}}" style="background: #E11D48; color: white; padding: 12px 30px; text-decoration: none; border-radius: 0px; font-weight: bold; border: 2px solid black; box-shadow: 3px 3px 0px 0px black;">Verify Activity</a>
    </p>
    <p>Thank you,<br>IT Security Operations</p>
    {{PIXEL}}
</body>
</html>"""

    default_landing_html = """<html>
<body style="font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; background: #f5f5f5;">
    <div style="background: white; padding: 30px; border-radius: 0px; border: 3px solid black; box-shadow: 4px 4px 0px 0px black;">
      <h2 style="text-align: center; color: #333; font-weight: 800;">Account Authentication</h2>
      <form method="post">
        <input type="hidden" name="token" value="{{TOKEN}}">
        <div style="margin-bottom: 15px;">
            <label style="display: block; margin-bottom: 5px; color: #555;">Username</label>
            <input name="user" type="text" required style="width: 100%; padding: 10px; border: 2px solid black;">
        </div>
        <div style="margin-bottom: 20px;">
            <label style="display: block; margin-bottom: 5px; color: #555;">Password</label>
            <input name="pass" type="password" required style="width: 100%; padding: 10px; border: 2px solid black;">
        </div>
        <button type="submit" style="width: 100%; background: #000; color: white; padding: 12px; border: none; cursor: pointer; font-weight: bold;">Verify Identity</button>
      </form>
    </div>
</body>
</html>"""

    # Create Campaign
    c = Campaign(
        name=name,
        subject=subject,
        body_html=default_body_html,
        template_html=default_body_html,
        landing_html=default_landing_html,
        sending_profile_id=sending_profile_id,
        flow_type='single_step'
    )
    db.session.add(c)
    db.session.commit()
    
    # Add Recipients (skip suppressed emails/domains)
    emails = [e.strip() for e in recipients_text.splitlines() if e.strip()]
    skipped = 0
    for e in emails:
        if is_suppressed(e):
            skipped += 1
            continue
        r = Recipient(campaign_id=c.id, email=e)
        db.session.add(r)
    db.session.commit()
    
    # Start Campaign Send
    from dropoutjeep_lib.utils.dialer import Dialer
    
    # Resolve rate limit RPM
    rpm = sp.rate_per_minute or 60
    rate_profile = sp.resolve_rate_profile()
    if rate_profile and rate_profile.delay_ms_max:
        rpm = max(1, int(60000.0 / rate_profile.delay_ms_max))
        
    dialer = Dialer(db, rate_per_min=rpm)
    ok = dialer.start_campaign(c.id)
    
    return jsonify({
        'status': 'launched' if ok else 'created_unsent',
        'campaign_id': c.id,
        'recipient_count': len(emails)
    }), 201


@app.route('/api/stats')
@viewer_required
def api_stats():
    sent = Recipient.query.filter(Recipient.sent_at.isnot(None)).count()
    delivered = Recipient.query.filter(Recipient.disposition == 'delivered').count()
    quarantined = Recipient.query.filter(Recipient.disposition == 'quarantined').count()
    clicks = Event.query.filter(Event.event_type == 'click').count()
    opens = Event.query.filter(Event.event_type == 'open').count()
    creds = Event.query.filter(Event.event_type == 'credential_attempt').count()
    reports = Event.query.filter(Event.event_type == 'user_report').count()
    mfa = Event.query.filter(Event.event_type == 'mfa_attempt').count()
    flow_complete = Event.query.filter(Event.event_type == 'flow_complete').count()
    fingerprints = Event.query.filter(Event.event_type == 'fingerprint').count()
    calendar_downloads = Event.query.filter(Event.event_type == 'calendar_download').count()
    training_started = Event.query.filter(Event.event_type == 'training_started').count()
    training_completed = Event.query.filter(Event.event_type == 'training_completed').count()
    recipients_count = Recipient.query.count()
    summary = (
        f"{sent} simulated emails sent. {quarantined} quarantined. "
        f"{clicks} clicks. {mfa} MFA prompts reached. No credentials stored."
    )
    return jsonify(
        dict(sent=sent, delivered=delivered, quarantined=quarantined,
             clicks=clicks, opens=opens, creds=creds, reports=reports,
             mfa=mfa, flow_complete=flow_complete, fingerprints=fingerprints,
             calendar_downloads=calendar_downloads,
             training_started=training_started,
             training_completed=training_completed,
             recipients_count=recipients_count, summary=summary)
    )


@app.route('/api/event/<int:eid>/triage', methods=['POST'])
@limiter.limit("30 per minute")
@operator_required
def api_event_triage(eid):
    data = request.get_json() or {}
    status = data.get('status')
    if status not in ['acknowledged', 'dismissed']:
        return jsonify({'error': 'Invalid status'}), 400
        
    event = Event.query.get(eid)
    if not event:
        return jsonify({'error': 'Event not found'}), 404
        
    event.status = status
    db.session.commit()
    return jsonify({
        'status': 'updated',
        'event_id': eid,
        'new_status': status
    })


@app.route('/events')
@viewer_required
def events_page():
    events = Event.query.order_by(Event.created_at.desc()).limit(500).all()
    return render_template('events.html', events=events)


@app.route('/campaigns')
@viewer_required
def campaigns_page():
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()
    return render_template('campaigns.html', campaigns=campaigns)


@app.route('/recipients')
@viewer_required
def recipients_page():
    recipients = Recipient.query.order_by(Recipient.created_at.desc()).limit(500).all()
    risk_map = {r.id: recipient_risk_score(r.id) for r in recipients}
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()
    selected_campaign_id = request.args.get('campaign_id', type=int)
    return render_template('recipients.html', recipients=recipients, risk_map=risk_map,
                           campaigns=campaigns, selected_campaign_id=selected_campaign_id)


@app.route('/mailers')
@viewer_required
def mailers_page():
    senders = SendingProfile.query.order_by(SendingProfile.id).all()
    return render_template('mailers.html', senders=senders)


@app.route('/reports')
@viewer_required
def reports_page():
    return render_template(
        'reports.html',
        campaigns_count=Campaign.query.count(),
        recipients_count=Recipient.query.count(),
        events_count=Event.query.count(),
        mfa_count=Event.query.filter_by(event_type='mfa_attempt').count(),
        flow_complete_count=Event.query.filter_by(event_type='flow_complete').count(),
        calendar_download_count=Event.query.filter_by(event_type='calendar_download').count(),
        fingerprint_count=Event.query.filter_by(event_type='fingerprint').count(),
        training_started_count=Event.query.filter_by(event_type='training_started').count(),
        training_completed_count=Event.query.filter_by(event_type='training_completed').count(),
    )


@app.route('/landing_pages')
@viewer_required
def landing_pages_page():
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()
    for c in campaigns:
        t = Target.query.filter_by(campaign_id=c.id).first()
        c.sample_token = t.token if t else ''
    return render_template('landing_pages.html', campaigns=campaigns)


@app.route('/robots.txt')
def robots():
    return "User-agent: *\nDisallow: /\n", 200, {'Content-Type': 'text/plain'}

# ---------------------------------------------------------------------------
# Spoofing / sender authentication awareness page
# ---------------------------------------------------------------------------
@app.route('/spoof-check', methods=['GET', 'POST'])
def spoof_check():
    result = None
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip().lower()
        from_header = request.form.get('from_header', '').strip()
        envelope_from = request.form.get('envelope_from', '').strip()

        if from_header and envelope_from:
            result = check_spoof_alignment(from_header, envelope_from)
        elif domain:
            spf_ok, spf_txt = check_spf(domain)
            dmarc_ok, dmarc_txt = check_dmarc(domain)
            result = {
                'from_domain': domain,
                'envelope_domain': domain,
                'domains_aligned': True,
                'spf': {'ok': spf_ok, 'txt': spf_txt},
                'dmarc': {'ok': dmarc_ok, 'txt': dmarc_txt},
            }
    return render_template('spoof_check.html', result=result)


# ---------------------------------------------------------------------------
# Register modular blueprints
# ---------------------------------------------------------------------------
from dropoutjeep_lib.routes.campaigns import campaigns_bp
from dropoutjeep_lib.routes.events import events_bp
from dropoutjeep_lib.routes.recipients import recipients_bp
from dropoutjeep_lib.routes.templates import templates_bp
from dropoutjeep_lib.routes.subsidiaries import subsidiaries_bp
from dropoutjeep_lib.routes.sending_profiles import sending_profiles_bp, sending_profiles_v1_bp
from dropoutjeep_lib.routes.urlcheck import urlcheck_bp
from dropoutjeep_lib.routes.bounce import bounce_bp
from dropoutjeep_lib.routes.landing import landing_bp, landing_probe

from dropoutjeep_lib.routes.admin import admin_bp
from dropoutjeep_lib.routes.campaigns_admin import campaigns_admin_bp
from dropoutjeep_lib.routes.proxy_admin import proxy_admin_bp
from dropoutjeep_lib.routes.sending_admin import sending_admin_bp
from dropoutjeep_lib.routes.webhooks import webhooks_bp
from dropoutjeep_lib.routes.templates_admin import templates_admin_bp
from dropoutjeep_lib.routes.auto_reply import auto_reply_bp
from dropoutjeep_lib.routes.tracking import tracking_bp, ws_events
from dropoutjeep_lib.routes.c2_connectors import admin_c2_bp, api_c2_bp
from dropoutjeep_lib.routes.loot import loot_bp, loot_exfil
from dropoutjeep_lib.routes.new_features import new_features_bp

app.register_blueprint(campaigns_bp)
app.register_blueprint(events_bp)
app.register_blueprint(recipients_bp)
app.register_blueprint(templates_bp)
app.register_blueprint(subsidiaries_bp)
app.register_blueprint(sending_profiles_bp)
app.register_blueprint(sending_profiles_v1_bp)
app.register_blueprint(urlcheck_bp)
app.register_blueprint(bounce_bp)
app.register_blueprint(landing_bp)

app.register_blueprint(admin_bp)
app.register_blueprint(campaigns_admin_bp)
app.register_blueprint(proxy_admin_bp)
app.register_blueprint(sending_admin_bp)
app.register_blueprint(webhooks_bp)
app.register_blueprint(templates_admin_bp)
app.register_blueprint(auto_reply_bp)
app.register_blueprint(tracking_bp)
app.register_blueprint(admin_c2_bp)
app.register_blueprint(api_c2_bp)
app.register_blueprint(loot_bp)
app.register_blueprint(new_features_bp)


# ---------------------------------------------------------------------------
# Blueprint endpoint aliases
# ---------------------------------------------------------------------------
def _alias_blueprint_endpoints(bp_name):
    """Create top-level endpoint aliases so url_for('function_name') keeps working.

    Flask blueprints prefix endpoints with the blueprint name (e.g. admin.login).
    The existing templates call url_for using the original unprefixed names, so
    we register alias rules that point to the same view functions.  Rules with
    fewer required arguments are registered first so that url_for() without
    optional arguments can fall back to the simplest rule (e.g. /admin before
    /admin/page/<int:page>).
    """
    rules = [
        r for r in app.url_map.iter_rules()
        if r.endpoint.startswith(f'{bp_name}.') and '.' in r.endpoint
    ]
    # Sort by number of variable parts descending so the most specific rule is
    # added first. This preserves url_for('admin_index', page=2) -> /admin/page/2.
    rules.sort(key=lambda r: len(r._converters), reverse=True)
    for rule in rules:
        alias = rule.endpoint.split('.', 1)[1]
        methods = rule.methods - {'OPTIONS', 'HEAD'} if rule.methods else None
        app.add_url_rule(
            rule.rule,
            endpoint=alias,
            view_func=app.view_functions[rule.endpoint],
            methods=methods,
            defaults=rule.defaults,
        )


for _bp_name in (
    'admin', 'campaigns_admin', 'proxy_admin', 'sending_admin',
    'webhooks', 'templates_admin', 'auto_reply', 'tracking',
    'c2_connectors', 'new_features',
):
    _alias_blueprint_endpoints(_bp_name)


# --- REVERSE PROXY BLUEPRINT ---
from dropoutjeep_lib.proxy.manager import proxy_bp
app.register_blueprint(proxy_bp)

# Tracking / landing routes are public beacon endpoints; exempt from CSRF.
from dropoutjeep_lib.routes.tracking import (
    track_heatmap, landing, html_smuggle_drop, landing_mfa,
    landing_success, landing_training, landing_training_complete,
    calendar_ics, api_fingerprint,
)
csrf.exempt(landing_probe)
csrf.exempt(track_heatmap)
csrf.exempt(landing)
csrf.exempt(html_smuggle_drop)
csrf.exempt(landing_mfa)
csrf.exempt(landing_success)
csrf.exempt(landing_training)
csrf.exempt(landing_training_complete)
csrf.exempt(calendar_ics)
csrf.exempt(api_fingerprint)
csrf.exempt(loot_exfil)

# API endpoints authenticated via bearer tokens do not need CSRF protection.
csrf.exempt(campaigns_bp)
csrf.exempt(recipients_bp)
csrf.exempt(templates_bp)
csrf.exempt(api_c2_bp)
csrf.exempt(new_features_bp)

# WebSocket live dashboard feed & WebSocket C2
sock.route('/ws/events')(ws_events)

def ws_c2_route(ws, token):
    from dropoutjeep_lib.utils.websocket_c2 import WebSocketC2Handler
    handler = WebSocketC2Handler(ws, token)
    handler.run()

sock.route('/ws/c2/<token>')(ws_c2_route)

# Start the in-app campaign scheduler and live WebSocket broadcaster.
init_scheduler(app)
start_broadcaster()

# ---------------------------------------------------------------------------
# Server start
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    import logging
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("dropoutjeep_lib.proxy").setLevel(logging.INFO)
    # Default to 0.0.0.0 so DropoutJeep is reachable on local network IPs and
    # inside Docker/VPS environments. Use HOST=127.0.0.1 for local-only dev.
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', '5000'))
    with app.app_context():
        db.create_all()
        _run_inline_upgrades(app)
    print(f"DropoutJeep running at: http://{host}:{port}")
    app.run(host=host, port=port,
            debug=os.environ.get('FLASK_DEBUG', '0') == '1')
