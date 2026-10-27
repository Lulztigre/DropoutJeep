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
    CapturedCredential, CapturedCookie
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

webhooks_bp = Blueprint('webhooks', __name__, url_prefix='/admin/webhooks')

WEBHOOK_EVENT_TYPES = [
    ('sent', 'Email sent'),
    ('open', 'Email opened'),
    ('click', 'Link clicked'),
    ('credential_attempt', 'Credential attempt'),
    ('mfa_attempt', 'MFA attempt'),
    ('proxy_credential_capture', 'Proxy credential capture'),
    ('proxy_mfa_capture', 'Proxy MFA capture'),
    ('proxy_session_cookie_capture', 'Proxy session cookie captured (post-MFA)'),
    ('canary_triggered', 'Canary triggered'),
    ('fingerprint', 'Fingerprint captured'),
    ('flow_complete', 'Flow completed'),
    ('training_started', 'Training started'),
    ('training_completed', 'Training completed'),
    ('send_failed', 'Send failed'),
]


@webhooks_bp.route('/')
@admin_required
def admin_webhooks():
    webhooks = Webhook.query.order_by(Webhook.created_at.desc()).all()
    campaigns = Campaign.query.order_by(Campaign.name).all()
    return render_template('webhooks.html', webhooks=webhooks,
                           campaigns=campaigns, event_types=WEBHOOK_EVENT_TYPES)


@webhooks_bp.route('/new', methods=['POST'])
@admin_required
def admin_webhook_new():
    name = request.form.get('name', '').strip()
    url = request.form.get('url', '').strip()
    secret = request.form.get('secret', '').strip()
    campaign_id = request.form.get('campaign_id', '')
    events = request.form.getlist('events')

    if not name or not url or not secret:
        flash('Name, URL, and secret are required', 'danger')
        return redirect(url_for('admin_webhooks'))

    w = Webhook(
        name=name,
        url=url,
        secret=secret,
        campaign_id=int(campaign_id) if campaign_id else None,
    )
    w.set_events(events)
    db.session.add(w)
    db.session.commit()
    flash(f'Webhook "{name}" created', 'success')
    return redirect(url_for('admin_webhooks'))


@webhooks_bp.route('/<int:webhook_id>/toggle', methods=['POST'])
@admin_required
def admin_webhook_toggle(webhook_id):
    w = Webhook.query.get_or_404(webhook_id)
    w.is_active = not w.is_active
    db.session.commit()
    flash(f'Webhook "{w.name}" {"enabled" if w.is_active else "disabled"}', 'success')
    return redirect(url_for('admin_webhooks'))


@webhooks_bp.route('/<int:webhook_id>/delete', methods=['POST'])
@admin_required
def admin_webhook_delete(webhook_id):
    w = Webhook.query.get_or_404(webhook_id)
    db.session.delete(w)
    db.session.commit()
    flash(f'Webhook "{w.name}" deleted', 'success')
    return redirect(url_for('admin_webhooks'))
