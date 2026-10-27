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

templates_admin_bp = Blueprint('templates_admin', __name__, url_prefix='/admin/templates')

@templates_admin_bp.route('/')
@operator_required
def admin_templates():
    from dropoutjeep_lib.utils.template_marketplace import get_categories
    category = request.args.get('category')
    query = EmailTemplate.query.order_by(EmailTemplate.category, EmailTemplate.name)
    if category:
        query = query.filter_by(category=category)
    templates = query.all()
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()
    return render_template('template_marketplace.html', templates=templates,
                           categories=get_categories(), current_category=category,
                           campaigns=campaigns)


@templates_admin_bp.route('/landing-templates')
@operator_required
def admin_landing_templates():
    """List reusable landing-page templates stored inside email templates."""
    templates = EmailTemplate.query.order_by(EmailTemplate.category, EmailTemplate.name).all()
    return render_template('landing_templates.html', templates=templates)


@templates_admin_bp.route('/<int:template_id>/import-to-campaign/<int:campaign_id>', methods=['POST'])
@operator_required
def admin_template_import_to_campaign(template_id, campaign_id):
    t = EmailTemplate.query.get_or_404(template_id)
    campaign = Campaign.query.get_or_404(campaign_id)
    campaign.subject = t.subject
    campaign.body_html = t.body_html
    campaign.template_html = t.body_html
    campaign.landing_html = t.landing_html
    db.session.commit()
    flash(f'Template "{t.name}" imported into campaign "{campaign.name}"', 'success')
    return redirect(url_for('admin_templates'))


@templates_admin_bp.route('/new', methods=['POST'])
@operator_required
def admin_template_new():
    t = EmailTemplate(
        name=request.form['name'],
        category=request.form.get('category', 'custom'),
        description=request.form.get('description', ''),
        subject=request.form.get('subject', ''),
        body_html=request.form.get('body_html', ''),
        landing_html=request.form.get('landing_html', ''),
        author=request.form.get('author') or g.current_user.username,
        is_builtin=False,
    )
    tags = request.form.get('tags', '')
    t.set_tags([tag.strip() for tag in tags.split(',') if tag.strip()])
    db.session.add(t)
    db.session.commit()
    flash('Template created', 'success')
    return redirect(url_for('admin_templates'))


@templates_admin_bp.route('/<int:template_id>/delete', methods=['POST'])
@operator_required
def admin_template_delete(template_id):
    t = EmailTemplate.query.get_or_404(template_id)
    if t.is_builtin:
        flash('Cannot delete built-in templates', 'danger')
        return redirect(url_for('admin_templates'))
    db.session.delete(t)
    db.session.commit()
    flash('Template deleted', 'success')
    return redirect(url_for('admin_templates'))
