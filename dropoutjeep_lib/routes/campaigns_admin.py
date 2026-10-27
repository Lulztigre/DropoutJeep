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
    CapturedCredential, CapturedCookie, CapturedOAuthToken, SamlCapture, Payload
)
from dropoutjeep_lib.utils.auth import (
    login_required, admin_required, operator_required, viewer_required,
    log_audit, get_current_user
)
from dropoutjeep_lib.utils.analytics import get_heatmap_data, get_recipient_timeline, export_campaign_csv, export_campaign_pdf, compare_campaigns
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
from dropoutjeep_lib.utils.settings import get_base_url
from dropoutjeep_lib.utils.scheduler import sync_campaign_schedules
from dropoutjeep_lib.utils.dialer import Dialer
from dropoutjeep_lib.utils.live import push_event
from dropoutjeep_lib.utils.mitre import summarize_campaign, coverage_report
from dropoutjeep_lib.utils.timing import campaign_timing_summary
from dropoutjeep_lib.utils.cookie_validation import validate_captured_cookie
from dropoutjeep_lib.utils.suppression import is_suppressed

campaigns_admin_bp = Blueprint('campaigns_admin', __name__)

@campaigns_admin_bp.route('/admin/campaign/new', methods=['GET', 'POST'])
@operator_required
def admin_new_campaign():
    if request.method == 'POST':
        # --- Inline prerequisite creation ---
        new_subsidiary_id = None
        proxy_domain = None
        staged_payload = None
        if request.form.get('inline_subsidiary_name'):
            s = Subsidiary(
                name=request.form['inline_subsidiary_name'],
                sending_domain=request.form['inline_subsidiary_sending_domain'],
                display_name=request.form['inline_subsidiary_display_name'],
                from_address=request.form['inline_subsidiary_from_address'],
                bounce_subdomain=request.form.get('inline_subsidiary_bounce_subdomain'),
                dkim_selector=request.form.get('inline_subsidiary_dkim_selector')
            )
            s.set_dkim_private_key(request.form.get('inline_subsidiary_dkim_private_key'))
            db.session.add(s)
            db.session.commit()
            new_subsidiary_id = s.id
            flash(f'Subsidiary "{s.name}" created.', 'success')

        sending_profile_id = request.form.get('sending_profile_id')
        if request.form.get('inline_profile_name'):
            sp = SendingProfile(
                name=request.form['inline_profile_name'],
                smtp_host=request.form['inline_profile_smtp_host'],
                smtp_port=int(request.form.get('inline_profile_smtp_port') or 587),
                smtp_user=request.form.get('inline_profile_smtp_user'),
                use_tls=request.form.get('inline_profile_use_tls') == 'on',
                subsidiary_id=int(request.form['inline_profile_subsidiary_id']) if request.form.get('inline_profile_subsidiary_id') else new_subsidiary_id,
            )
            sp.set_smtp_pass(request.form.get('inline_profile_smtp_pass'))
            db.session.add(sp)
            db.session.commit()
            sending_profile_id = sp.id
            flash(f'Sending profile "{sp.name}" created.', 'success')

        name = request.form['name']
        subject = request.form['subject']
        body_html = request.form['body_html']
        landing_html = request.form['landing_html']

        # Allow explicit template import for no-JS clients or direct marketplace reuse.
        template_id = request.form.get('template_id')
        if template_id:
            t = EmailTemplate.query.get(int(template_id))
            if t:
                if not subject.strip():
                    subject = t.subject
                if not body_html.strip():
                    body_html = t.body_html
                if not landing_html.strip():
                    landing_html = t.landing_html

        sending_profile_id = int(sending_profile_id) if sending_profile_id else None

        sending_profile = SendingProfile.query.get(sending_profile_id) if sending_profile_id else None
        if not sending_profile:
            # A campaign without a profile is still a useful draft: the copy, the
            # template and the recipient list are the expensive part. Launch stays
            # blocked until a profile is attached.
            flash('No sending profile selected. Campaign saved as a draft; attach a profile before launch.', 'warning')

        # --- DKIM / SPF / DMARC preflight validation ---
        sub = sending_profile.subsidiary if sending_profile else None
        domain = sub.sending_domain if sub else None
        if domain:
            dkim_results = dkim_spf_check(domain)
            if 'error' in str(dkim_results.get('spf', '')).lower():
                flash(f"SPF validation warning: {dkim_results['spf']}", 'warning')
            if 'error' in str(dkim_results.get('dkim', '')).lower():
                flash(f"DKIM validation warning: {dkim_results['dkim']}", 'warning')
            dmarc_ok, dmarc_txt = check_dmarc(domain)
            if not dmarc_ok:
                flash(f"DMARC record not found for {domain}", 'warning')
            if sub:
                try:
                    if not sub.get_dkim_private_key():
                        flash('DKIM key is not stored on the subsidiary, so messages will go out unsigned. '
                              'Regenerate it from Sending, Subsidiaries.', 'danger')
                except Exception:
                    flash('DKIM private key could not be decrypted. The environment key changed. '
                          'Restore the previous .env or regenerate the DKIM pair.', 'danger')

        # Bounce handling needs an IMAP mailbox on the profile. Without it bounce
        # events never arrive and the reported bounce rate reads zero.
        if sending_profile and not (sending_profile.imap_host or '').strip():
            flash('Bounce tracking is off: this sending profile has no IMAP mailbox, so bounces will not be recorded.', 'warning')

        # --- SMTP connectivity preflight ---
        # Reported, not enforced. Refusing to create the campaign threw away the
        # copy, the recipients and the settings, and the campaign appeared to
        # vanish. Launch and preflight are where a broken relay must stop you.
        if sending_profile:
            smtp_ok, smtp_txt = validate_smtp_relay(
                sending_profile.smtp_host or '',
                sending_profile.smtp_port or 587,
                sending_profile.smtp_user,
                sending_profile.get_smtp_pass()
            )
            if not smtp_ok:
                flash(f'Campaign saved, but the SMTP check failed: {smtp_txt}. '
                      'Fix the sending profile before launch.', 'danger')

        # Parse flow and calendar options
        from datetime import datetime as _dt
        flow_type = request.form.get('flow_type', 'single_step')
        current_user = getattr(g, 'current_user', None)
        if flow_type == 'reverse_proxy' and (not current_user or current_user.role != 'admin'):
            flash('Reverse proxy campaigns are restricted to administrators.', 'danger')
            return redirect(url_for('admin_new_campaign'))
        flow_config = {
            'redirect_url': request.form.get('flow_redirect_url', 'https://en.wikipedia.org/wiki/Phishing').strip(),
            'mfa_title': request.form.get('flow_mfa_title', 'Two-Factor Authentication').strip(),
            'success_message': request.form.get(
                'flow_success_message',
                'This was an authorized phishing simulation. Your submitted input has been recorded as evidence for awareness training.'
            ).strip(),
            'training_enabled': request.form.get('training_enabled') == 'on',
            'training_url': request.form.get('training_url', '').strip(),
            'training_duration_seconds': int(request.form.get('training_duration_seconds') or 30),
            'qr_code_enabled': request.form.get('qr_code_enabled') == 'on',
        }

        if flow_type == 'reverse_proxy':
            proxy_target_url = request.form.get('proxy_target_url', '').strip()
            if not proxy_target_url:
                flash('Reverse proxy campaigns require a target URL', 'danger')
                return redirect(url_for('admin_new_campaign'))
            if not proxy_target_url.startswith(('http://', 'https://')):
                flash('Target URL must start with http:// or https://', 'danger')
                return redirect(url_for('admin_new_campaign'))
            upstream_proxy = request.form.get('proxy_upstream_proxy', '').strip()
            if upstream_proxy:
                parsed = urlparse(upstream_proxy)
                if parsed.scheme not in ('http', 'https', 'socks5', 'socks5h'):
                    flash('Upstream proxy must use http://, https://, socks5:// or socks5h://', 'danger')
                    return redirect(url_for('admin_new_campaign'))
            flow_config['target_url'] = proxy_target_url
            flow_config['upstream_proxy'] = upstream_proxy
            flow_config['tls_fingerprint'] = request.form.get('proxy_tls_fingerprint', '').strip() or None
            flow_config['capture_credentials'] = request.form.get('proxy_capture_credentials') == 'on'
            flow_config['capture_cookies'] = request.form.get('proxy_capture_cookies') == 'on'
            flow_config['mfa_relay_enabled'] = request.form.get('proxy_mfa_relay_enabled') == 'on'

            # --- Proxy domain selection / creation (admin only) ---
            if current_user and current_user.role == 'admin':
                proxy_domain_id = request.form.get('proxy_domain_id')
                if proxy_domain_id:
                    proxy_domain = ProxyDomain.query.get(int(proxy_domain_id))
                proxy_domain_new = request.form.get('proxy_domain_new', '').strip()
                if proxy_domain_new:
                    if ProxyDomain.query.filter_by(domain=proxy_domain_new).first():
                        flash(f'Domain "{proxy_domain_new}" is already mapped', 'danger')
                        return redirect(url_for('admin_new_campaign'))
                    is_wildcard = proxy_domain_new.startswith('*.')
                    proxy_domain = ProxyDomain(
                        domain=proxy_domain_new,
                        campaign_id=None,  # Linked after campaign creation
                        is_wildcard=is_wildcard,
                        base_domain=proxy_domain_new[2:] if is_wildcard else proxy_domain_new,
                        server_ip=request.form.get('proxy_domain_server_ip', '').strip() or None,
                        dns_provider=request.form.get('proxy_domain_dns_provider', 'none').strip() or 'none',
                        auto_tls_enabled=request.form.get('proxy_domain_auto_tls') == 'on',
                    )
                    db.session.add(proxy_domain)
                    db.session.commit()
                    flash(f'Proxy domain "{proxy_domain_new}" created. Provision DNS/TLS before launch.', 'info')
            if not proxy_domain:
                flash('Reverse-proxy campaigns should not be launched until a proxy domain is provisioned and TLS is ready.', 'warning')

        # --- OAuth2 / SAML / payload staging ---
        oauth_cfg = {
            'provider': request.form.get('oauth_provider', '').strip(),
            'authorization_endpoint': request.form.get('oauth_authorization_endpoint', '').strip(),
            'token_endpoint': request.form.get('oauth_token_endpoint', '').strip(),
            'client_id': request.form.get('oauth_client_id', '').strip(),
            'client_secret': request.form.get('oauth_client_secret', '').strip(),
            'redirect_uri': request.form.get('oauth_redirect_uri', '').strip(),
            'scope': request.form.get('oauth_scope', '').strip(),
            'auto_exchange': request.form.get('oauth_auto_exchange') == 'on',
        }
        raw_extra = request.form.get('oauth_extra_params', '').strip()
        extra_params = {}
        if raw_extra:
            for line in raw_extra.splitlines():
                line = line.strip()
                if '=' in line:
                    k, v = line.split('=', 1)
                    extra_params[k.strip()] = v.strip()
        if extra_params:
            oauth_cfg['extra_params'] = extra_params
        if any(oauth_cfg.values()):
            flow_config['oauth'] = oauth_cfg

        saml_real_acs = request.form.get('saml_real_acs_url', '').strip()
        if saml_real_acs:
            flow_config['saml'] = {'real_acs_url': saml_real_acs}

        staged_payload = None
        payload_file = request.files.get('payload_file')
        payload_name = request.form.get('payload_name', '').strip()
        payload_filename = request.form.get('payload_filename', '').strip()
        if payload_file and payload_file.filename and payload_name and payload_filename:
            from pathlib import Path
            ext = Path(payload_filename).suffix.lstrip('.') or 'bin'
            mime = payload_file.mimetype or 'application/octet-stream'
            staged_payload = Payload(
                campaign_id=None,  # Linked after campaign creation
                name=payload_name,
                filename=payload_filename,
                extension=ext,
                mime_type=mime,
            )
            staged_payload.set_content(payload_file.read())
            db.session.add(staged_payload)
            db.session.commit()

        calendar_invite = request.form.get('calendar_invite') == '1'
        cal_start = request.form.get('calendar_event_start', '').strip()
        cal_end = request.form.get('calendar_event_end', '').strip()

        def _parse_dt(value):
            if not value:
                return None
            try:
                return _dt.fromisoformat(value)
            except Exception:
                return None

        # Deliverability + evasion options
        domain_reputation_check_enabled = request.form.get('domain_reputation_check_enabled') == 'on'
        sender_rotation_pool_id = request.form.get('sender_rotation_pool_id')

        # Admin-only advanced features
        sandbox_evasion_enabled = False
        sandbox_safe_html = ''
        html_smuggling_enabled = False
        html_smuggling_payload_raw = None
        html_smuggling_filename = None
        if current_user and current_user.role == 'admin':
            sandbox_evasion_enabled = request.form.get('sandbox_evasion_enabled') == 'on'
            sandbox_safe_html = request.form.get('sandbox_safe_html', '')
            html_smuggling_enabled = request.form.get('html_smuggling_enabled') == 'on'
            html_smuggling_filename = request.form.get('html_smuggling_filename', '').strip() or None
            payload_file = request.files.get('html_smuggling_payload_file')
            payload_text = request.form.get('html_smuggling_payload_text', '').strip()
            if html_smuggling_enabled:
                if payload_file and payload_file.filename:
                    html_smuggling_filename = html_smuggling_filename or payload_file.filename
                    html_smuggling_payload_raw = payload_file.read()
                elif payload_text:
                    html_smuggling_payload_raw = payload_text.encode('utf-8')

        # Validate recipients before creating the campaign.
        recipients_text = request.form.get('recipients', '')
        emails = [e.strip() for e in recipients_text.splitlines() if e.strip()]
        uploaded_recipients = request.files.get('recipients_file')
        has_recipient_file = uploaded_recipients and uploaded_recipients.filename
        if not emails and not has_recipient_file:
            flash('At least one recipient is required (text or file upload).', 'danger')
            return redirect(url_for('admin_new_campaign'))

        c = Campaign(
            name=name, subject=subject, body_html=body_html,
            template_html=body_html, landing_html=landing_html,
            sending_profile_id=sending_profile_id,
            flow_type=flow_type,
            flow_config=json.dumps(flow_config),
            calendar_invite=calendar_invite,
            calendar_event_title=request.form.get('calendar_event_title', '').strip() or None,
            calendar_event_location=request.form.get('calendar_event_location', '').strip() or None,
            calendar_event_start=_parse_dt(cal_start),
            calendar_event_end=_parse_dt(cal_end),
            scheduled_at=_parse_dt(request.form.get('schedule_datetime', '').strip()),
            schedule_cron=request.form.get('schedule_cron', '').strip() or None,
            schedule_timezone=request.form.get('schedule_timezone', 'UTC').strip(),
            schedule_enabled=request.form.get('schedule_enabled') == 'on',
            domain_reputation_check_enabled=domain_reputation_check_enabled,
            sender_rotation_pool_id=int(sender_rotation_pool_id) if sender_rotation_pool_id else None,
            sandbox_evasion_enabled=sandbox_evasion_enabled,
            sandbox_safe_html=sandbox_safe_html,
            html_smuggling_enabled=html_smuggling_enabled,
            html_smuggling_filename=html_smuggling_filename,
            use_enterprise_mailer=request.form.get('use_enterprise_mailer') == 'on',
            store_credentials_plaintext=request.form.get('store_credentials_plaintext') == 'on',
            edr_detection=request.form.get('edr_detection') == 'on',
            ip_reputation_filter=request.form.get('ip_reputation_filter') == 'on',
            safelinks_mode=request.form.get('safelinks_mode', 'standard').strip(),
        )
        if html_smuggling_enabled and html_smuggling_payload_raw:
            c.set_html_smuggling_payload(html_smuggling_payload_raw)
        db.session.add(c)
        db.session.commit()

        # Link staged proxy domain / payload to the new campaign
        if proxy_domain:
            proxy_domain.campaign_id = c.id
            db.session.add(proxy_domain)
        if staged_payload:
            staged_payload.campaign_id = c.id
            db.session.add(staged_payload)
        if proxy_domain or staged_payload:
            db.session.commit()

        suppressed_count = 0
        added_count = 0
        for e in emails:
            if is_suppressed(e):
                suppressed_count += 1
                continue
            r = Recipient(campaign_id=c.id, email=e)
            db.session.add(r)
            added_count += 1

        # Bulk recipient import from uploaded CSV/Excel.
        import_created = 0
        import_duplicates = 0
        import_errors = 0
        if has_recipient_file:
            from dropoutjeep_lib.utils.recipient_import import import_recipients
            result = import_recipients(
                uploaded_recipients.stream,
                uploaded_recipients.filename,
                campaign_id=c.id,
            )
            import_created = result.get('created', 0)
            import_duplicates = result.get('duplicates', 0)
            import_errors = len(result.get('errors', []))

        db.session.commit()
        total_added = added_count + import_created
        flash(f'Campaign created successfully! {total_added} recipients added.', 'success')
        if suppressed_count > 0:
            flash(f'{suppressed_count} recipient(s) skipped (found in suppression list).', 'warning')
        if import_duplicates:
            flash(f'{import_duplicates} file import duplicate(s) skipped.', 'info')
        if import_errors:
            errors_sample = result['errors'][:3]
            flash('File import errors: ' + '; '.join(f'row {e["row"]}: {e["reason"]}' for e in errors_sample), 'warning')
        if c.flow_type == "reverse_proxy":
            flash("Proxy campaign created. Configure target URL and rules.", "info")
            return redirect(url_for("admin_campaign_proxy_config", cid=c.id))
        flash("Run preflight checks before launching.", "info")
        return redirect(url_for('admin_campaign_validate', cid=c.id))
    sps = SendingProfile.query.all()
    rotation_pools = SenderRotationPool.query.order_by(SenderRotationPool.name).all()
    subsidiaries = Subsidiary.query.order_by(Subsidiary.name).all()
    email_templates = EmailTemplate.query.order_by(EmailTemplate.name).all()
    proxy_domains = ProxyDomain.query.order_by(ProxyDomain.domain).all()
    is_admin = getattr(g, 'current_user', None) and g.current_user.role == 'admin'
    return render_template(
        'campaign_new.html',
        sending_profiles=sps,
        rotation_pools=rotation_pools,
        subsidiaries=subsidiaries,
        email_templates=email_templates,
        proxy_domains=proxy_domains,
        is_admin=is_admin,
    )


@campaigns_admin_bp.route('/admin/campaign/<int:cid>/send', methods=['POST'])
@operator_required
def admin_send_campaign(cid):
    campaign = Campaign.query.get_or_404(cid)

    sp = campaign.sending_profile
    if not sp:
        flash('Send not started: this campaign has no sending profile. Attach one, then launch.', 'danger')
        return redirect(url_for('campaigns_admin.admin_campaign_edit', cid=cid))

    # Refuse to start a run that cannot authenticate. A launch against a dead
    # relay marks every recipient as failed and consumes the campaign's one
    # clean run, which is the worst possible time to discover a wrong port.
    smtp_ok, smtp_txt = validate_smtp_relay(
        sp.smtp_host or '', sp.smtp_port or 587, sp.smtp_user, sp.get_smtp_pass()
    )
    if not smtp_ok:
        flash(f'Send not started. SMTP check failed: {smtp_txt}', 'danger')
        return redirect(url_for('campaigns_admin.admin_campaign_edit', cid=cid))

    sub = sp.subsidiary
    if sub and sub.dkim_selector:
        try:
            signed = bool(sub.get_dkim_private_key())
        except Exception:
            signed = False
        if not signed:
            flash('Warning: no usable DKIM key on the subsidiary, so mail goes out unsigned '
                  'and DMARC alignment fails. Regenerate the key before a real send.', 'warning')

    # Resolve rate profile RPM as a fallback if no provider profile matched.
    rpm = sp.rate_per_minute if sp else 60
    rate_profile = sp.resolve_rate_profile() if sp else None
    if rate_profile and rate_profile.delay_ms_max:
        rpm = max(1, int(60000.0 / rate_profile.delay_ms_max))

    dialer = Dialer(db, rate_per_min=rpm)
    ok = dialer.start_campaign(cid)
    if ok:
        flash('Campaign send started in background', 'success')
    else:
        flash('No unsent recipients for this campaign', 'warning')
    return redirect(url_for('admin_index'))


@campaigns_admin_bp.route('/api/campaign/<int:cid>/progress')
@viewer_required
def campaign_progress(cid):
    campaign = Campaign.query.get_or_404(cid)
    job = CampaignJob.query.filter_by(campaign_id=cid) \
        .order_by(CampaignJob.started_at.desc()).first()
    if not job:
        return jsonify({'status': 'not_found'})
    total = job.total or Recipient.query.filter_by(campaign_id=cid).count()
    return jsonify({
        'status': job.status,
        'total': total,
        'sent': job.sent,
        'failed': job.failed,
        'started_at': job.started_at.isoformat() if job.started_at else None,
        'completed_at': job.completed_at.isoformat() if job.completed_at else None,
    })


@campaigns_admin_bp.route('/api/campaign/<int:cid>/stop', methods=['POST'])
@operator_required
def campaign_stop(cid):
    stopped = Dialer.stop_campaign(cid)
    if stopped:
        # Sync the job record status.
        job = CampaignJob.query.filter_by(campaign_id=cid) \
            .order_by(CampaignJob.started_at.desc()).first()
        if job:
            job.status = 'stopped'
            job.completed_at = datetime.utcnow()
            db.session.commit()
        return jsonify({'status': 'stopped'})
    return jsonify({'status': 'not_running'})


@campaigns_admin_bp.route('/api/campaign/<int:cid>/risk')
@viewer_required
def api_campaign_risk(cid):
    campaign = Campaign.query.get_or_404(cid)
    recipients = Recipient.query.filter_by(campaign_id=cid).all()
    result = []
    for r in recipients:
        score_info = recipient_risk_score(r.id)
        result.append({
            'recipient_id': r.id,
            'email': r.email,
            'score': score_info['score'],
            'bucket': score_info['bucket'],
            'breakdown': score_info['breakdown'],
        })
    return jsonify(result)


@campaigns_admin_bp.route('/api/recipients/<int:rid>/risk')
@viewer_required
def api_recipient_risk(rid):
    recipient = Recipient.query.get_or_404(rid)
    return jsonify({
        'recipient_id': recipient.id,
        'email': recipient.email,
        **recipient_risk_score(recipient.id)
    })


@campaigns_admin_bp.route('/admin/campaign/<int:cid>/analytics')
@operator_required
def admin_campaign_analytics(cid):
    """Campaign analytics dashboard with heatmap, geo, and export links."""
    campaign = Campaign.query.get_or_404(cid)
    from dropoutjeep_lib.utils.analytics import get_heatmap_data
    heatmap = get_heatmap_data(cid)
    return render_template('campaign_analytics.html', campaign=campaign, heatmap=heatmap)


@campaigns_admin_bp.route('/admin/campaign/<int:cid>/recipient/<int:rid>/timeline')
@operator_required
def admin_recipient_timeline(cid, rid):
    """Per-recipient chronological event timeline."""
    campaign = Campaign.query.get_or_404(cid)
    recipient = Recipient.query.get_or_404(rid)
    if recipient.campaign_id != cid:
        abort(404)
    from dropoutjeep_lib.utils.analytics import get_recipient_timeline
    timeline = get_recipient_timeline(rid)
    return render_template('recipient_timeline.html', campaign=campaign, recipient=recipient, timeline=timeline)


@campaigns_admin_bp.route('/admin/campaign/<int:cid>/export/csv')
@operator_required
def admin_campaign_export_csv(cid):
    """Export campaign results as CSV."""
    from dropoutjeep_lib.utils.analytics import export_campaign_csv
    csv_data = export_campaign_csv(cid)
    response = make_response(csv_data)
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=campaign_{cid}.csv'
    return response


@campaigns_admin_bp.route('/admin/campaign/<int:cid>/export/pdf')
@operator_required
def admin_campaign_export_pdf(cid):
    """Export campaign summary as PDF."""
    from dropoutjeep_lib.utils.analytics import export_campaign_pdf
    pdf_bytes = export_campaign_pdf(cid)
    response = make_response(pdf_bytes)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=campaign_{cid}.pdf'
    return response


@campaigns_admin_bp.route('/api/campaign/<int:cid>/funnel')
@viewer_required
def api_campaign_funnel(cid):
    Campaign.query.get_or_404(cid)
    return jsonify(compute_funnel(cid))


@campaigns_admin_bp.route('/admin/campaign/<int:cid>/funnel')
@viewer_required
def admin_campaign_funnel(cid):
    campaign = Campaign.query.get_or_404(cid)
    funnel = compute_funnel(cid)
    return render_template('campaign_funnel.html', campaign=campaign, funnel=funnel)


@campaigns_admin_bp.route('/admin/campaigns/compare')
@viewer_required
def admin_campaigns_compare():
    """Side-by-side comparison of selected campaigns."""
    campaign_ids = []
    for raw in (request.args.get('campaign_ids') or '').split(','):
        raw = raw.strip()
        if raw.isdigit():
            campaign_ids.append(int(raw))
    if len(campaign_ids) < 2:
        flash('Select at least two campaigns to compare.', 'warning')
        return redirect(url_for('campaigns_page'))

    summaries = compare_campaigns(campaign_ids)
    return render_template('campaign_compare.html', summaries=summaries)


@campaigns_admin_bp.route('/api/campaigns/compare')
@viewer_required
def api_campaigns_compare():
    """JSON side-by-side comparison of selected campaigns."""
    campaign_ids = []
    for raw in (request.args.get('campaign_ids') or '').split(','):
        raw = raw.strip()
        if raw.isdigit():
            campaign_ids.append(int(raw))
    if len(campaign_ids) < 2:
        return jsonify({'error': 'Select at least two campaigns'}), 400
    return jsonify(compare_campaigns(campaign_ids))


@campaigns_admin_bp.route('/api/campaign/<int:cid>/schedule', methods=['POST'])
@operator_required
def api_campaign_schedule(cid):
    campaign = Campaign.query.get_or_404(cid)
    data = request.get_json(silent=True) if request.is_json else request.form

    def _parse_dt(value):
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except Exception:
            return None

    campaign.scheduled_at = _parse_dt((data.get('schedule_datetime') or '').strip())
    campaign.schedule_cron = (data.get('schedule_cron') or '').strip() or None
    campaign.schedule_timezone = (data.get('schedule_timezone') or 'UTC').strip() or 'UTC'
    campaign.schedule_enabled = bool(data.get('schedule_enabled'))
    db.session.add(campaign)
    db.session.commit()
    sync_campaign_schedules()
    return jsonify({
        'status': 'scheduled',
        'campaign_id': cid,
        'schedule_enabled': campaign.schedule_enabled,
        'schedule_cron': campaign.schedule_cron,
        'scheduled_at': campaign.scheduled_at.isoformat() if campaign.scheduled_at else None,
    })


@campaigns_admin_bp.route('/api/campaign/<int:cid>/schedule/disable', methods=['POST'])
@operator_required
def api_campaign_schedule_disable(cid):
    campaign = Campaign.query.get_or_404(cid)
    campaign.schedule_enabled = False
    db.session.add(campaign)
    db.session.commit()
    sync_campaign_schedules()
    return jsonify({'status': 'disabled', 'campaign_id': cid})


@campaigns_admin_bp.route('/admin/campaign/<int:campaign_id>/clone', methods=['POST'])
@operator_required
def admin_campaign_clone(campaign_id):
    from dropoutjeep_lib.utils.campaign_clone import clone_campaign
    name = request.form.get('name', '').strip()
    copy_recipients = request.form.get('copy_recipients') == 'on'
    new_campaign = clone_campaign(campaign_id, new_name=name or None, copy_recipients=copy_recipients)
    flash(f'Campaign cloned as "{new_campaign.name}"', 'success')
    return redirect(url_for('admin_index'))


@campaigns_admin_bp.route('/admin/campaign/<int:campaign_id>/versions')
@viewer_required
def admin_campaign_versions(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    versions = CampaignVersion.query.filter_by(campaign_id=campaign_id) \
        .order_by(CampaignVersion.version_number.desc()).all()
    return render_template('campaign_versions.html', campaign=campaign, versions=versions)


@campaigns_admin_bp.route('/admin/campaign/<int:campaign_id>/versions/create', methods=['POST'])
@operator_required
def admin_campaign_version_create(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    version = campaign.snapshot_version(user_id=g.current_user.id,
                                        notes=request.form.get('notes'))
    db.session.add(version)
    db.session.commit()
    flash(f'Saved version #{version.version_number}', 'success')
    return redirect(url_for('admin_campaign_versions', campaign_id=campaign.id))


@campaigns_admin_bp.route('/admin/campaign/<int:campaign_id>/versions/<int:version_id>/restore', methods=['POST'])
@operator_required
def admin_campaign_version_restore(campaign_id, version_id):
    from dropoutjeep_lib.utils.campaign_clone import restore_campaign_version
    restore_campaign_version(campaign_id, version_id, user_id=g.current_user.id)
    flash('Campaign restored to selected version', 'success')
    return redirect(url_for('admin_campaign_versions', campaign_id=campaign_id))


@campaigns_admin_bp.route('/admin/campaign/<int:campaign_id>/canaries', methods=['GET', 'POST'])
@operator_required
def admin_canaries(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        token_type = request.form.get('token_type', 'url')
        redirect_url = request.form.get('redirect_url', '').strip()
        notes = request.form.get('notes', '').strip()
        if not name:
            flash('Canary name is required', 'danger')
            return redirect(url_for('admin_canaries', campaign_id=campaign_id))
        if token_type not in ('url', 'image'):
            token_type = 'url'
        canary = CanaryToken(
            name=name,
            token_type=token_type,
            campaign_id=campaign.id,
            redirect_url=redirect_url or None,
            notes=notes or None,
            status='active',
        )
        db.session.add(canary)
        db.session.commit()
        flash(f'Canary "{name}" created', 'success')
        return redirect(url_for('admin_canaries', campaign_id=campaign_id))

    canaries = CanaryToken.query.filter_by(campaign_id=campaign.id) \
        .order_by(CanaryToken.created_at.desc()).all()
    base_url = get_base_url(request.url_root).rstrip('/')
    return render_template('canary_tokens.html',
                           campaign=campaign,
                           canaries=canaries,
                           base_url=base_url)


@campaigns_admin_bp.route('/api/campaign/<int:campaign_id>/mitre')
@viewer_required
def api_campaign_mitre(campaign_id):
    """Return MITRE ATT&CK technique mapping and coverage for campaign events."""
    Campaign.query.get_or_404(campaign_id)
    events = Event.query.filter_by(campaign_id=campaign_id).all()
    return jsonify({
        'campaign_id': campaign_id,
        'summary': summarize_campaign(events),
        'coverage': coverage_report(events),
    })


@campaigns_admin_bp.route('/api/campaign/<int:campaign_id>/timing')
@viewer_required
def api_campaign_timing(campaign_id):
    """Return timing analytics for campaign events."""
    Campaign.query.get_or_404(campaign_id)
    return jsonify(campaign_timing_summary(campaign_id))


@campaigns_admin_bp.route('/api/campaign/<int:cid>/cookie/<int:cookie_id>/validate', methods=['POST'])
@operator_required
def api_validate_captured_cookie(cid, cookie_id):
    """Replay a captured cookie against the campaign target and store the result."""
    Campaign.query.get_or_404(cid)
    cookie = CapturedCookie.query.get_or_404(cookie_id)
    if cookie.campaign_id != cid:
        return jsonify({'error': 'Cookie does not belong to campaign'}), 404

    result = validate_captured_cookie(cookie_id)
    status_code = 200 if result.get('valid') else 400
    if result.get('valid') is None and result.get('error'):
        status_code = 400
    return jsonify({
        'valid': result.get('valid'),
        'error': result.get('error'),
        'status_code': result.get('status_code'),
        'redirect_location': result.get('redirect_location'),
        'validated_at': cookie.validated_at.isoformat() if cookie.validated_at else None,
    }), status_code


@campaigns_admin_bp.route('/api/campaign/<int:cid>/cookies/validate-all', methods=['POST'])
@operator_required
def api_validate_all_cookies(cid):
    """Replay all captured cookies for a campaign."""
    Campaign.query.get_or_404(cid)
    cookies = CapturedCookie.query.filter_by(campaign_id=cid).all()
    if not cookies:
        return jsonify({'error': 'No cookies found'}), 404

    results = []
    for c in cookies:
        result = validate_captured_cookie(c.id)
        results.append({
            'cookie_id': c.id,
            'cookie_name': c.cookie_name,
            'valid': result.get('valid'),
            'error': result.get('error'),
            'status_code': result.get('status_code'),
        })

    valid_count = sum(1 for r in results if r['valid'])
    invalid_count = len(results) - valid_count
    log_audit('cookie_validate_all', details={
        'campaign_id': cid, 'total': len(results),
        'valid': valid_count, 'invalid': invalid_count,
    })
    return jsonify({
        'total': len(results),
        'valid': valid_count,
        'invalid': invalid_count,
        'results': results,
    })


# ---------------------------------------------------------------------------
# Full campaign info view
# ---------------------------------------------------------------------------
@campaigns_admin_bp.route('/admin/campaign/<int:cid>/edit', methods=['GET', 'POST'])
@operator_required
def admin_campaign_edit(cid):
    """Central edit page for all pre-launch campaign settings."""
    campaign = Campaign.query.get_or_404(cid)
    current_user = getattr(g, 'current_user', None)
    is_admin = current_user and current_user.role == 'admin'

    if request.method == 'POST':
        campaign.name = request.form['name']
        campaign.subject = request.form['subject']
        campaign.body_html = request.form['body_html']
        campaign.template_html = request.form['body_html']
        campaign.landing_html = request.form['landing_html']

        sending_profile_id = request.form.get('sending_profile_id')
        campaign.sending_profile_id = int(sending_profile_id) if sending_profile_id else None

        # Recipients: replace list if provided
        recipients_text = request.form.get('recipients', '').strip()
        if recipients_text:
            Recipient.query.filter_by(campaign_id=cid).delete()
            for line in recipients_text.splitlines():
                email = line.strip()
                if email:
                    db.session.add(Recipient(campaign_id=cid, email=email))

        # Flow
        from datetime import datetime as _dt
        flow_type = request.form.get('flow_type', 'single_step')
        if flow_type == 'reverse_proxy' and not is_admin:
            flash('Reverse proxy campaigns are restricted to administrators.', 'danger')
            return redirect(url_for('campaigns_admin.admin_campaign_edit', cid=cid))
        campaign.flow_type = flow_type

        flow_config = campaign.get_flow_config() or {}
        flow_config.update({
            'redirect_url': request.form.get('flow_redirect_url', 'https://en.wikipedia.org/wiki/Phishing').strip(),
            'mfa_title': request.form.get('flow_mfa_title', 'Two-Factor Authentication').strip(),
            'success_message': request.form.get('flow_success_message', 'This was an authorized phishing simulation.').strip(),
            'training_enabled': request.form.get('training_enabled') == 'on',
            'training_url': request.form.get('training_url', '').strip(),
            'training_duration_seconds': int(request.form.get('training_duration_seconds') or 30),
            'qr_code_enabled': request.form.get('qr_code_enabled') == 'on',
        })
        if flow_type == 'reverse_proxy':
            target_url = request.form.get('proxy_target_url', '').strip()
            if target_url:
                flow_config['target_url'] = target_url
                flow_config['upstream_proxy'] = request.form.get('proxy_upstream_proxy', '').strip()
                flow_config['tls_fingerprint'] = request.form.get('proxy_tls_fingerprint', '').strip() or None
                flow_config['capture_credentials'] = request.form.get('proxy_capture_credentials') == 'on'
                flow_config['capture_cookies'] = request.form.get('proxy_capture_cookies') == 'on'
                flow_config['mfa_relay_enabled'] = request.form.get('proxy_mfa_relay_enabled') == 'on'

        # OAuth
        oauth_provider = request.form.get('oauth_provider', '').strip()
        if oauth_provider:
            oauth_cfg = {
                'provider': oauth_provider,
                'authorization_endpoint': request.form.get('oauth_authorization_endpoint', '').strip(),
                'token_endpoint': request.form.get('oauth_token_endpoint', '').strip(),
                'client_id': request.form.get('oauth_client_id', '').strip(),
                'client_secret': request.form.get('oauth_client_secret', '').strip(),
                'redirect_uri': request.form.get('oauth_redirect_uri', '').strip(),
                'scope': request.form.get('oauth_scope', '').strip(),
                'auto_exchange': request.form.get('oauth_auto_exchange') == 'on',
            }
            raw_extra = request.form.get('oauth_extra_params', '').strip()
            extra_params = {}
            if raw_extra:
                for line in raw_extra.splitlines():
                    line = line.strip()
                    if '=' in line:
                        k, v = line.split('=', 1)
                        extra_params[k.strip()] = v.strip()
            if extra_params:
                oauth_cfg['extra_params'] = extra_params
            flow_config['oauth'] = oauth_cfg
        elif 'oauth' in flow_config:
            del flow_config['oauth']

        # SAML
        saml_real_acs = request.form.get('saml_real_acs_url', '').strip()
        if saml_real_acs:
            flow_config['saml'] = {'real_acs_url': saml_real_acs}
        elif 'saml' in flow_config:
            del flow_config['saml']

        campaign.set_flow_config(flow_config)

        # Schedule
        def _parse_dt(value):
            if not value:
                return None
            try:
                return _dt.fromisoformat(value)
            except Exception:
                return None
        campaign.scheduled_at = _parse_dt(request.form.get('schedule_datetime', '').strip())
        campaign.schedule_cron = request.form.get('schedule_cron', '').strip() or None
        campaign.schedule_timezone = request.form.get('schedule_timezone', 'UTC').strip()
        campaign.schedule_enabled = request.form.get('schedule_enabled') == 'on'

        # Deliverability
        campaign.domain_reputation_check_enabled = request.form.get('domain_reputation_check_enabled') == 'on'
        campaign.store_credentials_plaintext = request.form.get('store_credentials_plaintext') == 'on'
        sender_rotation_pool_id = request.form.get('sender_rotation_pool_id')
        campaign.sender_rotation_pool_id = int(sender_rotation_pool_id) if sender_rotation_pool_id else None

        # Calendar
        campaign.calendar_invite = request.form.get('calendar_invite') == '1'
        campaign.calendar_event_title = request.form.get('calendar_event_title', '').strip() or None
        campaign.calendar_event_location = request.form.get('calendar_event_location', '').strip() or None
        campaign.calendar_event_start = _parse_dt(request.form.get('calendar_event_start', '').strip())
        campaign.calendar_event_end = _parse_dt(request.form.get('calendar_event_end', '').strip())

        db.session.commit()
        flash('Campaign updated.', 'success')
        return redirect(url_for('campaigns_admin.admin_campaign_edit', cid=cid))

    sps = SendingProfile.query.all()
    rotation_pools = SenderRotationPool.query.order_by(SenderRotationPool.name).all()
    subsidiaries = Subsidiary.query.order_by(Subsidiary.name).all()
    email_templates = EmailTemplate.query.order_by(EmailTemplate.name).all()
    proxy_domains = ProxyDomain.query.order_by(ProxyDomain.domain).all()
    recipients = Recipient.query.filter_by(campaign_id=cid).order_by(Recipient.email).all()
    recipients_text = '\n'.join(r.email for r in recipients)
    flow_config = campaign.get_flow_config()
    return render_template(
        'campaign_edit.html',
        campaign=campaign,
        sending_profiles=sps,
        rotation_pools=rotation_pools,
        subsidiaries=subsidiaries,
        email_templates=email_templates,
        proxy_domains=proxy_domains,
        recipients_text=recipients_text,
        flow_config=flow_config,
        is_admin=is_admin,
    )


@campaigns_admin_bp.route('/admin/campaign/<int:cid>/validate')
@operator_required
def admin_campaign_validate(cid):
    """Pre-flight validation panel with a structured launch checklist."""
    campaign = Campaign.query.get_or_404(cid)
    result = validate_campaign_before_launch(cid)
    return render_template('campaign_validate.html', campaign=campaign, result=result)


@campaigns_admin_bp.route('/admin/campaign/<int:cid>/info')
@viewer_required
def admin_campaign_info(cid):
    """Comprehensive single-page view of all campaign data."""
    from dropoutjeep_lib.utils.risk import recipient_risk_score, campaign_risk_summary
    from dropoutjeep_lib.utils.funnel import compute_funnel
    from dropoutjeep_lib.utils.payload_staging import list_payloads

    campaign = Campaign.query.get_or_404(cid)
    recipients = Recipient.query.filter_by(campaign_id=cid).order_by(Recipient.created_at.desc()).all()

    # Event stats
    event_counts = {}
    for etype in ['open', 'click', 'visit', 'credential_attempt', 'mfa_attempt',
                  'mfa_prompt', 'flow_complete', 'training_started', 'training_completed',
                  'calendar_download', 'fingerprint', 'html_smuggle_download',
                  'exfil_http', 'exfil_dns', 'user_report']:
        event_counts[etype] = Event.query.filter_by(campaign_id=cid, event_type=etype).count()

    # Credentials
    from dropoutjeep_lib.models import CapturedCredential, CapturedCookie, CapturedOAuthToken, SamlCapture, Payload
    credentials = CapturedCredential.query.filter_by(campaign_id=cid) \
        .order_by(CapturedCredential.captured_at.desc()).all()
    cookies = CapturedCookie.query.filter_by(campaign_id=cid) \
        .order_by(CapturedCookie.captured_at.desc()).all()
    oauth_tokens = CapturedOAuthToken.query.filter_by(campaign_id=cid) \
        .order_by(CapturedOAuthToken.captured_at.desc()).all()
    saml_captures = SamlCapture.query.filter_by(campaign_id=cid) \
        .order_by(SamlCapture.captured_at.desc()).all()
    payloads = Payload.query.filter_by(campaign_id=cid).all()

    # Risk
    risk = campaign_risk_summary(cid)
    risk_map = {r.id: recipient_risk_score(r.id) for r in recipients[:50]}

    # Funnel
    funnel = compute_funnel(cid)

    # Flow config
    flow_config = campaign.get_flow_config()

    return render_template(
        'campaign_info.html',
        campaign=campaign,
        recipients=recipients,
        event_counts=event_counts,
        credentials=credentials,
        cookies=cookies,
        oauth_tokens=oauth_tokens,
        saml_captures=saml_captures,
        payloads=payloads,
        risk=risk,
        risk_map=risk_map,
        funnel=funnel,
        flow_config=flow_config,
    )


@campaigns_admin_bp.route('/api/campaign/<int:campaign_id>/oauth-tokens')
@viewer_required
def api_campaign_oauth_tokens(campaign_id):
    """List captured OAuth tokens for a campaign with parsed id_token claims."""
    Campaign.query.get_or_404(campaign_id)
    tokens = CapturedOAuthToken.query.filter_by(campaign_id=campaign_id) \
        .order_by(CapturedOAuthToken.captured_at.desc()).all()
    return jsonify({
        'campaign_id': campaign_id,
        'tokens': [
            {
                'id': t.id,
                'recipient_id': t.recipient_id,
                'recipient_token': t.recipient_token,
                'provider': t.provider,
                'access_token': t.access_token,
                'refresh_token': t.refresh_token,
                'id_token': t.id_token,
                'id_token_claims': t.parsed_id_token_claims(),
                'token_type': t.token_type,
                'expires_in': t.expires_in,
                'scope': t.scope,
                'captured_at': t.captured_at.isoformat() if t.captured_at else None,
            }
            for t in tokens
        ],
    })


# ---------------------------------------------------------------------------
# OAuth2 flow configuration UI
# ---------------------------------------------------------------------------
@campaigns_admin_bp.route('/admin/campaign/<int:cid>/oauth-config', methods=['GET', 'POST'])
@operator_required
def admin_oauth_config(cid):
    """View and save OAuth2 phishing flow configuration for a campaign."""
    campaign = Campaign.query.get_or_404(cid)
    flow_cfg = campaign.get_flow_config()
    oauth_cfg = flow_cfg.get('oauth', {})

    if request.method == 'POST':
        # Parse extra_params from textarea (key=value lines)
        raw_extra = request.form.get('extra_params', '').strip()
        extra_params = {}
        if raw_extra:
            for line in raw_extra.splitlines():
                line = line.strip()
                if '=' in line:
                    k, v = line.split('=', 1)
                    extra_params[k.strip()] = v.strip()

        oauth_cfg = {
            'provider': request.form.get('provider', '').strip(),
            'authorization_endpoint': request.form.get('authorization_endpoint', '').strip(),
            'client_id': request.form.get('client_id', '').strip(),
            'redirect_uri': request.form.get('redirect_uri', '').strip(),
            'scope': request.form.get('scope', '').strip(),
            'auto_exchange': request.form.get('auto_exchange') == 'on',
            'token_endpoint': request.form.get('token_endpoint', '').strip(),
            'client_secret': request.form.get('client_secret', '').strip(),
            'extra_params': extra_params if extra_params else None,
        }
        flow_cfg['oauth'] = oauth_cfg
        campaign.set_flow_config(flow_cfg)
        db.session.commit()
        log_audit('oauth_config_update', details={'campaign_id': cid})
        flash('OAuth2 flow configuration saved.', 'success')
        return redirect(url_for('campaigns_admin.admin_oauth_config', cid=cid))

    # Build extra_params textarea content
    extra_params_text = ''
    if oauth_cfg.get('extra_params'):
        extra_params_text = '\n'.join(
            f"{k}={v}" for k, v in oauth_cfg['extra_params'].items()
        )

    from flask import current_app
    base_url = get_base_url('http://localhost:5000')
    return render_template(
        'admin_oauth_config.html',
        campaign=campaign,
        oauth_cfg=oauth_cfg,
        extra_params_text=extra_params_text,
        base_url=base_url,
    )


@campaigns_admin_bp.route('/admin/campaign/<int:cid>/oauth-tokens')
@viewer_required
def admin_oauth_tokens(cid):
    """Render the captured OAuth tokens page for a campaign."""
    campaign = Campaign.query.get_or_404(cid)
    tokens = CapturedOAuthToken.query.filter_by(campaign_id=cid) \
        .order_by(CapturedOAuthToken.captured_at.desc()).all()
    return render_template(
        'campaign_oauth_tokens.html',
        campaign=campaign,
        tokens=tokens,
    )


# ---------------------------------------------------------------------------
# SAML/SSO relay configuration UI
# ---------------------------------------------------------------------------
@campaigns_admin_bp.route('/admin/campaign/<int:cid>/saml-config', methods=['GET', 'POST'])
@operator_required
def admin_saml_config(cid):
    """View and save SAML/SSO relay configuration for a campaign."""
    campaign = Campaign.query.get_or_404(cid)
    flow_cfg = campaign.get_flow_config()
    saml_cfg = flow_cfg.get('saml', {})

    if request.method == 'POST':
        saml_cfg = {
            'real_acs_url': request.form.get('real_acs_url', '').strip(),
        }
        flow_cfg['saml'] = saml_cfg
        campaign.set_flow_config(flow_cfg)
        db.session.commit()
        log_audit('saml_config_update', details={'campaign_id': cid})
        flash('SAML/SSO relay configuration saved.', 'success')
        return redirect(url_for('campaigns_admin.admin_saml_config', cid=cid))

    from flask import current_app
    base_url = get_base_url('http://localhost:5000')
    return render_template(
        'admin_saml_config.html',
        campaign=campaign,
        saml_cfg=saml_cfg,
        base_url=base_url,
    )


@campaigns_admin_bp.route('/admin/campaign/<int:cid>/saml-captures')
@viewer_required
def admin_saml_captures(cid):
    """Render the captured SAML responses page for a campaign."""
    from dropoutjeep_lib.utils.saml_relay import _b64_decode_saml
    campaign = Campaign.query.get_or_404(cid)
    captures = SamlCapture.query.filter_by(campaign_id=cid) \
        .order_by(SamlCapture.captured_at.desc()).all()
    for c in captures:
        c.saml_response_decoded = _b64_decode_saml(c.saml_response) if c.saml_response else None
    return render_template(
        'campaign_saml_captures.html',
        campaign=campaign,
        captures=captures,
    )


# ---------------------------------------------------------------------------
# Payload management UI
# ---------------------------------------------------------------------------
@campaigns_admin_bp.route('/admin/campaign/<int:cid>/payloads')
@operator_required
def admin_payloads(cid):
    """View and manage staged payloads for a campaign."""
    from dropoutjeep_lib.utils.payload_staging import list_payloads
    campaign = Campaign.query.get_or_404(cid)
    payloads = list_payloads(campaign.id)
    return render_template(
        'payloads.html',
        campaign=campaign,
        payloads=payloads,
    )


# ---------------------------------------------------------------------------
# SAML relay trigger
# ---------------------------------------------------------------------------
@campaigns_admin_bp.route('/admin/campaign/<int:cid>/saml-relay/<int:capture_id>', methods=['POST'])
@operator_required
def admin_saml_relay(cid, capture_id):
    """Manually relay a captured SAMLResponse to the real ACS URL."""
    from dropoutjeep_lib.utils.saml_relay import relay_saml_response
    campaign = Campaign.query.get_or_404(cid)
    capture = SamlCapture.query.get_or_404(capture_id)
    if capture.campaign_id != cid:
        abort(400)

    flow_cfg = campaign.get_flow_config()
    real_acs = flow_cfg.get('saml', {}).get('real_acs_url')
    if not real_acs:
        flash('No real ACS URL configured for this campaign. Update SAML config first.', 'warning')
        return redirect(url_for('campaigns_admin.admin_saml_captures', cid=cid))

    ok, status_code = relay_saml_response(capture, real_acs)
    if ok:
        flash(f'SAML response relayed successfully. ACS returned HTTP {status_code}.', 'success')
    else:
        flash('SAML relay failed. Check logs for details.', 'danger')

    log_audit('saml_manual_relay', details={
        'campaign_id': cid, 'capture_id': capture_id, 'status': status_code
    })
    return redirect(url_for('campaigns_admin.admin_saml_captures', cid=cid))


# ---------------------------------------------------------------------------
# Polymorphic payload preview
# ---------------------------------------------------------------------------
@campaigns_admin_bp.route('/admin/campaign/<int:cid>/payloads/<int:pid>/preview')
@operator_required
def admin_payload_polymorph_preview(cid, pid):
    """Preview polymorphic variants of a payload for sample recipient tokens."""
    from dropoutjeep_lib.utils.polymorphic_payloads import polymorph_payload, _unique_marker
    from dropoutjeep_lib.utils.payload_staging import get_payload_content
    campaign = Campaign.query.get_or_404(cid)
    payload = Payload.query.get_or_404(pid)
    if payload.campaign_id != cid:
        abort(400)

    sample_tokens = [
        'aaaaaaaaaaaaaaaa',
        'bbbbbbbbbbbbbbbb',
        'cccccccccccccccc',
    ]

    variants = []
    content = payload.get_content()
    for token in sample_tokens:
        marker = _unique_marker(token)
        polymorphed = polymorph_payload(content, payload.extension, token)
        variants.append({
            'token': token,
            'marker': marker,
            'size_original': len(content),
            'size_polymorphed': len(polymorphed),
            'delta': len(polymorphed) - len(content),
        })

    return jsonify({
        'payload_id': payload.id,
        'filename': payload.filename,
        'extension': payload.extension,
        'per_recipient': payload.per_recipient,
        'variants': variants,
    })


# ---------------------------------------------------------------------------
# MFA relay stats UI
# ---------------------------------------------------------------------------
@campaigns_admin_bp.route('/admin/campaign/<int:cid>/mfa-relay-stats')
@viewer_required
def admin_mfa_relay_stats(cid):
    """View active MFA relay sessions for a campaign."""
    from dropoutjeep_lib.models import MfaRelayState
    from dropoutjeep_lib.proxy.mfa_relay import DEFAULT_TTL_SECONDS
    campaign = Campaign.query.get_or_404(cid)
    all_states = MfaRelayState.query.filter_by(campaign_id=cid) \
        .order_by(MfaRelayState.created_at.desc()).all()
    active = [s for s in all_states if not s.is_expired()]
    expired_count = len(all_states) - len(active)
    unique_tokens = len({s.recipient_token for s in all_states if s.recipient_token})
    return render_template(
        'mfa_relay_stats.html',
        campaign=campaign,
        all_states=all_states,
        active=active,
        expired_count=expired_count,
        unique_tokens=unique_tokens,
        ttl=DEFAULT_TTL_SECONDS,
    )


@campaigns_admin_bp.route('/admin/campaign/<int:cid>/qr')
@viewer_required
def admin_campaign_qr(cid):
    """Render per-recipient QR codes for a campaign."""
    from dropoutjeep_lib.utils.qr_codes import build_recipient_qr_img

    campaign = Campaign.query.get_or_404(cid)
    recipients = Recipient.query.filter_by(campaign_id=cid).order_by(Recipient.email).all()
    base_url = get_base_url('')
    qr_images = {}
    for r in recipients:
        try:
            qr_images[r.id] = build_recipient_qr_img(campaign, r, base_url)
        except Exception as exc:
            qr_images[r.id] = f'<p class="text-brutal-red">QR error: {exc}</p>'
    return render_template(
        'campaign_qr.html',
        campaign=campaign,
        recipients=recipients,
        qr_images=qr_images,
    )
