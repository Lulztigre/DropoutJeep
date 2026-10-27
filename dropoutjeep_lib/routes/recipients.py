"""API v1 recipient routes."""

import io
import re

from flask import Blueprint, g, jsonify, request

from dropoutjeep_lib import db
from dropoutjeep_lib.models import Campaign, Recipient
from dropoutjeep_lib.utils.auth import operator_required, api_token_required
from dropoutjeep_lib.utils.recipient_import import import_recipients

recipients_bp = Blueprint('recipients', __name__, url_prefix='/api/v1')

EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


def _validate_email(email: str) -> str | None:
    if not email:
        return 'email is required'
    if len(email) > 320:
        return 'email exceeds 320 characters'
    if not EMAIL_RE.match(email):
        return 'invalid email format'
    local, _, domain = email.rpartition('@')
    if not local or not domain or '.' not in domain:
        return 'invalid email domain'
    return None


def _import_recipients_json(campaign_id: int, items: list) -> dict:
    errors = []
    created = 0
    duplicates = 0
    seen = set()
    existing = {
        r.email.lower()
        for r in Recipient.query.filter_by(campaign_id=campaign_id).with_entities(Recipient.email).all()
    }

    for idx, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            errors.append({'row': idx, 'email': '', 'reason': 'expected object'})
            continue
        email = str(item.get('email', '')).strip()
        err = _validate_email(email)
        if err:
            errors.append({'row': idx, 'email': email, 'reason': err})
            continue
        email_lower = email.lower()
        if email_lower in seen or email_lower in existing:
            duplicates += 1
            continue
        seen.add(email_lower)
        r = Recipient(
            campaign_id=campaign_id,
            email=email,
            name=str(item.get('name', '')).strip() or None,
            external_id=str(item.get('external_id', '')).strip() or None,
        )
        db.session.add(r)
        created += 1

    db.session.commit()
    return {
        'created': created,
        'duplicates': duplicates,
        'errors': errors,
        'import_batch_id': None,
    }


@recipients_bp.route('/recipients/bulk', methods=['POST'])
@api_token_required('recipients:write')
@operator_required
def bulk_import_recipients():
    """Bulk import recipients via JSON list or CSV/XLSX file upload."""
    campaign_id = request.form.get('campaign_id') or request.args.get('campaign_id')
    if request.is_json:
        data = request.get_json(silent=True) or {}
        campaign_id = data.get('campaign_id')

    campaign = Campaign.query.get(campaign_id) if campaign_id else None
    if not campaign:
        return jsonify({'error': 'valid campaign_id is required'}), 400

    # File upload path.
    uploaded = request.files.get('file')
    if uploaded:
        result = import_recipients(
            uploaded.stream,
            uploaded.filename,
            campaign_id=campaign.id,
        )
        return jsonify({
            'status': 'imported',
            'campaign_id': campaign.id,
            'created': result['created'],
            'duplicates': result['duplicates'],
            'errors': result['errors'],
            'import_batch_id': result['import_batch_id'],
        })

    # JSON list path.
    data = request.get_json(silent=True) or {}
    items = data.get('recipients') if isinstance(data, dict) else None
    if not isinstance(items, list):
        return jsonify({'error': 'expected JSON {"recipients": [...]} or multipart file upload'}), 400

    result = _import_recipients_json(campaign.id, items)
    return jsonify({
        'status': 'imported',
        'campaign_id': campaign.id,
        **result,
    })
