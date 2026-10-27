from flask import Blueprint, jsonify, request

from dropoutjeep_lib import db
from dropoutjeep_lib.models import SendingProfile
from dropoutjeep_lib.utils.auth import viewer_required, operator_required, api_token_required

sending_profiles_bp = Blueprint('sending_profiles', __name__, url_prefix='/sending_profiles')
sending_profiles_v1_bp = Blueprint('sending_profiles_v1', __name__, url_prefix='/api/v1/sending-profiles')


def _profile_to_dict(p: SendingProfile) -> dict:
    return {
        'id': p.id,
        'name': p.name,
        'smtp_host': p.smtp_host,
        'smtp_port': p.smtp_port,
        'smtp_user': p.smtp_user,
        'use_tls': p.use_tls,
        'rate_per_minute': p.rate_per_minute,
        'subsidiary_id': p.subsidiary_id,
        'rate_profile_id': p.rate_profile_id,
        'is_active': p.is_active,
        'created_at': p.created_at.isoformat() if p.created_at else None,
        'updated_at': p.updated_at.isoformat() if p.updated_at else None,
    }


def _update_profile_from_data(p: SendingProfile, data: dict):
    if 'name' in data:
        p.name = data['name']
    if 'smtp_host' in data:
        p.smtp_host = data.get('smtp_host')
    if 'smtp_port' in data:
        p.smtp_port = int(data.get('smtp_port', 25) or 25)
    if 'smtp_user' in data:
        p.smtp_user = data.get('smtp_user')
    if 'smtp_pass' in data:
        p.set_smtp_pass(data.get('smtp_pass'))
    if 'use_tls' in data:
        p.use_tls = data.get('use_tls', True) in (True, 'on', 'true', '1')
    if 'rate_per_minute' in data:
        p.rate_per_minute = int(data.get('rate_per_minute', 60))
    if 'subsidiary_id' in data:
        p.subsidiary_id = data.get('subsidiary_id')
    if 'rate_profile_id' in data:
        p.rate_profile_id = data.get('rate_profile_id')


@sending_profiles_bp.route('/', methods=['GET'])
@viewer_required
def list_profiles():
    profiles = SendingProfile.query.all()
    return jsonify([
        {"id": p.id, "name": p.name, "host": p.smtp_host,
         "port": p.smtp_port, "subsidiary_id": p.subsidiary_id}
        for p in profiles
    ])


@sending_profiles_bp.route('/', methods=['POST'])
@operator_required
def create_profile():
    data = request.get_json() or request.form
    p = SendingProfile(
        name=data['name'],
        smtp_host=data.get('smtp_host'),
        smtp_port=int(data.get('smtp_port', 25) or 25),
        smtp_user=data.get('smtp_user'),
        use_tls=data.get('use_tls', True) in (True, 'on', 'true', '1'),
        subsidiary_id=data.get('subsidiary_id')
    )
    p.set_smtp_pass(data.get('smtp_pass'))
    db.session.add(p)
    db.session.commit()
    return jsonify({"status": "created", "id": p.id}), 201


# ---------------------------------------------------------------------------
# API v1 sending-profile endpoints
# ---------------------------------------------------------------------------

@sending_profiles_v1_bp.route('/', methods=['GET'])
@api_token_required('sending_profiles:read')
@viewer_required
def list_profiles_v1():
    profiles = SendingProfile.query.all()
    return jsonify([_profile_to_dict(p) for p in profiles])


@sending_profiles_v1_bp.route('/', methods=['POST'])
@api_token_required('sending_profiles:write')
@operator_required
def create_profile_v1():
    data = request.get_json() or request.form
    p = SendingProfile()
    _update_profile_from_data(p, data)
    db.session.add(p)
    db.session.commit()
    return jsonify({'status': 'created', 'profile': _profile_to_dict(p)}), 201


@sending_profiles_v1_bp.route('/<int:profile_id>', methods=['GET'])
@api_token_required('sending_profiles:read')
@viewer_required
def get_profile_v1(profile_id):
    p = SendingProfile.query.get_or_404(profile_id)
    return jsonify(_profile_to_dict(p))


@sending_profiles_v1_bp.route('/<int:profile_id>', methods=['PATCH'])
@api_token_required('sending_profiles:write')
@operator_required
def update_profile_v1(profile_id):
    p = SendingProfile.query.get_or_404(profile_id)
    data = request.get_json(silent=True) or request.form or {}
    _update_profile_from_data(p, data)
    db.session.commit()
    return jsonify({'status': 'updated', 'profile': _profile_to_dict(p)})


@sending_profiles_v1_bp.route('/<int:profile_id>', methods=['DELETE'])
@api_token_required('sending_profiles:write')
@operator_required
def delete_profile_v1(profile_id):
    p = SendingProfile.query.get_or_404(profile_id)
    db.session.delete(p)
    db.session.commit()
    return jsonify({'status': 'deleted', 'id': profile_id})
