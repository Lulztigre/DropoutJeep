"""Admin UI and API routes for C2 connector configs."""

import json
import logging

from flask import (
    Blueprint, request, redirect, url_for, render_template, flash, jsonify, abort
)

from dropoutjeep_lib import db
from dropoutjeep_lib.models import C2ConnectorConfig
from dropoutjeep_lib.utils.auth import admin_required, api_token_required, operator_required

logger = logging.getLogger(__name__)

admin_c2_bp = Blueprint('c2_connectors', __name__, url_prefix='/admin/c2-connectors')
api_c2_bp = Blueprint('api_c2', __name__, url_prefix='/api/c2/connectors')

C2_CONNECTOR_TYPES = [
    ('cobalt_strike', 'Cobalt Strike'),
    ('mythic', 'Mythic'),
    ('sliver', 'Sliver'),
]


def _parse_config(data: dict) -> dict:
    """Extract known C2 config keys from form/JSON input."""
    config = {}
    for key in (
        'url', 'password', 'secret', 'team_server',
        'api_token', 'callback_uuid', 'grpc_url',
    ):
        value = data.get(key)
        if value is not None:
            config[key] = value.strip() if isinstance(value, str) else value
    return config


# ---------------------------------------------------------------------------
# Admin UI routes
# ---------------------------------------------------------------------------

@admin_c2_bp.route('/')
@admin_required
def admin_c2_connectors():
    connectors = C2ConnectorConfig.query.order_by(C2ConnectorConfig.created_at.desc()).all()
    return render_template('c2_connectors.html', connectors=connectors,
                           connector_types=C2_CONNECTOR_TYPES)


@admin_c2_bp.route('/new', methods=['POST'])
@admin_required
def admin_c2_connector_new():
    name = request.form.get('name', '').strip()
    ctype = request.form.get('type', '').strip()
    if not name or ctype not in [t[0] for t in C2_CONNECTOR_TYPES]:
        flash('Name and a valid connector type are required', 'danger')
        return redirect(url_for('c2_connectors.admin_c2_connectors'))

    conn = C2ConnectorConfig(name=name, type=ctype, is_active=True)
    conn.set_config(_parse_config(request.form))
    db.session.add(conn)
    db.session.commit()
    flash(f'C2 connector "{name}" created', 'success')
    return redirect(url_for('c2_connectors.admin_c2_connectors'))


@admin_c2_bp.route('/<int:connector_id>/toggle', methods=['POST'])
@admin_required
def admin_c2_connector_toggle(connector_id):
    conn = C2ConnectorConfig.query.get_or_404(connector_id)
    conn.is_active = not conn.is_active
    db.session.commit()
    flash(f'C2 connector "{conn.name}" {"enabled" if conn.is_active else "disabled"}', 'success')
    return redirect(url_for('c2_connectors.admin_c2_connectors'))


@admin_c2_bp.route('/<int:connector_id>/delete', methods=['POST'])
@admin_required
def admin_c2_connector_delete(connector_id):
    conn = C2ConnectorConfig.query.get_or_404(connector_id)
    db.session.delete(conn)
    db.session.commit()
    flash(f'C2 connector "{conn.name}" deleted', 'success')
    return redirect(url_for('c2_connectors.admin_c2_connectors'))


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

def _connector_to_dict(conn: C2ConnectorConfig) -> dict:
    return {
        'id': conn.id,
        'name': conn.name,
        'type': conn.type,
        'config': conn.get_config(),
        'is_active': conn.is_active,
        'created_at': conn.created_at.isoformat() if conn.created_at else None,
        'updated_at': conn.updated_at.isoformat() if conn.updated_at else None,
    }


@api_c2_bp.route('/', methods=['GET'])
@api_token_required('campaigns:read')
@operator_required
def api_c2_list():
    connectors = C2ConnectorConfig.query.order_by(C2ConnectorConfig.created_at.desc()).all()
    return jsonify([_connector_to_dict(c) for c in connectors])


@api_c2_bp.route('/', methods=['POST'])
@api_token_required('campaigns:write')
@operator_required
def api_c2_create():
    data = request.get_json(silent=True) or request.form or {}
    name = (data.get('name') or '').strip()
    ctype = (data.get('type') or '').strip()
    if not name or ctype not in [t[0] for t in C2_CONNECTOR_TYPES]:
        return jsonify({'error': 'name and valid type are required'}), 400

    conn = C2ConnectorConfig(name=name, type=ctype, is_active=bool(data.get('is_active', True)))
    conn.set_config(_parse_config(data))
    db.session.add(conn)
    db.session.commit()
    return jsonify(_connector_to_dict(conn)), 201


@api_c2_bp.route('/<int:connector_id>', methods=['GET'])
@api_token_required('campaigns:read')
@operator_required
def api_c2_get(connector_id):
    conn = C2ConnectorConfig.query.get_or_404(connector_id)
    return jsonify(_connector_to_dict(conn))


@api_c2_bp.route('/<int:connector_id>', methods=['PATCH'])
@api_token_required('campaigns:write')
@operator_required
def api_c2_update(connector_id):
    conn = C2ConnectorConfig.query.get_or_404(connector_id)
    data = request.get_json(silent=True) or request.form or {}

    if 'name' in data:
        conn.name = (data['name'] or '').strip()
    if 'type' in data:
        ctype = (data['type'] or '').strip()
        if ctype not in [t[0] for t in C2_CONNECTOR_TYPES]:
            return jsonify({'error': 'invalid connector type'}), 400
        conn.type = ctype
    if 'is_active' in data:
        conn.is_active = bool(data['is_active'])
    if any(k in data for k in ('url', 'password', 'secret', 'team_server',
                                'api_token', 'callback_uuid', 'grpc_url')):
        config = conn.get_config()
        config.update(_parse_config(data))
        conn.set_config(config)

    db.session.commit()
    return jsonify(_connector_to_dict(conn))


@api_c2_bp.route('/<int:connector_id>', methods=['DELETE'])
@api_token_required('campaigns:write')
@operator_required
def api_c2_delete(connector_id):
    conn = C2ConnectorConfig.query.get_or_404(connector_id)
    db.session.delete(conn)
    db.session.commit()
    return jsonify({'status': 'deleted', 'id': connector_id})
