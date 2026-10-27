from flask import Blueprint, request, abort, jsonify, render_template_string

from dropoutjeep_lib.models import Campaign, Recipient, Event
from dropoutjeep_lib import db

landing_bp = Blueprint('landing', __name__)


@landing_bp.route('/api/landing_probe', methods=['POST'])
def landing_probe():
    """Receive a lightweight JS beacon from landing pages."""
    try:
        data = request.get_json(silent=True) or {}
        token = data.get('token')
        if token:
            recipient = Recipient.query.filter_by(token=token).first()
            event = Event(
                campaign_id=recipient.campaign_id if recipient else None,
                recipient_id=recipient.id if recipient else None,
                event_type='probe',
                meta=str({
                    'mouse': data.get('mouse'),
                    'webdriver': data.get('probe', {}).get('webdriver'),
                    'ua': request.headers.get('User-Agent', '')
                })
            )
            db.session.add(event)
            db.session.commit()
        return ('', 204)
    except Exception as e:
        return jsonify({'error': str(e)}), 400
