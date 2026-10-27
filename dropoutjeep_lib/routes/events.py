from flask import Blueprint, jsonify, request, render_template

from dropoutjeep_lib.models import Event
from dropoutjeep_lib.utils.auth import viewer_required

events_bp = Blueprint('events', __name__, url_prefix='/events')


@events_bp.route('/', methods=['GET'])
@viewer_required
def list_events():
    event_type = request.args.get('event_type', '').strip()
    query = Event.query.order_by(Event.created_at.desc())
    if event_type:
        query = query.filter_by(event_type=event_type)
    events = query.limit(500).all()

    if request.headers.get('Accept') == 'application/json' or request.args.get('format') == 'json':
        return jsonify([
            {"id": e.id, "type": e.event_type, "campaign_id": e.campaign_id,
             "created_at": e.created_at, "meta": e.meta}
            for e in events
        ])
    return render_template('events.html', events=events)
