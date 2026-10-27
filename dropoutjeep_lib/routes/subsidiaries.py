from flask import Blueprint, jsonify, request, render_template

from dropoutjeep_lib import db
from dropoutjeep_lib.models import Subsidiary, SendingProfile
from dropoutjeep_lib.utils.auth import viewer_required, operator_required
from dropoutjeep_lib.utils.validator import check_spf, check_dkim_selector, validate_smtp_relay
from dropoutjeep_lib.utils.dkim_utils import check_dmarc

subsidiaries_bp = Blueprint('subsidiaries', __name__, url_prefix='/subsidiaries')


@subsidiaries_bp.route('/', methods=['GET'])
@viewer_required
def list_subsidiaries():
    subs = Subsidiary.query.all()
    return jsonify([
        {"id": s.id, "name": s.name, "domain": s.sending_domain}
        for s in subs
    ])


@subsidiaries_bp.route('/', methods=['POST'])
@operator_required
def add_subsidiary():
    data = request.get_json() or request.form
    new_s = Subsidiary(
        name=data['name'],
        sending_domain=data['sending_domain'],
        display_name=data['display_name'],
        from_address=data['from_address'],
        bounce_subdomain=data.get('bounce_subdomain'),
        dkim_selector=data.get('dkim_selector')
    )
    new_s.set_dkim_private_key(data.get('dkim_private_key'))
    db.session.add(new_s)
    db.session.commit()
    return jsonify({"status": "created", "id": new_s.id}), 201


@subsidiaries_bp.route('/sending_profile/<int:sp_id>/deliverability', methods=['GET'])
@viewer_required
def deliverability(sp_id):
    """Quick DNS + SMTP deliverability check for a sending profile."""
    sp = SendingProfile.query.get_or_404(sp_id)
    domain = sp.subsidiary.sending_domain if sp.subsidiary else None
    selector = sp.subsidiary.dkim_selector if sp.subsidiary else None
    spf_ok, spf_txt = check_spf(domain) if domain else (False, "No domain")
    dkim_ok, dkim_txt = check_dkim_selector(domain, selector) if domain and selector else (False, "No domain/selector")
    dmarc_ok, dmarc_txt = check_dmarc(domain) if domain else (False, "No domain")
    smtp_ok, smtp_txt = validate_smtp_relay(sp.smtp_host or '', sp.smtp_port or 587,
                                            sp.smtp_user, sp.get_smtp_pass())
    return render_template(
        'deliverability_result.html',
        sp=sp, domain=domain, selector=selector,
        result={
            'spf': {'ok': spf_ok, 'txt': spf_txt},
            'dkim': {'ok': dkim_ok, 'txt': dkim_txt},
            'dmarc': {'ok': dmarc_ok, 'txt': dmarc_txt},
            'smtp': {'ok': smtp_ok, 'txt': smtp_txt},
        }
    )
