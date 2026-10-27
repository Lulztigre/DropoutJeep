from flask import Blueprint, jsonify, request, abort

from dropoutjeep_lib import db
from dropoutjeep_lib.models import EmailTemplate, Campaign
from dropoutjeep_lib.utils.auth import viewer_required, operator_required, api_token_required

templates_bp = Blueprint('templates', __name__, url_prefix='/api/v1/templates')


ALL_SCOPES = ['templates:read', 'templates:write', 'campaigns:read', 'campaigns:write']


@templates_bp.route('/', methods=['GET'])
@api_token_required('templates:read')
@viewer_required
def list_templates():
    category = request.args.get('category')
    query = EmailTemplate.query.order_by(EmailTemplate.category, EmailTemplate.name)
    if category:
        query = query.filter_by(category=category)
    return jsonify([t.to_dict() for t in query.all()])


@templates_bp.route('/<int:template_id>', methods=['GET'])
@api_token_required('templates:read')
@viewer_required
def get_template(template_id):
    t = EmailTemplate.query.get_or_404(template_id)
    return jsonify(t.to_dict())


@templates_bp.route('/<int:template_id>/export', methods=['GET'])
@api_token_required('templates:read')
@viewer_required
def export_template(template_id):
    import json
    t = EmailTemplate.query.get_or_404(template_id)
    payload = t.to_dict()
    return jsonify(payload)


@templates_bp.route('/', methods=['POST'])
@api_token_required('templates:write')
@operator_required
def create_template():
    data = request.get_json() or request.form
    t = EmailTemplate(
        name=data.get('name', 'Untitled'),
        category=data.get('category', 'custom'),
        description=data.get('description', ''),
        subject=data.get('subject', ''),
        body_html=data.get('body_html', data.get('template_html', '')),
        landing_html=data.get('landing_html', ''),
        author=data.get('author'),
        source_url=data.get('source_url'),
        is_builtin=False,
    )
    tags = data.get('tags')
    if isinstance(tags, list):
        t.set_tags(tags)
    elif isinstance(tags, str):
        t.set_tags([tag.strip() for tag in tags.split(',') if tag.strip()])
    db.session.add(t)
    db.session.commit()
    return jsonify({'status': 'created', 'id': t.id}), 201


@templates_bp.route('/<int:template_id>/import-to-campaign/<int:campaign_id>', methods=['POST'])
@api_token_required('templates:write', 'campaigns:write')
@operator_required
def import_template_to_campaign(template_id, campaign_id):
    t = EmailTemplate.query.get_or_404(template_id)
    campaign = Campaign.query.get_or_404(campaign_id)
    campaign.subject = t.subject
    campaign.body_html = t.body_html
    campaign.template_html = t.body_html
    campaign.landing_html = t.landing_html
    db.session.commit()
    return jsonify({'status': 'imported', 'campaign_id': campaign.id, 'template_id': t.id})


@templates_bp.route('/<int:template_id>', methods=['DELETE'])
@api_token_required('templates:write')
@operator_required
def delete_template(template_id):
    t = EmailTemplate.query.get_or_404(template_id)
    if t.is_builtin:
        abort(400, description='Cannot delete built-in templates')
    db.session.delete(t)
    db.session.commit()
    return jsonify({'status': 'deleted', 'id': template_id})
