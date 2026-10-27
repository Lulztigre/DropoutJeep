from flask import Blueprint, render_template, request

from dropoutjeep_lib.utils.mailbox_fetcher import fetch_emails
from dropoutjeep_lib.utils.bounce_parser import parse_bounce
from dropoutjeep_lib.utils.auth import viewer_required, operator_required

bounce_bp = Blueprint('bounce', __name__, url_prefix='/admin/bounce')


@bounce_bp.route('/', methods=['GET'])
@viewer_required
def bounce_dashboard():
    return render_template('bounce.html')


@bounce_bp.route('/test', methods=['POST'])
@operator_required
def bounce_test():
    server = request.form['imap_server']
    user = request.form['imap_user']
    password = request.form['imap_pass']
    messages = fetch_emails(server, user, password)
    count = len(messages)
    for msg in messages:
        parse_bounce(msg)
    return render_template('bounce.html', message=f"{count} messages processed.")
