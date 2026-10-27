from flask import Blueprint

# Public blueprints registered by the main Flask app.
campaigns_bp = Blueprint('campaigns', __name__)
events_bp = Blueprint('events', __name__)
recipients_bp = Blueprint('recipients', __name__)
subsidiaries_bp = Blueprint('subsidiaries', __name__)
sending_profiles_bp = Blueprint('sending_profiles', __name__)
urlcheck_bp = Blueprint('urlcheck', __name__)
bounce_bp = Blueprint('bounce', __name__)
landing_bp = Blueprint('landing', __name__)

# Admin / tracking blueprints are defined in their own modules.  They are made
# available through lazy attributes so importing this package does not trigger
# circular imports (e.g. urlcheck -> routes __init__ -> admin -> domain_reputation).
_BLUEPRINT_MODULES = {
    'admin_bp': 'admin',
    'campaigns_admin_bp': 'campaigns_admin',
    'proxy_admin_bp': 'proxy_admin',
    'sending_admin_bp': 'sending_admin',
    'webhooks_bp': 'webhooks',
    'templates_admin_bp': 'templates_admin',
    'auto_reply_bp': 'auto_reply',
    'tracking_bp': 'tracking',
}


def __getattr__(name):
    if name in _BLUEPRINT_MODULES:
        module_name = _BLUEPRINT_MODULES[name]
        module = __import__(f'dropoutjeep_lib.routes.{module_name}', fromlist=[name])
        return getattr(module, name)
    raise AttributeError(f"module 'dropoutjeep_lib.routes' has no attribute '{name}'")
