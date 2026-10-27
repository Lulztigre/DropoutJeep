"""Authentication, RBAC, and audit helpers for DropoutJeep."""

from functools import wraps

from flask import (
    abort, g, jsonify, redirect, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from dropoutjeep_lib import db
from dropoutjeep_lib.models import AuditLog, User


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def _unauthorized_response():
    if request.path.startswith('/api') or request.is_json:
        return jsonify({'error': 'unauthorized'}), 401
    return redirect(url_for('admin_login'))


def _forbidden_response():
    if request.path.startswith('/api') or request.is_json:
        return jsonify({'error': 'forbidden'}), 403
    return abort(403)


def get_current_user() -> User | None:
    uid = session.get('user_id')
    if not uid:
        return None
    return User.query.get(uid)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = getattr(g, 'current_user', None)
        if not user:
            user = get_current_user()
        if not user:
            return _unauthorized_response()
        g.current_user = user
        return view(*args, **kwargs)
    return wrapped


def require_roles(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            user = g.current_user
            if not user.is_active:
                return _forbidden_response()
            if user.role not in roles and user.role != 'admin':
                return _forbidden_response()
            return view(*args, **kwargs)
        return wrapped
    return decorator


def admin_required(view):
    return require_roles('admin')(view)


def operator_required(view):
    return require_roles('admin', 'operator')(view)


def viewer_required(view):
    return require_roles('admin', 'operator', 'viewer')(view)


def api_token_required(*scopes):
    """Decorator that accepts either a session user or a valid API token.

    If an Authorization: Bearer <token> header is present, the token is
    validated (active, not expired, required scopes present). Otherwise the
    normal session-based auth chain is used.
    """
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            from dropoutjeep_lib.models import ApiToken, User
            auth_header = request.headers.get('Authorization', '')
            if auth_header.lower().startswith('bearer '):
                token_plain = auth_header[7:].strip()
                if not token_plain:
                    return _unauthorized_response()
                import hashlib
                from datetime import datetime
                token_hash = hashlib.sha256(token_plain.encode()).hexdigest()
                token = ApiToken.query.filter_by(token_hash=token_hash, is_active=True).first()
                if not token:
                    return _unauthorized_response()
                if token.expires_at and token.expires_at < datetime.utcnow():
                    return _unauthorized_response()
                missing = [s for s in scopes if not token.has_scope(s)]
                if missing:
                    return _forbidden_response()
                token.last_used_at = datetime.utcnow()
                db.session.commit()
                g.api_token = token
                g.current_user = User.query.get(token.created_by_user_id) if token.created_by_user_id else None
                log_audit('api_token_used', f'token={token.name} path={request.path}')
                return view(*args, **kwargs)
            # No Bearer token: rely on session auth.
            user = get_current_user()
            if not user:
                return _unauthorized_response()
            g.current_user = user
            g.api_token = None
            return view(*args, **kwargs)
        return wrapped
    return decorator


def log_audit(action: str, details: str | None = None) -> AuditLog | None:
    user = getattr(g, 'current_user', None)
    entry = AuditLog(
        user_id=user.id if user else None,
        action=action,
        method=request.method,
        path=request.path,
        status_code=None,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:512],
        details=details,
    )
    db.session.add(entry)
    db.session.commit()
    return entry


def update_audit_status(audit_entry: AuditLog, status_code: int) -> None:
    if audit_entry:
        audit_entry.status_code = status_code
        db.session.commit()
