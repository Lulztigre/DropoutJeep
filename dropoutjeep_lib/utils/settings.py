"""Runtime settings helper.

The Setting table stores admin-editable values from /admin/settings.
This helper lets the rest of the app read those values while still
falling back to environment variables or a hard-coded default.

Must be called inside a Flask app context because it queries the DB.
"""

import os


def get_setting(key: str, default=None):
    """Return a Setting value, env fallback, or default.

    Keys are stored lowercase in the Setting table. Environment fallback
    uses the uppercase version of the key.
    """
    from dropoutjeep_lib.models import Setting

    row = Setting.query.filter_by(key=key.lower()).first()
    if row and row.value:
        return row.value

    env_key = key.upper()
    if env_key in os.environ:
        return os.environ[env_key]

    return default


def get_setting_int(key: str, default: int = 0) -> int:
    """Return a setting as int."""
    value = get_setting(key)
    if value is None or value == '':
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def get_setting_bool(key: str, default: bool = False) -> bool:
    """Return a setting as bool."""
    value = get_setting(key)
    if value is None:
        return default
    return str(value).lower() in ('1', 'true', 'yes', 'on')


def get_base_url(default: str = 'http://localhost:5000') -> str:
    """Return the configured public base URL."""
    from flask import current_app
    return get_setting('base_url') or current_app.config.get('BASE_URL') or default
