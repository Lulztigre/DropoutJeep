"""SQLite pragmas applied to every engine in the app and the standalone proxy.

Without these, two processes writing the same file (the Flask app and the
proxy container, which both write events) collide with "database is locked"
and the losing write disappears. For a campaign that means a click that never
gets recorded, which then reads as a false negative in the report.

WAL lets one writer and many readers proceed at the same time, and the busy
timeout makes a blocked writer wait instead of failing immediately.
"""

from sqlalchemy import event
from sqlalchemy.engine import Engine

_INSTALLED = False


def install_sqlite_pragmas() -> None:
    """Idempotent: safe to call from both entry points."""
    global _INSTALLED
    if _INSTALLED:
        return

    @event.listens_for(Engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, connection_record):  # noqa: ARG001
        module = type(dbapi_connection).__module__
        if not module.startswith("sqlite3"):
            return
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()
        except Exception:
            # In-memory databases and read-only handles reject some pragmas.
            pass

    _INSTALLED = True
