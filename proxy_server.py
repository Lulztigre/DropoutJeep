#!/usr/bin/env python
"""Entry point for the standalone DropoutJeep async proxy server."""

import os

import uvicorn

from dropoutjeep_lib.proxy.server import app


def _check_database() -> None:
    """Fail loudly when the proxy is pointed at the wrong database file.

    The proxy writes click and capture events into the same SQLite file as the
    Flask app. Started against a different path it runs happily, captures never
    appear in the dashboard, and nothing logs an error.
    """
    import os as _os
    url = _os.environ.get("DATABASE_URL", "sqlite:///phish.db")
    if not url.startswith("sqlite"):
        return
    path = url.replace("sqlite:///", "", 1).split("?", 1)[0]
    if not path:
        return
    candidate = path if _os.path.exists(path) else "/" + path.lstrip("/")
    if not _os.path.exists(candidate):
        print(f"[proxy] WARNING: database not found at {candidate}. "
              f"Use the same DATABASE_URL the app uses, or captures will be written "
              f"to a database nobody reads.", flush=True)
        return
    try:
        import sqlite3
        conn = sqlite3.connect(candidate)
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
    except Exception as exc:
        print(f"[proxy] WARNING: could not inspect {candidate}: {exc}", flush=True)
        return
    if "event" not in tables and "campaign" not in tables:
        print(f"[proxy] WARNING: {candidate} has no DropoutJeep tables. "
              f"Almost certainly the wrong DATABASE_URL.", flush=True)

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    _check_database()
    uvicorn.run(
        app,
        host=os.environ.get("PROXY_HOST", "0.0.0.0"),
        port=int(os.environ.get("PROXY_PORT", "8080")),
    )
