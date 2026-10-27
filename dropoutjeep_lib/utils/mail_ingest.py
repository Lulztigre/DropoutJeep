"""Bounce ingestion driven by the sending profiles.

Each active SendingProfile that has an IMAP host, user and password gets polled
for unseen mail, and anything that parses as a delivery failure becomes a bounce
event. IMAP_HOST/IMAP_USER/IMAP_PASS in the environment are still honoured as a
fallback for installs that keep a single shared mailbox, but the profile is the
source of truth.

The old version of this module had placeholder credentials baked in and was never
called, so a configured bounce mailbox still produced zero bounce events.
"""

import os
import time

from dropoutjeep_lib.utils.mailbox_fetcher import fetch_emails
from dropoutjeep_lib.utils.bounce_parser import parse_bounce


def _sources():
    """Yield (label, host, user, password) for every mailbox worth polling."""
    out = []
    try:
        from dropoutjeep_lib.models import SendingProfile
        profiles = SendingProfile.query.filter_by(is_active=True).all()
    except Exception:
        profiles = []

    for sp in profiles:
        host = (sp.imap_host or '').strip()
        user = (sp.imap_user or '').strip()
        if not host or not user:
            continue
        try:
            password = sp.get_imap_pass()
        except Exception:
            # Undecryptable because the environment key changed. Skip rather than
            # hammer the server with a login that can never succeed.
            password = None
        if password:
            out.append((f'profile:{sp.name or sp.id}', host, user, password))

    host = (os.environ.get('IMAP_HOST') or '').strip()
    user = (os.environ.get('IMAP_USER') or '').strip()
    password = os.environ.get('IMAP_PASS') or ''
    if host and user and password:
        out.append(('env', host, user, password))
    return out


def ingest_once(limit=None):
    """Poll each configured mailbox once. Returns counts, never raises."""
    stats = {'mailboxes': 0, 'messages': 0, 'bounces': 0, 'errors': []}
    seen = set()

    for label, host, user, password in _sources():
        key = (host.lower(), user.lower())
        if key in seen:
            continue  # same mailbox on two profiles: parse it once
        seen.add(key)

        stats['mailboxes'] += 1
        try:
            messages = fetch_emails(host, user, password, limit=limit)
        except Exception as exc:
            stats['errors'].append(f'{label}: {exc}')
            continue

        stats['messages'] += len(messages)
        for msg in messages:
            try:
                if parse_bounce(msg):
                    stats['bounces'] += 1
            except Exception as exc:
                stats['errors'].append(f'{label}: {exc}')
    return stats


def run_ingestion(interval=300):
    while True:
        stats = ingest_once()
        print(f"[ingest] mailboxes={stats['mailboxes']} messages={stats['messages']} "
              f"bounces={stats['bounces']}")
        time.sleep(interval)


if __name__ == '__main__':
    run_ingestion()
