"""Persistent suppression-list helpers.

Suppression entries are stored in the database and checked during recipient
import and campaign launch.  Both exact email addresses and entire domains can
be suppressed.
"""

import csv
import io
from typing import Iterable

from dropoutjeep_lib import db
from dropoutjeep_lib.models import SuppressedEmail


def _normalize_email(value: str) -> str:
    return value.strip().lower()


def _domain_from_email(email: str) -> str:
    if '@' in email:
        return email.split('@', 1)[1]
    return email


def is_suppressed(email: str) -> bool:
    """Return True if the email or its domain is suppressed."""
    email = _normalize_email(email)
    domain = _domain_from_email(email)
    return db.session.query(SuppressedEmail.query.filter(
        (SuppressedEmail.email == email) | (SuppressedEmail.domain == domain)
    ).exists()).scalar()


def suppress(email: str, source: str | None = None) -> SuppressedEmail:
    """Add an email (or domain) to the suppression list."""
    email = _normalize_email(email)
    domain = _domain_from_email(email)
    existing = SuppressedEmail.query.filter_by(email=email).first()
    if existing:
        return existing
    row = SuppressedEmail(email=email, domain=domain, source=source)
    db.session.add(row)
    db.session.commit()
    return row


def remove_suppression(email: str) -> bool:
    """Remove an exact email from the suppression list."""
    email = _normalize_email(email)
    row = SuppressedEmail.query.filter_by(email=email).first()
    if row:
        db.session.delete(row)
        db.session.commit()
        return True
    return False


def list_suppressions(limit: int = 1000, offset: int = 0) -> list[SuppressedEmail]:
    return SuppressedEmail.query.order_by(SuppressedEmail.created_at.desc()) \
        .limit(limit).offset(offset).all()


def import_suppressions(lines: Iterable[str], source: str | None = None) -> dict:
    """Import suppressions from an iterable of lines.

    Supports:
      - CSV with an 'email' header
      - Plain email/domain list (one per line)
    """
    lines = list(lines)
    added = 0
    duplicates = 0
    errors = []

    # Try CSV first if the first non-empty line looks like a header.
    reader = None
    for line in lines:
        stripped = line.strip()
        if stripped:
            if stripped.lower().startswith('email'):
                reader = csv.DictReader(io.StringIO('\n'.join(lines)))
            break

    items = []
    if reader:
        for row in reader:
            value = (row.get('email') or row.get('Email') or '').strip()
            if value:
                items.append(value)
    else:
        items = [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]

    for value in items:
        if '@' not in value and '.' not in value:
            errors.append({'value': value, 'reason': 'invalid email or domain'})
            continue
        normalized = _normalize_email(value)
        domain = _domain_from_email(normalized)
        exists = SuppressedEmail.query.filter_by(email=normalized).first()
        if exists:
            duplicates += 1
            continue
        db.session.add(SuppressedEmail(email=normalized, domain=domain, source=source))
        added += 1

    db.session.commit()
    return {'added': added, 'duplicates': duplicates, 'errors': errors}


def export_suppressions() -> str:
    """Export suppression list as CSV text."""
    rows = SuppressedEmail.query.order_by(SuppressedEmail.email).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['email', 'domain', 'source', 'created_at'])
    for row in rows:
        writer.writerow([
            row.email,
            row.domain,
            row.source or '',
            row.created_at.isoformat() if row.created_at else '',
        ])
    return buf.getvalue()
