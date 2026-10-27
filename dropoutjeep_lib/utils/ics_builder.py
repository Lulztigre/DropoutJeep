import uuid
from datetime import datetime, timezone


def build_ics(event_title: str, event_start: datetime, event_end: datetime,
              location: str = None, description: str = None,
              organizer_email: str = None, uid: str = None) -> str:
    """Build a minimal RFC 5545 iCalendar (.ics) string."""
    uid = uid or str(uuid.uuid4())
    now = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')

    def fmt(dt: datetime) -> str:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime('%Y%m%dT%H%M%SZ')

    lines = [
        'BEGIN:VCALENDAR',
        'VERSION:2.0',
        'PRODID:-//DropoutJeep//Simulation//EN',
        'METHOD:REQUEST',
        'BEGIN:VEVENT',
        f'UID:{uid}',
        f'DTSTAMP:{now}',
        f'ORGANIZED;CN=DropoutJeep Simulation:mailto:{organizer_email or "no-reply@example.com"}',
        f'SUMMARY:{_escape(event_title or "Meeting")}',
        f'DTSTART:{fmt(event_start)}',
        f'DTEND:{fmt(event_end)}',
    ]
    if location:
        lines.append(f'LOCATION:{_escape(location)}')
    if description:
        lines.append(f'DESCRIPTION:{_escape(description)}')
    lines.extend([
        'STATUS:CONFIRMED',
        'SEQUENCE:0',
        'END:VEVENT',
        'END:VCALENDAR',
    ])
    return '\r\n'.join(lines)


def _escape(value: str) -> str:
    return value.replace('\\', '\\\\').replace(';', '\\;').replace(',', '\\,').replace('\n', '\\n').replace('\r', '')
