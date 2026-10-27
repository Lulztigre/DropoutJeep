"""Automated domain warmup sender.

Runs a daily job that sends a ramping volume of benign, legitimate-looking
business emails (newsletter / team memo / weekly summary / product update)
through a sending profile to build sender reputation before real campaign
traffic.  Volume follows an exponential curve from ~10/day on day 1 to
5000/day on day 30.

Progress (the current warmup day and last-run date) is persisted in the
``settings`` table so the cycle survives restarts.  Domain reputation is
read and updated through :mod:`dropoutjeep_lib.utils.domain_reputation`.

These helpers must be invoked inside a Flask application context because
they query the database and construct the :class:`Mailer`.
"""

from __future__ import annotations

import logging
import random
import time
from datetime import date, datetime, timedelta
from typing import Dict, List, Tuple

from dropoutjeep_lib import db
from dropoutjeep_lib.models import SendingProfile, Setting, Subsidiary

from .domain_reputation import (
    get_or_refresh_domain_reputation,
    is_domain_ready_for_volume,
    record_domain_send,
)
from .mailer import Mailer

logger = logging.getLogger("dropoutjeep")

# ---------------------------------------------------------------------------
# Warmup curve
# ---------------------------------------------------------------------------

WARMUP_DAYS = 30
START_VOLUME = 10
END_VOLUME = 5000


def _calculate_daily_volume(day: int) -> int:
    """Target send volume for a given warmup day (1-indexed).

    Exponential curve ``START_VOLUME * (END_VOLUME/START_VOLUME) ** (day/30)``
    rounded to the nearest integer.  Day 1 ≈ 12, day 30 = 5000.
    """
    if day <= 1:
        # Floor the first day at the configured start volume so the ramp
        # never undershoots the minimum that produces a measurable signal.
        return START_VOLUME
    if day >= WARMUP_DAYS:
        return END_VOLUME
    ratio = END_VOLUME / START_VOLUME
    volume = START_VOLUME * (ratio ** (day / WARMUP_DAYS))
    return max(START_VOLUME, int(round(volume)))


def get_warmup_schedule() -> List[Dict]:
    """Return the full 30-day warmup schedule as a list of ``{day, volume}``."""
    return [
        {"day": day, "volume": _calculate_daily_volume(day)}
        for day in range(1, WARMUP_DAYS + 1)
    ]


# ---------------------------------------------------------------------------
# Settings persistence helpers (no set_setting helper exists in the codebase)
# ---------------------------------------------------------------------------

def _get_setting_value(key: str, default: str = "") -> str:
    row = Setting.query.filter_by(key=key.lower()).first()
    return row.value if row and row.value is not None else default


def _set_setting_value(key: str, value: str) -> None:
    row = Setting.query.filter_by(key=key.lower()).first()
    if row:
        row.value = value
    else:
        row = Setting(key=key.lower(), value=value)
        db.session.add(row)
    db.session.commit()


def _warmup_day_key(profile_id: int) -> str:
    return f"warmup_day_{profile_id}"


def _warmup_last_run_key(profile_id: int) -> str:
    return f"warmup_last_run_date_{profile_id}"


def _get_current_warmup_day(profile_id: int) -> int:
    raw = _get_setting_value(_warmup_day_key(profile_id), "1")
    try:
        day = int(raw)
    except (TypeError, ValueError):
        day = 1
    return max(1, min(WARMUP_DAYS, day))


def _advance_warmup_day(profile_id: int) -> None:
    today = date.today()
    last_raw = _get_setting_value(_warmup_last_run_key(profile_id))
    last_date: date | None = None
    if last_raw:
        try:
            last_date = datetime.strptime(last_raw, "%Y-%m-%d").date()
        except ValueError:
            last_date = None

    # Only advance the day once per calendar day so repeated manual runs
    # during the same day don't burn through the schedule.
    if last_date is None or last_date < today:
        current = _get_current_warmup_day(profile_id)
        next_day = min(WARMUP_DAYS, current + 1)
        _set_setting_value(_warmup_day_key(profile_id), str(next_day))
        _set_setting_value(_warmup_last_run_key(profile_id), today.isoformat())
        logger.info("warmup day advanced to %d for profile %d", next_day, profile_id)


# ---------------------------------------------------------------------------
# Benign content templates
# ---------------------------------------------------------------------------

_TEMPLATES: List[Tuple[str, str]] = [
    (
        "Weekly team memo — {week}",
        (
            "<html><body style='font-family:Arial,sans-serif;color:#333'>"
            "<h2>Weekly Team Memo</h2>"
            "<p>Hi team,</p>"
            "<p>Here's a quick summary of this week's priorities, wins, and "
            "focus areas. Please review before Monday's standup.</p>"
            "<ul>"
            "<li><b>Shipping:</b> two features cleared QA and went live.</li>"
            "<li><b>Support:</b> median first-response time dropped 18%.</li>"
            "<li><b>Next week:</b> finalise the Q3 roadmap and capacity plan.</li>"
            "</ul>"
            "<p>Questions? Reply here or drop a note in #team.</p>"
            "<p>— The Operations Team</p>"
            "<hr><p style='font-size:11px;color:#888'>"
            "You received this memo as part of an internal distribution list. "
            "Reply 'unsubscribe' to opt out.</p>"
            "</body></html>"
        ),
    ),
    (
        "Company newsletter — {month} edition",
        (
            "<html><body style='font-family:Georgia,serif;color:#222'>"
            "<h2>The {month} Newsletter</h2>"
            "<p>Welcome to this month's update from across the company.</p>"
            "<h3>Highlights</h3>"
            "<p>This month we welcomed new teammates, shipped a major update to "
            "our analytics dashboard, and completed the annual security review "
            "with zero findings.</p>"
            "<h3>Upcoming</h3>"
            "<p>Join us next month for the product roadmap webinar and the "
            "engineering open house. Calendar invites will follow.</p>"
            "<p>Thanks for reading.</p>"
            "<p>— Communications</p>"
            "<hr><p style='font-size:11px;color:#999'>"
            "You're receiving this because you subscribed to company updates. "
            "Use the link below to manage your preferences.</p>"
            "</body></html>"
        ),
    ),
    (
        "Weekly summary report — {week}",
        (
            "<html><body style='font-family:Helvetica,Arial,sans-serif;color:#111'>"
            "<h2>Weekly Summary Report</h2>"
            "<p>Attached is the summary of activity and metrics for the week "
            "of {week}.</p>"
            "<p><b>Key metrics</b></p>"
            "<ul>"
            "<li>Active users: up 4.2% week-over-week.</li>"
            "<li>Conversion: steady at 3.1%.</li>"
            "<li>System uptime: 99.97%.</li>"
            "</ul>"
            "<p>The full report is available on the internal portal. Please "
            "reach out with any questions.</p>"
            "<p>— Reporting</p>"
            "<hr><p style='font-size:11px;color:#888'>"
            "This is an automated summary. Reply 'unsubscribe' to stop "
            "receiving weekly reports.</p>"
            "</body></html>"
        ),
    ),
    (
        "Product update: new analytics features",
        (
            "<html><body style='font-family:Arial,sans-serif;color:#333'>"
            "<h2>What's new this week</h2>"
            "<p>We just shipped several improvements to help you get more out "
            "of the platform:</p>"
            "<ul>"
            "<li>Faster dashboard load times.</li>"
            "<li>New export formats (CSV, XLSX, PDF).</li>"
            "<li>Improved filters and saved views.</li>"
            "</ul>"
            "<p>These features are available to all plans, no action required. "
            "Log in to try them out.</p>"
            "<p>— Product Team</p>"
            "<hr><p style='font-size:11px;color:#888'>"
            "You're receiving this product update as a registered user. "
            "Manage your email preferences via the link below.</p>"
            "</body></html>"
        ),
    ),
]


def _current_week_string() -> str:
    """Return a human-readable week label, e.g. 'Jul 28 – Aug 3'."""
    today = date.today()
    start = today - timedelta(days=today.weekday())
    end = start + timedelta(days=6)
    return f"{start.strftime('%b %d')} – {end.strftime('%b %d')}"


def _current_month_string() -> str:
    return date.today().strftime("%B")


def _get_warmup_content() -> Tuple[str, str]:
    """Generate benign newsletter/memo content and return ``(subject, body)``.

    Content is drawn at random from a pool of legitimate business templates
    designed to be opened (clear subject, no spam triggers) and to include a
    working unsubscribe path.  Subjects are lightly personalised with the
    current week/month so they don't look identical across days.
    """
    subject_tmpl, body_tmpl = random.choice(_TEMPLATES)
    week = _current_week_string()
    month = _current_month_string()
    subject = subject_tmpl.format(week=week, month=month)
    body = body_tmpl.format(week=week, month=month)
    return subject, body


# ---------------------------------------------------------------------------
# Recipient resolution
# ---------------------------------------------------------------------------

# A small built-in seed list used only when no recipients are configured.
# Real warmup should point this at monitored/seed inboxes that generate
# opens (and never complaints).  Configure via the 'warmup_recipients'
# setting (comma-separated list of addresses).
_DEFAULT_SEED_RECIPIENTS = [
    "warmup-seed@example.net",
    "opens-tracker@example.net",
    "inbox-monitor@example.net",
    "reputation-seed@example.net",
]


def _get_warmup_recipients(profile: SendingProfile) -> List[str]:
    """Return the configured warmup recipient pool for a profile.

    Resolution order:
      1. per-profile setting ``warmup_recipients_<id>``
      2. global setting ``warmup_recipients``
      3. built-in default seed list
    """
    raw = (
        _get_setting_value(f"warmup_recipients_{profile.id}")
        or _get_setting_value("warmup_recipients")
    )
    if raw:
        addrs = [a.strip() for a in raw.split(",") if a.strip()]
        if addrs:
            return addrs
    return list(_DEFAULT_SEED_RECIPIENTS)


def _build_recipient_list(pool: List[str], count: int) -> List[str]:
    """Expand a small recipient pool to ``count`` unique-ish addresses using
    plus-addressing tags so each message targets a distinct inbox-style
    mailbox while still routing to the same seed account."""
    if not pool:
        return []
    if count <= len(pool):
        return pool[:count]
    expanded: List[str] = []
    for i in range(count):
        base = pool[i % len(pool)]
        if "@" in base:
            local, domain = base.split("@", 1)
            expanded.append(f"{local}+w{i}@{domain}")
        else:
            expanded.append(base)
    return expanded


# ---------------------------------------------------------------------------
# Mailer construction
# ---------------------------------------------------------------------------

def _build_mailer(profile: SendingProfile) -> Mailer:
    """Construct a :class:`Mailer` from a sending profile and its subsidiary,
    mirroring the kwargs used by the campaign Dialer so DKIM signing and
    SMTP auth match production sends."""
    sub: Subsidiary | None = profile.subsidiary
    return Mailer(
        smtp_host=profile.smtp_host,
        smtp_port=profile.smtp_port or 25,
        smtp_user=profile.smtp_user,
        smtp_pass=profile.get_smtp_pass(),
        use_tls=profile.use_tls,
        dkim_selector=sub.dkim_selector if sub else None,
        dkim_domain=sub.sending_domain if sub else None,
        dkim_private_key=sub.get_dkim_private_key() if sub else None,
    )


def _from_address(profile: SendingProfile) -> str:
    sub = profile.subsidiary
    if sub and sub.from_address:
        return sub.from_address
    if profile.smtp_user and "@" in profile.smtp_user:
        return profile.smtp_user
    return f"no-reply@{profile.smtp_host or 'localhost'}"


# ---------------------------------------------------------------------------
# Warmup cycle
# ---------------------------------------------------------------------------

def run_warmup_cycle(sending_profile_id: int) -> Dict:
    """Execute one day's warmup sends for a sending profile.

    Returns a dict with:
        ``sent``   – number of emails successfully sent.
        ``target``  – the planned volume for the current warmup day.
        ``day``     – the current warmup day (1-30).
        ``errors``  – list of error strings for failed sends.
    """
    profile = SendingProfile.query.get(sending_profile_id)
    if not profile:
        return {
            "sent": 0,
            "target": 0,
            "day": 0,
            "errors": [f"sending profile {sending_profile_id} not found"],
        }
    if not profile.is_active:
        return {
            "sent": 0,
            "target": 0,
            "day": _get_current_warmup_day(sending_profile_id),
            "errors": ["sending profile is not active"],
        }

    day = _get_current_warmup_day(sending_profile_id)
    target = _calculate_daily_volume(day)

    sub = profile.subsidiary
    domain = sub.sending_domain if sub else (profile.smtp_host or "")

    # Respect the domain's current reputation volume cap so warmup never
    # pushes a freshly-warmed domain past its allowed ceiling.
    capped_target = target
    if sub:
        ok, msg = is_domain_ready_for_volume(sub, target)
        if not ok:
            logger.info("warmup target %d capped by reputation: %s", target, msg)
            rep = get_or_refresh_domain_reputation(sub.sending_domain, sub.id)
            from .domain_reputation import _warmup_volume_limit
            capped_target = min(target, _warmup_volume_limit(rep.warmup_level))
            capped_target = max(0, capped_target)

    if capped_target <= 0:
        logger.info("warmup day %d skipped — domain reputation cap is 0", day)
        _advance_warmup_day(sending_profile_id)
        return {"sent": 0, "target": 0, "day": day, "errors": []}

    recipients = _build_recipient_list(
        _get_warmup_recipients(profile), capped_target
    )
    if not recipients:
        return {
            "sent": 0,
            "target": capped_target,
            "day": day,
            "errors": ["no warmup recipients configured"],
        }

    envelope_from = _from_address(profile)
    mailer = _build_mailer(profile)

    sent = 0
    errors: List[str] = []
    # Throttle to respect the profile's rate-per-minute setting.
    rate_per_min = max(1, profile.rate_per_minute or 60)
    per_message_delay = max(0.0, 60.0 / rate_per_min - 0.05)

    for idx, to_addr in enumerate(recipients):
        subject, body = _get_warmup_content()
        try:
            mailer.send(
                envelope_from=envelope_from,
                to_addr=to_addr,
                subject=subject,
                html_body=body,
            )
            sent += 1
            if sent % 50 == 0:
                logger.info(
                    "warmup profile %d day %d: sent %d/%d",
                    sending_profile_id, day, sent, capped_target,
                )
        except Exception as exc:
            msg = f"send {idx + 1} to {to_addr} failed: {exc}"
            errors.append(msg)
            logger.warning("warmup send error: %s", msg)
        if per_message_delay and idx + 1 < len(recipients):
            time.sleep(per_message_delay)

    try:
        mailer.close()
    except Exception:
        pass

    # Record sends against the domain reputation tracker.
    if sub:
        record_domain_send(sub, count=sent)

    _advance_warmup_day(sending_profile_id)

    logger.info(
        "warmup cycle complete: profile=%d day=%d sent=%d target=%d errors=%d",
        sending_profile_id, day, sent, capped_target, len(errors),
    )

    return {
        "sent": sent,
        "target": capped_target,
        "day": day,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Status check
# ---------------------------------------------------------------------------

def _check_warmup_status(domain: str) -> Dict:
    """Check domain reputation score and warmup progress.

    Returns a dict with the reputation score, warmup level, today's sent
    count, the current warmup day (best-effort, since days are tracked per
    profile — this reports the highest active profile day for the domain),
    the planned target for that day, and whether the warmup window is
    complete.
    """
    rep = get_or_refresh_domain_reputation(domain)
    sub = rep.subsidiary

    warmup_day = 0
    target_today = 0
    if sub:
        # Find the active sending profile(s) for this subsidiary and report
        # the most-advanced warmup day among them.
        profiles = (
            SendingProfile.query
            .filter_by(subsidiary_id=sub.id, is_active=True)
            .all()
        )
        for p in profiles:
            d = _get_current_warmup_day(p.id)
            if d > warmup_day:
                warmup_day = d
                target_today = _calculate_daily_volume(d)

    return {
        "domain": domain,
        "reputation_score": rep.overall_score,
        "warmup_level": rep.warmup_level,
        "daily_sent_count": rep.daily_sent_count,
        "warmup_day": warmup_day,
        "target_today": target_today,
        "warmup_complete": warmup_day >= WARMUP_DAYS,
        "last_checked_at": rep.last_checked_at.isoformat() if rep.last_checked_at else None,
    }
