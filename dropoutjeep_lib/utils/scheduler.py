"""In-app campaign scheduler backed by APScheduler.

Campaigns store their schedule on the Campaign model.  On startup we load
all enabled schedules into a single BackgroundScheduler.  The scheduler
re-uses the existing Dialer to send campaigns so no extra infrastructure is
required.
"""

import os
from datetime import datetime

import pytz
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger

from dropoutjeep_lib import db
from dropoutjeep_lib.models import Campaign


_scheduler = BackgroundScheduler()
_app = None


def init_scheduler(app):
    """Start the scheduler and load enabled campaign schedules."""
    global _app
    _app = app

    if _scheduler.running:
        return

    # Avoid starting the scheduler in the Werkzeug reloader parent process.
    # In the reloader, only the child process has WERKZEUG_RUN_MAIN='true'.
    run_main = os.environ.get('WERKZEUG_RUN_MAIN')
    if app.debug and run_main is not None and run_main != 'true':
        return

    _scheduler.start()
    with app.app_context():
        sync_campaign_schedules()
        _add_auto_reply_job()
        _add_redirector_health_job()
        _add_bounce_ingest_job()


def _timezone(tz_name: str):
    try:
        return pytz.timezone(tz_name)
    except Exception:
        return pytz.UTC


def sync_campaign_schedules():
    """Reload all enabled campaign schedules into the scheduler."""
    if not _scheduler.running:
        return

    # Remove only campaign jobs. remove_all_jobs() also killed the interval jobs
    # (auto-reply poll, redirector health, bounce ingestion) every time a campaign
    # schedule was saved, so those features quietly stopped for the rest of the
    # process lifetime.
    for job in _scheduler.get_jobs():
        if job.id.startswith('dj_campaign_'):
            _scheduler.remove_job(job.id)

    try:
        campaigns = Campaign.query.filter_by(schedule_enabled=True).all()
    except Exception as exc:
        print(f'[scheduler] Could not load campaign schedules (migration pending?): {exc}')
        return

    for campaign in campaigns:
        _add_campaign_job(campaign)



def _add_campaign_job(campaign: Campaign):
    job_id = f'dj_campaign_{campaign.id}'
    tz = _timezone(campaign.schedule_timezone or 'UTC')
    trigger = None

    cron = (campaign.schedule_cron or '').strip()
    if cron:
        try:
            parts = cron.split()
            if len(parts) == 5:
                minute, hour, day, month, day_of_week = parts
                trigger = CronTrigger(
                    minute=minute, hour=hour, day=day,
                    month=month, day_of_week=day_of_week,
                    timezone=tz,
                )
        except Exception:
            trigger = None
    elif campaign.scheduled_at:
        try:
            run_date = campaign.scheduled_at
            if run_date.tzinfo is None:
                run_date = tz.localize(run_date)
            trigger = DateTrigger(run_date=run_date, timezone=tz)
        except Exception:
            trigger = None

    if trigger:
        _scheduler.add_job(
            _run_scheduled_campaign,
            trigger,
            id=job_id,
            args=[campaign.id],
            replace_existing=True,
        )


def _run_scheduled_campaign(campaign_id: int):
    if _app is None:
        return

    with _app.app_context():
        from dropoutjeep_lib.utils.dialer import Dialer

        campaign = Campaign.query.get(campaign_id)
        if not campaign or not campaign.schedule_enabled:
            return

        campaign.schedule_last_run_at = datetime.utcnow()
        db.session.add(campaign)
        db.session.commit()

        sp = campaign.sending_profile
        rpm = sp.rate_per_minute if sp else 60
        rate_profile = sp.resolve_rate_profile() if sp else None
        if rate_profile and rate_profile.delay_ms_max:
            rpm = max(1, int(60000.0 / rate_profile.delay_ms_max))

        dialer = Dialer(db, rate_per_min=rpm)
        dialer.start_campaign(campaign_id)


def _add_auto_reply_job():
    """Register the periodic auto-reply inbox poll."""
    _scheduler.add_job(
        _run_auto_reply_poll,
        'interval',
        minutes=5,
        id='dj_auto_reply_poll',
        replace_existing=True,
    )


def _run_auto_reply_poll():
    if _app is None:
        return
    with _app.app_context():
        from dropoutjeep_lib.utils.auto_replier import process_all_auto_replies
        process_all_auto_replies()


def _add_bounce_ingest_job():
    """Poll the bounce mailbox on each sending profile. Off unless IMAP is set."""
    minutes = int(os.environ.get('BOUNCE_INGEST_MINUTES', '5') or 5)
    _scheduler.add_job(
        _run_bounce_ingest,
        'interval',
        minutes=minutes,
        id='dj_bounce_ingest',
        replace_existing=True,
    )


def _run_bounce_ingest():
    if _app is None:
        return
    with _app.app_context():
        try:
            from dropoutjeep_lib.utils.mail_ingest import ingest_once
            stats = ingest_once()
            if stats.get('bounces') or stats.get('errors'):
                print(f"[bounce] mailboxes={stats['mailboxes']} messages={stats['messages']} "
                      f"bounces={stats['bounces']} errors={stats['errors'][:2]}")
        except Exception as exc:
            print(f'[bounce] ingestion failed: {exc}')


def _add_redirector_health_job():
    """Register the periodic redirector health check (every 5 minutes)."""
    _scheduler.add_job(
        _run_redirector_health_checks,
        'interval',
        minutes=5,
        id='dj_redirector_health',
        replace_existing=True,
    )


def _run_redirector_health_checks():
    if _app is None:
        return
    with _app.app_context():
        try:
            from dropoutjeep_lib.utils.redirectors import check_all_redirectors
            results = check_all_redirectors()
            unhealthy = [r for r in results if not r['healthy']]
            if unhealthy:
                print(f'[redirector-health] {len(unhealthy)} unhealthy redirector(s): '
                      + ', '.join(r['name'] for r in unhealthy))
        except Exception as exc:
            print(f'[redirector-health] check failed: {exc}')


def get_scheduler():
    return _scheduler
