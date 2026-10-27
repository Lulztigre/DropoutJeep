import secrets
import os
import base64
import hashlib
import json
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Date, ForeignKey, Boolean, func, event
from sqlalchemy.orm import relationship
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import generate_password_hash, check_password_hash
from . import db

Base = db.Model

_ENC_PREFIX = 'enc::'


def _fernet_cipher():
    key = os.environ.get('FERNET_KEY')
    if key:
        return Fernet(key.encode())
    fallback_secret = os.environ.get('FLASK_SECRET', 'dropoutjeep-dev-only-secret')
    derived = base64.urlsafe_b64encode(hashlib.sha256(fallback_secret.encode()).digest())
    return Fernet(derived)


def _encrypt_secret(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not value:
        return value
    if value.startswith(_ENC_PREFIX):
        return value
    token = _fernet_cipher().encrypt(value.encode()).decode()
    return f'{_ENC_PREFIX}{token}'


def _decrypt_secret(value: str | None) -> str | None:
    if value is None:
        return None
    if not value.startswith(_ENC_PREFIX):
        return value
    token = value[len(_ENC_PREFIX):]
    try:
        return _fernet_cipher().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise ValueError('Encrypted secret could not be decrypted. Verify FERNET_KEY/FLASK_SECRET.') from exc


class Subsidiary(Base):
    __tablename__ = 'subsidiary'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    sending_domain = Column(String(255), nullable=False)
    display_name = Column(String(255), nullable=False)
    from_address = Column(String(320), nullable=False)
    bounce_subdomain = Column(String(255))
    dkim_selector = Column(String(128))
    dkim_private_key = Column(Text)

    # Warmup tracking for sender reputation
    warmup_level = Column(Integer, default=0)
    daily_sent_count = Column(Integer, default=0)
    last_sent_date = Column(Date, nullable=True)

    def set_dkim_private_key(self, private_key: str | None):
        self.dkim_private_key = _encrypt_secret(private_key)

    def get_dkim_private_key(self) -> str | None:
        return _decrypt_secret(self.dkim_private_key)


class RateProfile(Base):
    __tablename__ = 'rate_profile'
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)
    host_pattern = Column(String(255))
    hourly_limit = Column(Integer, default=500)
    daily_limit = Column(Integer, default=2000)
    monthly_limit = Column(Integer, default=60000)
    delay_ms_min = Column(Integer, default=100)
    delay_ms_max = Column(Integer, default=300)
    burst_size = Column(Integer, default=5)
    is_default = Column(Boolean, default=False)


class SendingProfile(Base):
    __tablename__ = 'sending_profile'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    smtp_host = Column(String(255))
    smtp_port = Column(Integer, default=25)
    smtp_user = Column(String(255))
    smtp_pass = Column(Text)
    use_tls = Column(Boolean, default=True)
    rate_per_minute = Column(Integer, default=60)

    # IMAP inbox for auto-reply engine
    imap_host = Column(String(255), nullable=True)
    imap_port = Column(Integer, default=993)
    imap_user = Column(String(255), nullable=True)
    imap_pass = Column(Text, nullable=True)
    imap_use_tls = Column(Boolean, default=True)
    rate_profile_id = Column(Integer, ForeignKey('rate_profile.id'), nullable=True)
    rate_profile = relationship('RateProfile')
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    subsidiary_id = Column(Integer, ForeignKey('subsidiary.id'))
    subsidiary = relationship('Subsidiary')

    # BIMI / ARC / Warmup extensions
    bimi_logo_url = Column(String(1024), nullable=True)
    arc_enabled = Column(Boolean, default=False)
    arc_selector = Column(String(255), nullable=True)
    warmup_active = Column(Boolean, default=False)
    warmup_day = Column(Integer, default=0)

    def set_smtp_pass(self, password: str | None):
        self.smtp_pass = _encrypt_secret(password)

    def get_smtp_pass(self) -> str | None:
        return _decrypt_secret(self.smtp_pass)

    def set_imap_pass(self, password: str | None):
        self.imap_pass = _encrypt_secret(password)

    def get_imap_pass(self) -> str | None:
        return _decrypt_secret(self.imap_pass)

    def resolve_rate_profile(self):
        import re
        if self.rate_profile_id:
            return RateProfile.query.get(self.rate_profile_id)
        # Check specific (non-default) profiles first so host patterns win
        # over the catch-all default profile.
        profiles = RateProfile.query.order_by(RateProfile.is_default.asc()).all()
        for p in profiles:
            if p.host_pattern and re.search(p.host_pattern, self.smtp_host or '', re.I):
                return p
        return RateProfile.query.filter_by(is_default=True).first()


class Campaign(Base):
    __tablename__ = 'campaign'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    subject = Column(String(512), nullable=False, default='')
    body_html = Column(Text, nullable=False, default='')
    # template_html is kept for backward compatibility with older snippets.
    template_html = Column(Text, nullable=False, default='')
    landing_html = Column(Text, nullable=False, default='')
    sending_profile_id = Column(Integer, ForeignKey('sending_profile.id'))
    sending_profile = relationship('SendingProfile')
    created_at = Column(DateTime, server_default=func.now())

    # Multi-step flow configuration
    flow_type = Column(String(32), nullable=False, default='single_step')
    flow_config = Column(Text, nullable=True)

    # Calendar invite simulation
    calendar_invite = Column(Boolean, default=False)
    calendar_event_title = Column(String(255), nullable=True)
    calendar_event_location = Column(String(255), nullable=True)
    calendar_event_start = Column(DateTime, nullable=True)
    calendar_event_end = Column(DateTime, nullable=True)

    # Campaign scheduling (one-time or cron-based recurrence)
    scheduled_at = Column(DateTime, nullable=True)
    schedule_cron = Column(String(128), nullable=True)
    schedule_timezone = Column(String(64), default=lambda: os.environ.get('SCHEDULE_TIMEZONE', 'UTC'))
    schedule_enabled = Column(Boolean, default=False)
    schedule_last_run_at = Column(DateTime, nullable=True)

    # Clone lineage
    parent_campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=True)

    # Advanced deliverability / evasion toggles
    domain_reputation_check_enabled = Column(Boolean, default=True)
    sender_rotation_pool_id = Column(Integer, ForeignKey('sender_rotation_pool.id'), nullable=True)
    sender_rotation_pool = relationship('SenderRotationPool', foreign_keys=[sender_rotation_pool_id])
    sandbox_evasion_enabled = Column(Boolean, default=False)
    sandbox_safe_html = Column(Text, nullable=False, default='')
    html_smuggling_enabled = Column(Boolean, default=False)
    html_smuggling_payload = Column(Text, nullable=True)
    html_smuggling_filename = Column(String(255), nullable=True)
    use_enterprise_mailer = Column(Boolean, default=False)
    store_credentials_plaintext = Column(Boolean, default=False)
    edr_detection = Column(Boolean, default=True)
    ip_reputation_filter = Column(Boolean, default=True)
    safelinks_mode = Column(String(32), default='standard')

    def set_html_smuggling_payload(self, value: str | bytes | None):
        if value is None:
            self.html_smuggling_payload = None
            return
        if isinstance(value, bytes):
            value = base64.b64encode(value).decode('ascii')
        self.html_smuggling_payload = _encrypt_secret(value)

    def get_html_smuggling_payload(self) -> str | None:
        if not self.html_smuggling_payload:
            return None
        return _decrypt_secret(self.html_smuggling_payload)

    def get_flow_config(self):
        import json
        if not self.flow_config:
            return {}
        try:
            return json.loads(self.flow_config)
        except Exception:
            return {}

    def set_flow_config(self, value: dict):
        import json
        self.flow_config = json.dumps(value) if value else None

    def snapshot_version(self, user_id=None, notes=None):
        """Create a CampaignVersion snapshot of the current campaign state."""
        latest = CampaignVersion.query.filter_by(campaign_id=self.id) \
            .order_by(CampaignVersion.version_number.desc()).first()
        version_number = (latest.version_number + 1) if latest else 1
        return CampaignVersion(
            campaign_id=self.id,
            version_number=version_number,
            name=self.name,
            subject=self.subject,
            body_html=self.body_html,
            landing_html=self.landing_html,
            flow_config=self.flow_config,
            created_by_user_id=user_id,
            notes=notes or f'Snapshot before version {version_number}',
        )

    def is_proxy_campaign(self) -> bool:
        return self.flow_type == "reverse_proxy"

    def get_proxy_target_url(self) -> str | None:
        if not self.is_proxy_campaign():
            return None
        return self.get_flow_config().get("target_url")

    def get_proxy_rules(self) -> list[dict]:
        if not self.is_proxy_campaign():
            return []
        return self.get_flow_config().get("rules", [])

    def get_status(self) -> str:
        """Return campaign status: draft, scheduled, running, completed, failed, stopped, ready."""
        if self.schedule_enabled:
            return 'scheduled'
        job = CampaignJob.query.filter_by(campaign_id=self.id) \
            .order_by(CampaignJob.started_at.desc()).first()
        if job:
            return job.status
        recipient_count = Recipient.query.filter_by(campaign_id=self.id).count()
        if recipient_count == 0:
            return 'draft'
        sent_count = Recipient.query.filter_by(campaign_id=self.id).filter(Recipient.sent_at.isnot(None)).count()
        if sent_count == 0:
            return 'ready'
        return 'unsent'

    def get_status_color(self) -> str:
        """Return CSS color class for the status badge."""
        status = self.get_status()
        colors = {
            'draft': 'bg-gray-200 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
            'ready': 'bg-brutal-emerald text-white',
            'scheduled': 'bg-brutal-amber text-pure-black',
            'running': 'bg-blue-500 text-white',
            'completed': 'bg-pure-black text-stark-white dark:bg-stark-white dark:text-pure-black',
            'failed': 'bg-brutal-red text-white',
            'stopped': 'bg-brutal-red text-white',
            'unsent': 'bg-gray-300 text-gray-700 dark:bg-gray-600 dark:text-gray-300',
        }
        return colors.get(status, 'bg-gray-200 text-gray-700')

    def get_recipient_count(self) -> int:
        """Return total recipient count."""
        return Recipient.query.filter_by(campaign_id=self.id).count()

    def get_sent_count(self) -> int:
        """Return count of recipients who have been sent to."""
        return Recipient.query.filter_by(campaign_id=self.id).filter(Recipient.sent_at.isnot(None)).count()


class CampaignVersion(Base):
    __tablename__ = 'campaign_version'
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=False)
    campaign = relationship('Campaign')
    version_number = Column(Integer, nullable=False)
    name = Column(String(255), nullable=False)
    subject = Column(String(512), nullable=False, default='')
    body_html = Column(Text, nullable=False, default='')
    landing_html = Column(Text, nullable=False, default='')
    flow_config = Column(Text, nullable=True)
    created_by_user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    created_by_user = relationship('User')
    notes = Column(Text)
    created_at = Column(DateTime, server_default=func.now())


class CampaignVariant(Base):
    __tablename__ = 'campaign_variant'
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=False)
    campaign = relationship('Campaign')
    variant_key = Column(String(16), nullable=False)
    name = Column(String(255), nullable=False)
    body_html = Column(Text, nullable=False, default='')
    landing_html = Column(Text, nullable=False, default='')
    weight = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime, server_default=func.now())

    def to_dict(self):
        return {
            'id': self.id,
            'variant_key': self.variant_key,
            'name': self.name,
            'weight': self.weight,
        }


class Target(Base):
    __tablename__ = 'target'
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey('campaign.id'))
    campaign = relationship('Campaign')
    email = Column(String(320), nullable=False)
    token = Column(String(128), nullable=False, default=lambda: secrets.token_urlsafe(16))
    sent_at = Column(DateTime)
    disposition = Column(String(64))


class Recipient(Base):
    __tablename__ = 'recipient'
    id = Column(Integer, primary_key=True)
    email = Column(String(320), nullable=False)
    name = Column(String(255))
    external_id = Column(String(255))
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=True)
    campaign = relationship('Campaign')
    token = Column(String(128), nullable=False, default=lambda: secrets.token_urlsafe(16))
    sent_at = Column(DateTime)
    disposition = Column(String(64))
    import_batch_id = Column(String(64), nullable=True)
    variant_key = Column(String(16), nullable=True)
    created_at = Column(DateTime, server_default=func.now())


class Event(Base):
    __tablename__ = 'event'
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey('target.id'), nullable=True)
    target = relationship('Target', backref='events')
    recipient_id = Column(Integer, ForeignKey('recipient.id'), nullable=True)
    recipient = relationship('Recipient')
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=True)
    campaign = relationship('Campaign')
    event_type = Column(String(64), nullable=False)
    meta = Column(Text)
    status = Column(String(64), default='new')  # new, acknowledged, dismissed
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(Text, nullable=True)
    mitre_techniques = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    def mitre_techniques_list(self) -> list[str]:
        import json
        try:
            return json.loads(self.mitre_techniques or '[]')
        except Exception:
            return []

    def set_mitre_techniques(self, techniques: list[str]):
        import json
        self.mitre_techniques = json.dumps(list(techniques)) if techniques else '[]'


@event.listens_for(Event, 'before_insert')
def _capture_event_request_context(mapper, connection, event_obj):
    """Auto-fill IP and User-Agent from the current Flask request context."""
    try:
        from flask import request
        if request:
            if not event_obj.ip_address:
                event_obj.ip_address = request.remote_addr
            if not event_obj.user_agent:
                event_obj.user_agent = request.headers.get('User-Agent')
    except Exception:
        pass


@event.listens_for(Event, 'before_insert')
def _map_event_mitre_techniques(mapper, connection, event_obj):
    """Auto-populate MITRE ATT&CK technique mapping on event creation."""
    if event_obj.mitre_techniques is None:
        from dropoutjeep_lib.utils.mitre import map_event_type
        event_obj.set_mitre_techniques(map_event_type(event_obj.event_type))


class TrainingCompletion(Base):
    __tablename__ = 'training_completion'
    id = Column(Integer, primary_key=True)
    recipient_id = Column(Integer, ForeignKey('recipient.id'), nullable=False)
    recipient = relationship('Recipient')
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=False)
    campaign = relationship('Campaign')
    training_url = Column(Text)
    status = Column(String(32), default='started')  # started, completed, skipped
    started_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())


class CampaignJob(Base):
    __tablename__ = 'campaign_job'
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey('campaign.id'))
    campaign = relationship('Campaign')
    status = Column(String(32), default='pending')  # pending, running, paused, completed, failed, stopped
    total = Column(Integer, default=0)
    sent = Column(Integer, default=0)
    failed = Column(Integer, default=0)
    rotation_index = Column(Integer, default=0)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())


class AutoReplyRule(Base):
    __tablename__ = 'auto_reply_rule'
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=True)
    campaign = relationship('Campaign')
    name = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    filter_sender_pattern = Column(String(512), nullable=True)
    filter_subject_pattern = Column(String(512), nullable=True)
    reply_template_html = Column(Text, nullable=False)
    reply_subject_template = Column(String(512), default='Re: {subject}')
    max_replies_per_session = Column(Integer, default=10)
    delay_seconds = Column(Integer, default=5)
    auto_approve = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())


class PendingReply(Base):
    __tablename__ = 'pending_reply'
    id = Column(Integer, primary_key=True)
    rule_id = Column(Integer, ForeignKey('auto_reply_rule.id'), nullable=False)
    rule = relationship('AutoReplyRule')
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=True)
    campaign = relationship('Campaign')
    original_message_id = Column(String(512), nullable=True)
    original_subject = Column(String(512), nullable=True)
    original_sender = Column(String(320), nullable=True)
    reply_subject = Column(String(512), nullable=True)
    reply_body_html = Column(Text, nullable=True)
    status = Column(String(32), default='pending')  # pending, approved, rejected, sent
    created_at = Column(DateTime, server_default=func.now())
    sent_at = Column(DateTime, nullable=True)


class Setting(Base):
    __tablename__ = 'settings'
    id = Column(Integer, primary_key=True)
    key = Column(String(255), unique=True, nullable=False)
    value = Column(Text, nullable=False)


class ApiToken(Base):
    __tablename__ = 'api_token'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    token_hash = Column(String(128), nullable=False, index=True)
    scopes = Column(Text, nullable=False, default='[]')
    created_by_user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    created_by_user = relationship('User')
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, server_default=func.now())

    def get_scopes(self):
        import json
        try:
            return json.loads(self.scopes or '[]')
        except Exception:
            return []

    def set_scopes(self, scopes):
        import json
        self.scopes = json.dumps(list(scopes)) if scopes else '[]'

    def has_scope(self, scope):
        token_scopes = self.get_scopes()
        return scope in token_scopes or 'admin' in token_scopes


class EmailTemplate(Base):
    __tablename__ = 'email_template'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    category = Column(String(128), nullable=False, default='custom')
    description = Column(Text)
    tags = Column(Text)
    subject = Column(String(512), nullable=False, default='')
    body_html = Column(Text, nullable=False, default='')
    landing_html = Column(Text, nullable=False, default='')
    is_builtin = Column(Boolean, nullable=False, default=False)
    author = Column(String(255))
    source_url = Column(String(1024))
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    def get_tags(self):
        import json
        try:
            return json.loads(self.tags or '[]')
        except Exception:
            return []

    def set_tags(self, tags):
        import json
        self.tags = json.dumps(list(tags)) if tags else '[]'

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'category': self.category,
            'description': self.description,
            'tags': self.get_tags(),
            'subject': self.subject,
            'body_html': self.body_html,
            'landing_html': self.landing_html,
            'is_builtin': self.is_builtin,
            'author': self.author,
            'source_url': self.source_url,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(128), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False, default='viewer')  # admin, operator, viewer
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class AuditLog(Base):
    __tablename__ = 'audit_log'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    user = relationship('User')
    action = Column(String(128), nullable=False)
    method = Column(String(16), nullable=False)
    path = Column(String(1024), nullable=False)
    status_code = Column(Integer, nullable=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(512), nullable=True)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())


class CanaryToken(Base):
    __tablename__ = 'canary_token'
    id = Column(Integer, primary_key=True)
    token = Column(String(128), nullable=False, unique=True, index=True,
                   default=lambda: secrets.token_urlsafe(16))
    name = Column(String(255), nullable=False)
    token_type = Column(String(32), nullable=False, default='url')  # url, image
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=True)
    campaign = relationship('Campaign')
    redirect_url = Column(Text, nullable=True)
    status = Column(String(32), default='active')  # active, triggered, disabled
    triggered_at = Column(DateTime, nullable=True)
    trigger_meta = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())


class Webhook(Base):
    __tablename__ = 'webhook'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=True)
    campaign = relationship('Campaign')
    url = Column(String(2048), nullable=False)
    secret = Column(String(512), nullable=False)
    events = Column(Text, nullable=False, default='[]')
    is_active = Column(Boolean, nullable=False, default=True)
    last_status = Column(String(32), nullable=True)
    last_sent_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    def get_events(self):
        try:
            return json.loads(self.events or '[]')
        except Exception:
            return []

    def set_events(self, events):
        self.events = json.dumps(list(events)) if events else '[]'

    def matches(self, event_type: str) -> bool:
        events = self.get_events()
        return not events or event_type in events


class C2ConnectorConfig(Base):
    __tablename__ = 'c2_connector_config'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    type = Column(String(32), nullable=False)  # cobalt_strike | mythic | sliver
    config = Column(Text, nullable=False, default='{}')
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    def get_config(self):
        try:
            return json.loads(self.config or '{}')
        except Exception:
            return {}

    def set_config(self, value: dict):
        self.config = json.dumps(value) if value else '{}'


class CapturedCookie(Base):
    __tablename__ = 'captured_cookie'
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=False)
    campaign = relationship('Campaign')
    recipient_token = Column(String(128), nullable=True)
    cookie_name = Column(String(512), nullable=False)
    cookie_value = Column(Text, nullable=False)
    cookie_domain = Column(String(512), nullable=True)
    cookie_path = Column(String(512), nullable=True)
    source = Column(String(32), nullable=False, default='response')  # response | request
    captured_at = Column(DateTime, server_default=func.now())

    # Cookie replay validation state
    is_valid = Column(Boolean, nullable=True)
    validated_at = Column(DateTime, nullable=True)
    validation_error = Column(Text, nullable=True)


class CapturedCredential(Base):
    __tablename__ = 'captured_credential'
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=False)
    campaign = relationship('Campaign')
    recipient_id = Column(Integer, ForeignKey('recipient.id'), nullable=True)
    recipient = relationship('Recipient')
    credential_type = Column(String(32), nullable=False)  # password | mfa | other
    field_name = Column(String(255), nullable=False)
    username = Column(String(512), nullable=True)
    _value_enc = Column('value_enc', Text, nullable=False)
    source_path = Column(String(2048), nullable=True)
    captured_at = Column(DateTime, server_default=func.now())

    def set_value(self, value: str | None):
        self._value_enc = _encrypt_secret(value)

    def get_value(self) -> str | None:
        return _decrypt_secret(self._value_enc)


class Redirector(Base):
    __tablename__ = 'redirector'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    url_template = Column(String(1024), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    health_status = Column(String(32), default='unknown')
    last_checked_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    def __repr__(self):
        return f'<Redirector {self.name} {self.health_status}>'


class ProxyDomain(Base):
    __tablename__ = 'proxy_domain'
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), nullable=False, unique=True, index=True)
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=False)
    campaign = relationship('Campaign')
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, server_default=func.now())

    # Multi-domain / automatic TLS
    is_wildcard = Column(Boolean, nullable=False, default=False)
    base_domain = Column(String(255), nullable=True, index=True)
    server_ip = Column(String(64), nullable=True)
    dns_provider = Column(String(64), nullable=False, default='none')
    dns_credentials_enc = Column(Text, nullable=True)
    auto_tls_enabled = Column(Boolean, nullable=False, default=False)
    acme_email = Column(String(320), nullable=True)
    tls_provider = Column(String(64), nullable=False, default='none')
    tls_ready = Column(Boolean, nullable=False, default=False)
    cert_path = Column(Text, nullable=True)
    key_path = Column(Text, nullable=True)
    last_provisioned_at = Column(DateTime, nullable=True)
    provision_error = Column(Text, nullable=True)

    def set_dns_credentials(self, value: dict | None):
        import json
        self.dns_credentials_enc = _encrypt_secret(json.dumps(value)) if value else None

    def get_dns_credentials(self) -> dict | None:
        import json
        raw = _decrypt_secret(self.dns_credentials_enc)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    def is_fully_provisioned(self) -> bool:
        if not self.is_wildcard:
            return True
        if self.dns_provider != 'none' and not self.server_ip:
            return False
        if self.auto_tls_enabled and not self.tls_ready:
            return False
        return True


class DomainReputation(Base):
    __tablename__ = 'domain_reputation'
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), nullable=False, unique=True, index=True)
    subsidiary_id = Column(Integer, ForeignKey('subsidiary.id'), nullable=True)
    subsidiary = relationship('Subsidiary')
    domain_age_days = Column(Integer, nullable=True)
    virus_total_score = Column(Integer, nullable=True)
    virus_total_categories = Column(Text, nullable=True)
    blacklist_flags = Column(Text, nullable=True)
    spf_ok = Column(Boolean, default=False)
    dkim_ok = Column(Boolean, default=False)
    dmarc_ok = Column(Boolean, default=False)
    overall_score = Column(Integer, default=0)
    warmup_level = Column(Integer, default=0)
    daily_sent_count = Column(Integer, default=0)
    last_sent_date = Column(Date, nullable=True)
    last_checked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    def get_blacklist_flags(self):
        try:
            return json.loads(self.blacklist_flags or '[]')
        except Exception:
            return []

    def set_blacklist_flags(self, flags):
        self.blacklist_flags = json.dumps(list(flags)) if flags else '[]'

    def get_virus_total_categories(self):
        try:
            return json.loads(self.virus_total_categories or '{}')
        except Exception:
            return {}

    def set_virus_total_categories(self, categories):
        self.virus_total_categories = json.dumps(dict(categories)) if categories else '{}'


class SenderRotationPool(Base):
    __tablename__ = 'sender_rotation_pool'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=True)
    campaign = relationship('Campaign', foreign_keys=[campaign_id])
    created_at = Column(DateTime, server_default=func.now())


class SenderRotationEntry(Base):
    __tablename__ = 'sender_rotation_entry'
    id = Column(Integer, primary_key=True)
    pool_id = Column(Integer, ForeignKey('sender_rotation_pool.id'), nullable=False)
    pool = relationship('SenderRotationPool', backref='entries')
    sending_profile_id = Column(Integer, ForeignKey('sending_profile.id'), nullable=False)
    sending_profile = relationship('SendingProfile')
    subsidiary_id = Column(Integer, ForeignKey('subsidiary.id'), nullable=True)
    subsidiary = relationship('Subsidiary')
    display_name_override = Column(String(255), nullable=True)
    from_address_override = Column(String(320), nullable=True)
    sort_order = Column(Integer, default=0)


class RecipientFingerprint(Base):
    __tablename__ = 'recipient_fingerprint'
    id = Column(Integer, primary_key=True)
    recipient_id = Column(Integer, ForeignKey('recipient.id'), nullable=False)
    recipient = relationship('Recipient')
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=False)
    campaign = relationship('Campaign')
    first_seen_ip = Column(String(64), nullable=True)
    first_seen_ua = Column(Text, nullable=True)
    first_seen_hash = Column(String(64), nullable=True)
    # Browser-collected device fingerprint hash used to correlate recipients
    # and events across campaigns/sessions.
    device_hash = Column(String(64), nullable=True, index=True)
    first_seen_at = Column(DateTime, server_default=func.now())


class MfaRelayState(Base):
    __tablename__ = 'mfa_relay_state'
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=False)
    campaign = relationship('Campaign')
    recipient_token = Column(String(128), nullable=True)
    client_ip = Column(String(64), nullable=True)
    username_field = Column(String(255), nullable=True)
    username_value = Column(Text, nullable=True)
    password_field = Column(String(255), nullable=True)
    password_value = Column(Text, nullable=True)
    path = Column(String(2048), nullable=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    def is_expired(self) -> bool:
        from datetime import datetime
        return self.expires_at < datetime.utcnow()


class SuppressedEmail(Base):
    __tablename__ = 'suppressed_email'
    id = Column(Integer, primary_key=True)
    email = Column(String(320), nullable=False, unique=True, index=True)
    domain = Column(String(255), nullable=False, index=True)
    source = Column(String(64), nullable=True)
    created_at = Column(DateTime, server_default=func.now())


class Payload(Base):
    __tablename__ = 'payload'
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=False)
    campaign = relationship('Campaign')
    name = Column(String(255), nullable=False)
    filename = Column(String(255), nullable=False)
    extension = Column(String(16), nullable=False)
    mime_type = Column(String(255), nullable=False)
    content_enc = Column(Text, nullable=False)
    per_recipient = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, server_default=func.now())

    def set_content(self, data: bytes):
        self.content_enc = _encrypt_secret(base64.b64encode(data).decode('ascii'))

    def get_content(self) -> bytes:
        raw = _decrypt_secret(self.content_enc)
        if raw is None:
            return b''
        return base64.b64decode(raw)


class OAuthTokenCapture(Base):
    __tablename__ = 'oauth_token_capture'
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=False)
    campaign = relationship('Campaign')
    recipient_id = Column(Integer, ForeignKey('recipient.id'), nullable=True)
    recipient = relationship('Recipient')
    recipient_token = Column(String(128), nullable=True)
    provider = Column(String(128), nullable=True)
    auth_code = Column(Text, nullable=True)
    access_token = Column(Text, nullable=True)
    refresh_token = Column(Text, nullable=True)
    id_token = Column(Text, nullable=True)
    token_type = Column(String(32), nullable=True)
    expires_in = Column(Integer, nullable=True)
    scope = Column(String(512), nullable=True)
    captured_at = Column(DateTime, server_default=func.now())


class CapturedOAuthToken(Base):
    __tablename__ = 'captured_oauth_token'
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=False)
    campaign = relationship('Campaign')
    recipient_id = Column(Integer, ForeignKey('recipient.id'), nullable=True)
    recipient = relationship('Recipient')
    recipient_token = Column(String(128), nullable=True)
    provider = Column(String(128), nullable=True)
    access_token = Column(Text, nullable=True)
    refresh_token = Column(Text, nullable=True)
    id_token = Column(Text, nullable=True)
    token_type = Column(String(32), nullable=True)
    expires_in = Column(Integer, nullable=True)
    scope = Column(String(512), nullable=True)
    captured_at = Column(DateTime, server_default=func.now())

    def parsed_id_token_claims(self) -> dict:
        from .utils.token_parser import parse_jwt_id_token
        return parse_jwt_id_token(self.id_token or '')


class SamlCapture(Base):
    __tablename__ = 'saml_capture'
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=False)
    campaign = relationship('Campaign')
    recipient_id = Column(Integer, ForeignKey('recipient.id'), nullable=True)
    recipient = relationship('Recipient')
    recipient_token = Column(String(128), nullable=True)
    saml_response = Column(Text, nullable=True)
    relay_state = Column(Text, nullable=True)
    relayed_to = Column(String(2048), nullable=True)
    relay_status = Column(String(32), nullable=True)
    captured_at = Column(DateTime, server_default=func.now())


class RedirectorHealthLog(Base):
    __tablename__ = 'redirector_health_log'
    id = Column(Integer, primary_key=True)
    redirector_id = Column(Integer, ForeignKey('redirector.id'), nullable=False)
    redirector = relationship('Redirector', backref='health_logs')
    is_healthy = Column(Boolean, nullable=False)
    status_code = Column(Integer, nullable=True)
    response_time_ms = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    checked_at = Column(DateTime, server_default=func.now())


class LootItem(Base):
    __tablename__ = 'loot_item'
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=False)
    campaign = relationship('Campaign')
    recipient_id = Column(Integer, ForeignKey('recipient.id'), nullable=True)
    recipient = relationship('Recipient')
    recipient_token = Column(String(128), nullable=True)
    source = Column(String(255), nullable=False)
    category = Column(String(64), nullable=False, default='other')
    data_enc = Column(Text, nullable=False)
    ip = Column(String(64), nullable=True)
    ua = Column(Text, nullable=True)
    captured_at = Column(DateTime, server_default=func.now())

    LOOT_CATEGORIES = {
        'browser_password',
        'browser_cookie',
        'cloud_token',
        'os_credential',
        'vault_secret',
        'ssh_key',
        'other',
    }

    def set_data(self, data: dict):
        self.data_enc = _encrypt_secret(json.dumps(data, default=str))

    def get_data(self) -> dict:
        raw = _decrypt_secret(self.data_enc)
        if raw is None:
            return {}
        try:
            return json.loads(raw)
        except Exception:
            return {'_raw': raw}
