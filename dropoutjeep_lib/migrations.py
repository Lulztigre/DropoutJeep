"""Idempotent additive schema migrations run at import time."""

from dropoutjeep_lib import db


def _ensure_campaign_schedule_columns(app):
    """Idempotent additive migration for campaign scheduling columns."""
    campaign_cols = [
        ('scheduled_at', 'DATETIME'),
        ('schedule_cron', 'VARCHAR(128)'),
        ('schedule_timezone', "VARCHAR(64) DEFAULT 'UTC'"),
        ('schedule_enabled', 'BOOLEAN DEFAULT 0'),
        ('schedule_last_run_at', 'DATETIME'),
    ]
    with app.app_context():
        for col, dtype in campaign_cols:
            try:
                db.session.execute(db.text(f"ALTER TABLE campaign ADD COLUMN {col} {dtype}"))
                db.session.commit()
                print(f'[upgrade] Added campaign.{col}')
            except Exception:
                db.session.rollback()


def _run_inline_upgrades(app):
    """Run all additive schema upgrades idempotently at import time."""
    upgrades = [
        ("ALTER TABLE event ADD COLUMN status VARCHAR(64) DEFAULT 'new'", "status"),
        ("ALTER TABLE campaign ADD COLUMN flow_type VARCHAR(32) DEFAULT 'single_step'", "flow_type"),
        ("ALTER TABLE campaign ADD COLUMN flow_config TEXT", "flow_config"),
        ("ALTER TABLE campaign ADD COLUMN calendar_invite BOOLEAN DEFAULT 0", "calendar_invite"),
        ("ALTER TABLE campaign ADD COLUMN calendar_event_title VARCHAR(255)", "calendar_event_title"),
        ("ALTER TABLE campaign ADD COLUMN calendar_event_location VARCHAR(255)", "calendar_event_location"),
        ("ALTER TABLE campaign ADD COLUMN calendar_event_start DATETIME", "calendar_event_start"),
        ("ALTER TABLE campaign ADD COLUMN calendar_event_end DATETIME", "calendar_event_end"),
        ("ALTER TABLE campaign ADD COLUMN scheduled_at DATETIME", "scheduled_at"),
        ("ALTER TABLE campaign ADD COLUMN schedule_cron VARCHAR(128)", "schedule_cron"),
        ("ALTER TABLE campaign ADD COLUMN schedule_timezone VARCHAR(64) DEFAULT 'UTC'", "schedule_timezone"),
        ("ALTER TABLE campaign ADD COLUMN schedule_enabled BOOLEAN DEFAULT 0", "schedule_enabled"),
        ("ALTER TABLE campaign ADD COLUMN schedule_last_run_at DATETIME", "schedule_last_run_at"),
        ("""CREATE TABLE IF NOT EXISTS training_completion (
            id INTEGER NOT NULL PRIMARY KEY,
            recipient_id INTEGER NOT NULL,
            campaign_id INTEGER NOT NULL,
            training_url TEXT,
            status VARCHAR(32) DEFAULT 'started',
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            completed_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(recipient_id) REFERENCES recipient (id),
            FOREIGN KEY(campaign_id) REFERENCES campaign (id)
        )""", "training_completion"),
        ("ALTER TABLE campaign ADD COLUMN parent_campaign_id INTEGER", "parent_campaign_id"),
        ("ALTER TABLE recipient ADD COLUMN import_batch_id VARCHAR(64)", "import_batch_id"),
        ("""CREATE TABLE IF NOT EXISTS api_token (
            id INTEGER NOT NULL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            token_hash VARCHAR(128) NOT NULL,
            scopes TEXT NOT NULL DEFAULT '[]',
            created_by_user_id INTEGER,
            last_used_at DATETIME,
            expires_at DATETIME,
            is_active BOOLEAN NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(created_by_user_id) REFERENCES user (id)
        )""", "api_token"),
        ("""CREATE TABLE IF NOT EXISTS email_template (
            id INTEGER NOT NULL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            category VARCHAR(128) NOT NULL DEFAULT 'custom',
            description TEXT,
            tags TEXT,
            subject VARCHAR(512) NOT NULL DEFAULT '',
            body_html TEXT NOT NULL DEFAULT '',
            landing_html TEXT NOT NULL DEFAULT '',
            is_builtin BOOLEAN NOT NULL DEFAULT 0,
            author VARCHAR(255),
            source_url VARCHAR(1024),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )""", "email_template"),
        ("""CREATE TABLE IF NOT EXISTS campaign_version (
            id INTEGER NOT NULL PRIMARY KEY,
            campaign_id INTEGER NOT NULL,
            version_number INTEGER NOT NULL,
            name VARCHAR(255) NOT NULL,
            subject VARCHAR(512) NOT NULL DEFAULT '',
            body_html TEXT NOT NULL DEFAULT '',
            landing_html TEXT NOT NULL DEFAULT '',
            flow_config TEXT,
            created_by_user_id INTEGER,
            notes TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(campaign_id) REFERENCES campaign (id),
            FOREIGN KEY(created_by_user_id) REFERENCES user (id)
        )""", "campaign_version"),
        ("""CREATE TABLE IF NOT EXISTS canary_token (
            id INTEGER NOT NULL PRIMARY KEY,
            token VARCHAR(128) NOT NULL UNIQUE,
            name VARCHAR(255) NOT NULL,
            token_type VARCHAR(32) NOT NULL DEFAULT 'url',
            campaign_id INTEGER,
            redirect_url TEXT,
            status VARCHAR(32) DEFAULT 'active',
            triggered_at DATETIME,
            trigger_meta TEXT,
            notes TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(campaign_id) REFERENCES campaign (id)
        )""", "canary_token"),
        ("""CREATE TABLE IF NOT EXISTS webhook (
            id INTEGER NOT NULL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            campaign_id INTEGER,
            url VARCHAR(2048) NOT NULL,
            secret VARCHAR(512) NOT NULL,
            events TEXT NOT NULL DEFAULT '[]',
            is_active BOOLEAN NOT NULL DEFAULT 1,
            last_status VARCHAR(32),
            last_sent_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(campaign_id) REFERENCES campaign (id)
        )""", "webhook"),
        ("""CREATE TABLE IF NOT EXISTS captured_cookie (
            id INTEGER NOT NULL PRIMARY KEY,
            campaign_id INTEGER NOT NULL,
            recipient_token VARCHAR(128),
            cookie_name VARCHAR(512) NOT NULL,
            cookie_value TEXT NOT NULL,
            cookie_domain VARCHAR(512),
            cookie_path VARCHAR(512),
            source VARCHAR(32) DEFAULT 'response',
            captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(campaign_id) REFERENCES campaign (id)
        )""", "captured_cookie"),
        ("""CREATE TABLE IF NOT EXISTS captured_credential (
            id INTEGER NOT NULL PRIMARY KEY,
            campaign_id INTEGER NOT NULL,
            recipient_id INTEGER,
            credential_type VARCHAR(32) NOT NULL,
            field_name VARCHAR(255) NOT NULL,
            username VARCHAR(512),
            value_enc TEXT NOT NULL,
            source_path VARCHAR(2048),
            captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(campaign_id) REFERENCES campaign (id),
            FOREIGN KEY(recipient_id) REFERENCES recipient (id)
        )""", "captured_credential"),
        ("""CREATE TABLE IF NOT EXISTS proxy_domain (
            id INTEGER NOT NULL PRIMARY KEY,
            domain VARCHAR(255) NOT NULL UNIQUE,
            campaign_id INTEGER NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_wildcard BOOLEAN NOT NULL DEFAULT 0,
            base_domain VARCHAR(255),
            server_ip VARCHAR(64),
            dns_provider VARCHAR(64) NOT NULL DEFAULT 'none',
            dns_credentials_enc TEXT,
            auto_tls_enabled BOOLEAN NOT NULL DEFAULT 0,
            acme_email VARCHAR(320),
            tls_provider VARCHAR(64) NOT NULL DEFAULT 'none',
            tls_ready BOOLEAN NOT NULL DEFAULT 0,
            cert_path TEXT,
            key_path TEXT,
            last_provisioned_at DATETIME,
            provision_error TEXT,
            FOREIGN KEY(campaign_id) REFERENCES campaign (id)
        )""", "proxy_domain"),
        ("""CREATE TABLE IF NOT EXISTS redirector (
            id INTEGER NOT NULL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            url_template VARCHAR(1024) NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT 1,
            health_status VARCHAR(32) DEFAULT 'unknown',
            last_checked_at DATETIME,
            last_error TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )""", "redirector"),
        ("ALTER TABLE campaign ADD COLUMN domain_reputation_check_enabled BOOLEAN DEFAULT 1", "domain_reputation_check_enabled"),
        ("ALTER TABLE campaign ADD COLUMN sender_rotation_pool_id INTEGER", "sender_rotation_pool_id"),
        ("ALTER TABLE campaign ADD COLUMN sandbox_evasion_enabled BOOLEAN DEFAULT 0", "sandbox_evasion_enabled"),
        ("ALTER TABLE campaign ADD COLUMN sandbox_safe_html TEXT DEFAULT ''", "sandbox_safe_html"),
        ("ALTER TABLE campaign ADD COLUMN html_smuggling_enabled BOOLEAN DEFAULT 0", "html_smuggling_enabled"),
        ("ALTER TABLE campaign ADD COLUMN html_smuggling_payload TEXT", "html_smuggling_payload"),
        ("ALTER TABLE campaign ADD COLUMN html_smuggling_filename VARCHAR(255)", "html_smuggling_filename"),
        ("ALTER TABLE campaign ADD COLUMN use_enterprise_mailer BOOLEAN DEFAULT 0", "use_enterprise_mailer"),
        ("ALTER TABLE event ADD COLUMN mitre_techniques TEXT", "mitre_techniques"),
        ("ALTER TABLE recipient ADD COLUMN variant_key VARCHAR(16)", "variant_key"),
        ("""CREATE TABLE IF NOT EXISTS campaign_variant (
            id INTEGER NOT NULL PRIMARY KEY,
            campaign_id INTEGER NOT NULL,
            variant_key VARCHAR(16) NOT NULL,
            name VARCHAR(255) NOT NULL,
            body_html TEXT NOT NULL DEFAULT '',
            landing_html TEXT NOT NULL DEFAULT '',
            weight INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(campaign_id) REFERENCES campaign (id)
        )""", "campaign_variant"),
        ("ALTER TABLE campaign_job ADD COLUMN rotation_index INTEGER DEFAULT 0", "rotation_index"),
        ("ALTER TABLE subsidiary ADD COLUMN warmup_level INTEGER DEFAULT 0", "warmup_level"),
        ("ALTER TABLE subsidiary ADD COLUMN daily_sent_count INTEGER DEFAULT 0", "daily_sent_count"),
        ("ALTER TABLE subsidiary ADD COLUMN last_sent_date DATE", "last_sent_date"),
        ("""CREATE TABLE IF NOT EXISTS domain_reputation (
            id INTEGER NOT NULL PRIMARY KEY,
            domain VARCHAR(255) NOT NULL UNIQUE,
            subsidiary_id INTEGER,
            domain_age_days INTEGER,
            virus_total_score INTEGER,
            virus_total_categories TEXT,
            blacklist_flags TEXT,
            spf_ok BOOLEAN DEFAULT 0,
            dkim_ok BOOLEAN DEFAULT 0,
            dmarc_ok BOOLEAN DEFAULT 0,
            overall_score INTEGER DEFAULT 0,
            warmup_level INTEGER DEFAULT 0,
            daily_sent_count INTEGER DEFAULT 0,
            last_sent_date DATE,
            last_checked_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(subsidiary_id) REFERENCES subsidiary (id)
        )""", "domain_reputation"),
        ("""CREATE TABLE IF NOT EXISTS sender_rotation_pool (
            id INTEGER NOT NULL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            campaign_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(campaign_id) REFERENCES campaign (id)
        )""", "sender_rotation_pool"),
        ("""CREATE TABLE IF NOT EXISTS sender_rotation_entry (
            id INTEGER NOT NULL PRIMARY KEY,
            pool_id INTEGER NOT NULL,
            sending_profile_id INTEGER NOT NULL,
            subsidiary_id INTEGER,
            display_name_override VARCHAR(255),
            from_address_override VARCHAR(320),
            sort_order INTEGER DEFAULT 0,
            FOREIGN KEY(pool_id) REFERENCES sender_rotation_pool (id),
            FOREIGN KEY(sending_profile_id) REFERENCES sending_profile (id),
            FOREIGN KEY(subsidiary_id) REFERENCES subsidiary (id)
        )""", "sender_rotation_entry"),
        ("""CREATE TABLE IF NOT EXISTS recipient_fingerprint (
            id INTEGER NOT NULL PRIMARY KEY,
            recipient_id INTEGER NOT NULL,
            campaign_id INTEGER NOT NULL,
            first_seen_ip VARCHAR(64),
            first_seen_ua TEXT,
            first_seen_hash VARCHAR(64),
            device_hash VARCHAR(64),
            first_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(recipient_id) REFERENCES recipient (id),
            FOREIGN KEY(campaign_id) REFERENCES campaign (id)
        )""", "recipient_fingerprint"),
        ("ALTER TABLE recipient_fingerprint ADD COLUMN device_hash VARCHAR(64)", "device_hash"),
        ("""CREATE TABLE IF NOT EXISTS mfa_relay_state (
            id INTEGER NOT NULL PRIMARY KEY,
            campaign_id INTEGER NOT NULL,
            recipient_token VARCHAR(128),
            client_ip VARCHAR(64),
            username_field VARCHAR(255),
            username_value TEXT,
            password_field VARCHAR(255),
            password_value TEXT,
            path VARCHAR(2048),
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(campaign_id) REFERENCES campaign (id)
        )""", "mfa_relay_state"),
        ("""CREATE TABLE IF NOT EXISTS suppressed_email (
            id INTEGER NOT NULL PRIMARY KEY,
            email VARCHAR(320) NOT NULL UNIQUE,
            domain VARCHAR(255) NOT NULL,
            source VARCHAR(64),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )""", "suppressed_email"),
        ("""CREATE TABLE IF NOT EXISTS payload (
            id INTEGER NOT NULL PRIMARY KEY,
            campaign_id INTEGER NOT NULL,
            name VARCHAR(255) NOT NULL,
            filename VARCHAR(255) NOT NULL,
            extension VARCHAR(16) NOT NULL,
            mime_type VARCHAR(255) NOT NULL,
            content_enc TEXT NOT NULL,
            per_recipient BOOLEAN NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(campaign_id) REFERENCES campaign (id)
        )""", "payload"),
        ("""CREATE TABLE IF NOT EXISTS oauth_token_capture (
            id INTEGER NOT NULL PRIMARY KEY,
            campaign_id INTEGER NOT NULL,
            recipient_id INTEGER,
            recipient_token VARCHAR(128),
            provider VARCHAR(128),
            auth_code TEXT,
            access_token TEXT,
            refresh_token TEXT,
            id_token TEXT,
            token_type VARCHAR(32),
            expires_in INTEGER,
            scope VARCHAR(512),
            captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(campaign_id) REFERENCES campaign (id),
            FOREIGN KEY(recipient_id) REFERENCES recipient (id)
        )""", "oauth_token_capture"),
        ("""CREATE TABLE IF NOT EXISTS captured_oauth_token (
            id INTEGER NOT NULL PRIMARY KEY,
            campaign_id INTEGER NOT NULL,
            recipient_id INTEGER,
            recipient_token VARCHAR(128),
            provider VARCHAR(128),
            access_token TEXT,
            refresh_token TEXT,
            id_token TEXT,
            token_type VARCHAR(32),
            expires_in INTEGER,
            scope VARCHAR(512),
            captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(campaign_id) REFERENCES campaign (id),
            FOREIGN KEY(recipient_id) REFERENCES recipient (id)
        )""", "captured_oauth_token"),
        ("""CREATE TABLE IF NOT EXISTS saml_capture (
            id INTEGER NOT NULL PRIMARY KEY,
            campaign_id INTEGER NOT NULL,
            recipient_id INTEGER,
            recipient_token VARCHAR(128),
            saml_response TEXT,
            relay_state TEXT,
            relayed_to VARCHAR(2048),
            relay_status VARCHAR(32),
            captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(campaign_id) REFERENCES campaign (id),
            FOREIGN KEY(recipient_id) REFERENCES recipient (id)
        )""", "saml_capture"),
        ("ALTER TABLE captured_cookie ADD COLUMN is_valid BOOLEAN", "is_valid"),
        ("ALTER TABLE captured_cookie ADD COLUMN validated_at DATETIME", "validated_at"),
        ("ALTER TABLE captured_cookie ADD COLUMN validation_error TEXT", "validation_error"),
        ("""CREATE TABLE IF NOT EXISTS c2_connector_config (
            id INTEGER NOT NULL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            type VARCHAR(32) NOT NULL,
            config TEXT NOT NULL DEFAULT '{}',
            is_active BOOLEAN NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )""", "c2_connector_config"),
        ("ALTER TABLE campaign ADD COLUMN store_credentials_plaintext BOOLEAN DEFAULT 0", "store_credentials_plaintext"),
        ("""CREATE TABLE IF NOT EXISTS loot_item (
            id INTEGER NOT NULL PRIMARY KEY,
            campaign_id INTEGER NOT NULL,
            recipient_id INTEGER,
            recipient_token VARCHAR(128),
            source VARCHAR(255) NOT NULL,
            category VARCHAR(64) NOT NULL DEFAULT 'other',
            data_enc TEXT NOT NULL,
            ip VARCHAR(64),
            ua TEXT,
            captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(campaign_id) REFERENCES campaign (id),
            FOREIGN KEY(recipient_id) REFERENCES recipient (id)
        )""", "loot_item"),
        ("ALTER TABLE sending_profile ADD COLUMN bimi_logo_url VARCHAR(1024)", "bimi_logo_url"),
        ("ALTER TABLE sending_profile ADD COLUMN arc_enabled BOOLEAN DEFAULT 0", "arc_enabled"),
        ("ALTER TABLE sending_profile ADD COLUMN arc_selector VARCHAR(255)", "arc_selector"),
        ("ALTER TABLE sending_profile ADD COLUMN warmup_active BOOLEAN DEFAULT 0", "warmup_active"),
        ("ALTER TABLE sending_profile ADD COLUMN warmup_day INTEGER DEFAULT 0", "warmup_day"),
        ("ALTER TABLE campaign ADD COLUMN edr_detection BOOLEAN DEFAULT 1", "edr_detection"),
        ("ALTER TABLE campaign ADD COLUMN ip_reputation_filter BOOLEAN DEFAULT 1", "ip_reputation_filter"),
        ("ALTER TABLE campaign ADD COLUMN safelinks_mode VARCHAR(32) DEFAULT 'standard'", "safelinks_mode"),
    ]
    with app.app_context():
        for sql, col in upgrades:
            try:
                db.session.execute(db.text(sql))
                db.session.commit()
                print(f'[upgrade] Added {col}')
            except Exception:
                db.session.rollback()
