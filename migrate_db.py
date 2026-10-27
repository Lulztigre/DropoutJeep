"""One-time SQLite migration for the VEX SENDER feature gaps.

Adds any missing columns/tables introduced by CampaignJob, RateProfile,
AutoReplyRule and PendingReply without dropping existing data.
"""

import os
import shutil
import sqlite3
from pathlib import Path

# Match Flask's instance-relative SQLite resolution. If DATABASE_URL is not set
# and instance/phish.db already exists, migrate that file instead of the cwd one.
DB_URL = os.environ.get('DATABASE_URL')
if not DB_URL:
    instance_db = Path('instance/phish.db')
    if instance_db.exists():
        DB_URL = f'sqlite:///{instance_db}'
    else:
        DB_URL = 'sqlite:///phish.db'
DB_PATH = Path(DB_URL.replace('sqlite:///', ''))
BACKUP_PATH = DB_PATH.with_suffix('.db.backup')


def _column_exists(cur, table, column):
    cur.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cur.fetchall())


def _table_exists(cur, table):
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
    return cur.fetchone() is not None


def main():
    print(f"Using database: {DB_PATH} (from DATABASE_URL={DB_URL})")

    if not DB_PATH.exists():
        print(f"Database not found at {DB_PATH}; it will be created on first app run.")
        return

    shutil.copy(DB_PATH, BACKUP_PATH)
    print(f"Backed up existing database to {BACKUP_PATH}")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # --- sending_profile missing columns ---
    if _table_exists(cur, 'sending_profile'):
        sending_profile_cols = [
            ('is_active', 'BOOLEAN DEFAULT 1'),
            ('created_at', 'DATETIME DEFAULT CURRENT_TIMESTAMP'),
            ('updated_at', 'DATETIME DEFAULT CURRENT_TIMESTAMP'),
            ('rate_profile_id', 'INTEGER'),
            ('imap_host', 'VARCHAR(255)'),
            ('imap_port', 'INTEGER DEFAULT 993'),
            ('imap_user', 'VARCHAR(255)'),
            ('imap_pass', 'TEXT'),
            ('imap_use_tls', 'BOOLEAN DEFAULT 1'),
        ]
        for col, dtype in sending_profile_cols:
            if not _column_exists(cur, 'sending_profile', col):
                cur.execute(f"ALTER TABLE sending_profile ADD COLUMN {col} {dtype}")
                print(f"Added sending_profile.{col}")
    else:
        print("sending_profile table does not exist yet; will be created by db.create_all")

    # --- auto_reply_rule missing columns ---
    if _table_exists(cur, 'auto_reply_rule'):
        if not _column_exists(cur, 'auto_reply_rule', 'auto_approve'):
            cur.execute("ALTER TABLE auto_reply_rule ADD COLUMN auto_approve BOOLEAN DEFAULT 0")
            print("Added auto_reply_rule.auto_approve")
    else:
        print("auto_reply_rule table does not exist yet; will be created by db.create_all")

    # --- event missing columns ---
    if _table_exists(cur, 'event'):
        event_cols = [
            ('ip_address', 'VARCHAR(64)'),
            ('user_agent', 'TEXT'),
        ]
        for col, dtype in event_cols:
            if not _column_exists(cur, 'event', col):
                cur.execute(f"ALTER TABLE event ADD COLUMN {col} {dtype}")
                print(f"Added event.{col}")
    else:
        print("event table does not exist yet; will be created by db.create_all")

    # --- rate_profile table ---
    if not _table_exists(cur, 'rate_profile'):
        cur.execute("""
            CREATE TABLE rate_profile (
                id INTEGER NOT NULL PRIMARY KEY,
                name VARCHAR(128) NOT NULL,
                host_pattern VARCHAR(255),
                hourly_limit INTEGER DEFAULT 500,
                daily_limit INTEGER DEFAULT 2000,
                monthly_limit INTEGER DEFAULT 60000,
                delay_ms_min INTEGER DEFAULT 100,
                delay_ms_max INTEGER DEFAULT 300,
                burst_size INTEGER DEFAULT 5,
                is_default BOOLEAN DEFAULT 0
            )
        """)
        print("Created rate_profile table")

    # --- campaign_job table ---
    if not _table_exists(cur, 'campaign_job'):
        cur.execute("""
            CREATE TABLE campaign_job (
                id INTEGER NOT NULL PRIMARY KEY,
                campaign_id INTEGER,
                status VARCHAR(32) DEFAULT 'pending',
                total INTEGER DEFAULT 0,
                sent INTEGER DEFAULT 0,
                failed INTEGER DEFAULT 0,
                started_at DATETIME,
                completed_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(campaign_id) REFERENCES campaign (id)
            )
        """)
        print("Created campaign_job table")

    # --- auto_reply_rule table ---
    if not _table_exists(cur, 'auto_reply_rule'):
        cur.execute("""
            CREATE TABLE auto_reply_rule (
                id INTEGER NOT NULL PRIMARY KEY,
                campaign_id INTEGER,
                name VARCHAR(255) NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                filter_sender_pattern VARCHAR(512),
                filter_subject_pattern VARCHAR(512),
                reply_template_html TEXT NOT NULL,
                reply_subject_template VARCHAR(512) DEFAULT 'Re: {subject}',
                max_replies_per_session INTEGER DEFAULT 10,
                delay_seconds INTEGER DEFAULT 5,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(campaign_id) REFERENCES campaign (id)
            )
        """)
        print("Created auto_reply_rule table")

    # --- pending_reply table ---
    if not _table_exists(cur, 'pending_reply'):
        cur.execute("""
            CREATE TABLE pending_reply (
                id INTEGER NOT NULL PRIMARY KEY,
                rule_id INTEGER NOT NULL,
                campaign_id INTEGER,
                original_message_id VARCHAR(512),
                original_subject VARCHAR(512),
                original_sender VARCHAR(320),
                reply_subject VARCHAR(512),
                reply_body_html TEXT,
                status VARCHAR(32) DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                sent_at DATETIME,
                FOREIGN KEY(rule_id) REFERENCES auto_reply_rule (id),
                FOREIGN KEY(campaign_id) REFERENCES campaign (id)
            )
        """)
        print("Created pending_reply table")

    # --- redirector table ---
    if not _table_exists(cur, 'redirector'):
        cur.execute("""
            CREATE TABLE redirector (
                id INTEGER NOT NULL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                url_template VARCHAR(1024) NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                health_status VARCHAR(32) DEFAULT 'unknown',
                last_checked_at DATETIME,
                last_error TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("Created redirector table")

    # --- proxy_domain multi-domain columns ---
    if _table_exists(cur, 'proxy_domain'):
        proxy_domain_cols = [
            ('is_wildcard', 'BOOLEAN DEFAULT 0'),
            ('base_domain', 'VARCHAR(255)'),
            ('server_ip', 'VARCHAR(64)'),
            ('dns_provider', "VARCHAR(64) DEFAULT 'none'"),
            ('dns_credentials_enc', 'TEXT'),
            ('auto_tls_enabled', 'BOOLEAN DEFAULT 0'),
            ('acme_email', 'VARCHAR(320)'),
            ('tls_provider', "VARCHAR(64) DEFAULT 'none'"),
            ('tls_ready', 'BOOLEAN DEFAULT 0'),
            ('cert_path', 'TEXT'),
            ('key_path', 'TEXT'),
            ('last_provisioned_at', 'DATETIME'),
            ('provision_error', 'TEXT'),
        ]
        for col, dtype in proxy_domain_cols:
            if not _column_exists(cur, 'proxy_domain', col):
                cur.execute(f"ALTER TABLE proxy_domain ADD COLUMN {col} {dtype}")
                print(f"Added proxy_domain.{col}")
    else:
        print("proxy_domain table does not exist yet; will be created by db.create_all")

    # --- campaign schedule columns ---
    if _table_exists(cur, 'campaign'):
        campaign_cols = [
            ('scheduled_at', 'DATETIME'),
            ('schedule_cron', 'VARCHAR(128)'),
            ('schedule_timezone', 'VARCHAR(64) DEFAULT \'UTC\''),
            ('schedule_enabled', 'BOOLEAN DEFAULT 0'),
            ('schedule_last_run_at', 'DATETIME'),
        ]
        for col, dtype in campaign_cols:
            if not _column_exists(cur, 'campaign', col):
                cur.execute(f"ALTER TABLE campaign ADD COLUMN {col} {dtype}")
                print(f"Added campaign.{col}")
    else:
        print("campaign table does not exist yet; will be created by db.create_all")

    # --- training_completion table ---
    if not _table_exists(cur, 'training_completion'):
        cur.execute("""
            CREATE TABLE training_completion (
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
            )
        """)
        print("Created training_completion table")

    # --- user table ---
    if not _table_exists(cur, 'user'):
        cur.execute("""
            CREATE TABLE user (
                id INTEGER NOT NULL PRIMARY KEY,
                username VARCHAR(128) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(32) NOT NULL DEFAULT 'viewer',
                is_active BOOLEAN NOT NULL DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("Created user table")

    # --- audit_log table ---
    if not _table_exists(cur, 'audit_log'):
        cur.execute("""
            CREATE TABLE audit_log (
                id INTEGER NOT NULL PRIMARY KEY,
                user_id INTEGER,
                action VARCHAR(128) NOT NULL,
                method VARCHAR(16) NOT NULL,
                path VARCHAR(1024) NOT NULL,
                status_code INTEGER,
                ip_address VARCHAR(64),
                user_agent VARCHAR(512),
                details TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES user (id)
            )
        """)
        print("Created audit_log table")

    # --- Seed default rate profiles ---
    cur.execute("SELECT COUNT(*) FROM rate_profile")
    if cur.fetchone()[0] == 0:
        profiles = [
            ('Gmail', r'gmail\.com', 500, 2000, 60000, 200, 500, 3, 0),
            ('Outlook', r'outlook\.com', 800, 8000, 240000, 150, 400, 4, 0),
            ('Office 365', r'office365\.com', 1000, 10000, 300000, 100, 300, 5, 0),
            ('Custom', r'.*', 2000, 50000, 1500000, 50, 200, 10, 1),
        ]
        cur.executemany(
            """INSERT INTO rate_profile
               (name, host_pattern, hourly_limit, daily_limit, monthly_limit,
                delay_ms_min, delay_ms_max, burst_size, is_default)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            profiles
        )
        print("Seeded default rate profiles")

    conn.commit()
    conn.close()
    print("Migration complete.")


if __name__ == '__main__':
    main()
