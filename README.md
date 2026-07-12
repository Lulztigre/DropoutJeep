# DropoutJeep

A phishing simulation and security awareness testing platform - I built this out of necessity, frankly i was tired of always asking to be whitelisted per red team exercise. It runs email campaigns with tracking, builds fake landing pages, and can proxy real websites through a transparent MITM (Man-in-the-Middle) engine to capture credentials and MFA tokens.

**Use only for authorized internal security awareness testing.** Get written approval before running any campaigns.

---

## Table of Contents

- [What It Does](#what-it-does)
- [Quick Start](#quick-start)
- [Setup](#setup)
  - [Windows](#windows)
  - [Linux/macOS](#linuxmacos)
  - [Docker](#docker)
- [Configuration](#configuration)
- [First Campaign (Step-by-Step)](#first-campaign-step-by-step)
  - [1. Create a Subsidiary](#1-create-a-subsidiary)
  - [2. Create a Sending Profile](#2-create-a-sending-profile)
  - [3. Build the Email](#3-build-the-email)
  - [4. Design the Landing Page](#4-design-the-landing-page)
  - [5. Add Recipients](#5-add-recipients)
  - [6. Pre-flight Checks](#6-pre-flight-checks)
  - [7. Send the Campaign](#7-send-the-campaign)
  - [8. Analyze Results](#8-analyze-results)
- [Reverse Proxy / MITM Campaigns](#reverse-proxy--mitm-campaigns)
  - [How It Works](#how-it-works)
  - [Content Manipulation Rules](#content-manipulation-rules)
  - [Plugins](#plugins)
  - [Upstream Egress Proxy](#upstream-egress-proxy)
- [All Features](#all-features)
  - [Email Features](#email-features)
  - [Landing Page Features](#landing-page-features)
  - [Proxy Features](#proxy-features)
  - [OAuth and SAML Phishing](#oauth-and-saml-phishing)
  - [Tracking and Analytics](#tracking-and-analytics)
  - [Anti-Detection](#anti-detection)
  - [C2 Connectors](#c2-connectors)
  - [Auto-Reply Engine](#auto-reply-engine)
  - [Webhooks](#webhooks)
  - [Suppression List](#suppression-list)
  - [Infrastructure](#infrastructure)
- [How to Run a Successful Campaign](#how-to-run-a-successful-campaign)
- [Project Structure](#project-structure)
- [Environment Variables](#environment-variables)
- [Running Behind a Reverse Proxy](#running-behind-a-reverse-proxy)
- [Security Notes](#security-notes)
- [Compliance](#compliance)

---

## What It Does

DropoutJeep does three things:

1. **Email campaigns** - Send phishing emails via SMTP, track who opens and clicks, capture credentials on fake login pages.
2. **Landing pages** - Fake login pages that look like your target site, with fingerprinting and canary tokens.
3. **Reverse proxy MITM** - Proxy a real website through DropoutJeep and modify it on the fly. The victim sees the real site, but form submissions go through your server first.

---
<img width="964" height="660" alt="image" src="https://github.com/user-attachments/assets/0d2063b4-b679-4e47-8cd2-2fb4a418eae1" />

## Quick Start

The fastest way to get running:

```bash
# Clone/download the project
cd DropoutJeep

# Create a virtual environment and install dependencies
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate    # Linux/macOS

pip install -r requirements.txt

# Set required environment variables (Windows PowerShell)
$env:FLASK_SECRET="any-random-long-string"
$env:ADMIN_USERNAME="admin"
$env:ADMIN_PASSWORD="your-password"
$env:BASE_URL="http://localhost:5000"
$env:HMAC_SECRET="another-random-string"

# Run it
python dropoutjeep.py
```

Open `http://localhost:5000/admin` in your browser and log in.

---

## Setup

### Windows

```powershell
cd DropoutJeep
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# Set environment variables
$env:FLASK_SECRET="your-random-string"
$env:ADMIN_USERNAME="admin"
$env:ADMIN_PASSWORD="your-password"
$env:BASE_URL="http://localhost:5000"
$env:HMAC_SECRET="another-random-string"

python dropoutjeep.py
```

### Linux/macOS

```bash
cd DropoutJeep
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export FLASK_SECRET="your-random-string"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="your-password"
export BASE_URL="http://localhost:5000"
export HMAC_SECRET="another-random-string"

python dropoutjeep.py
```

### Docker

```bash
docker build -t dropoutjeep .
docker run -d \
  -p 5000:5000 \
  -e FLASK_SECRET="change-me" \
  -e ADMIN_USERNAME="admin" \
  -e ADMIN_PASSWORD="change-me" \
  -e BASE_URL="https://your-domain.com" \
  -v dropoutjeep-data:/app/instance \
  --name dropoutjeep \
  dropoutjeep
```

For a production deployment with automatic HTTPS, see `VPS_DEPLOYMENT.md`.

---

## Configuration

Key environment variables (set these before running):

| Variable | Required | What It Does |
|----------|----------|-------------|
| `FLASK_SECRET` | Yes | Random string for session signing |
| `ADMIN_USERNAME` | Yes | Your admin login username |
| `ADMIN_PASSWORD` | Yes | Your admin login password |
| `BASE_URL` | Yes | Public URL where DropoutJeep is accessible (e.g., `https://phish.example.com`) |
| `HMAC_SECRET` | Yes | Random string used to sign tracking tokens |
| `DATABASE_URL` | No | Database connection string (default: SQLite) |
| `HOST` | No | Bind address (default: `0.0.0.0`) |
| `PORT` | No | Bind port (default: `5000`) |
| `FLASK_DEBUG` | No | Set to `0` for production |
| `FERNET_KEY` | No | Encryption key for stored passwords (derived from FLASK_SECRET if not set) |
| `USE_PROXYFIX` | No | Set to `1` if behind Cloudflare or another reverse proxy |
| `RETENTION_DAYS` | No | How long to keep events (default: 90) |

Full list in the [Environment Variables](#environment-variables) section below.

---

## First Campaign (Step-by-Step)

### 1. Create a Subsidiary

A subsidiary defines who the email appears to come from.

1. Go to `/admin/subsidiary/new`
2. Fill in:
   - **Name** - Internal name (e.g., "IT Security Team")
   - **Sending domain** - The domain emails come from (e.g., `yourcompany.com`)
   - **Display name** - What recipients see as the sender name
   - **From address** - Email address (e.g., `security@yourcompany.com`)
   - **DKIM selector** - Optional. Use `default` if you generate DKIM keys
   - **DKIM private key** - Optional. Click "Generate" to create a new keypair
3. Save

<img width="680" height="581" alt="image" src="https://github.com/user-attachments/assets/329ffd6b-ec74-4085-a15c-0c41ed63d962" />


### 2. Create a Sending Profile

A sending profile tells DropoutJeep how to send emails (SMTP settings).

1. Go to `/admin/sending_profile/new`
2. Fill in:
   - **Name** - Internal name (e.g., "Company SMTP")
   - **SMTP host** - Your SMTP server address
   - **SMTP port** - Usually `587` (TLS) or `465` (SSL)
   - **SMTP username** - Your SMTP login
   - **SMTP password** - Your SMTP password
   - **Use TLS** - Enable this for port 587
   - **Subsidiary** - Select the subsidiary you just created
3. Click **Validate SMTP** to test the connection
4. Save
   
### 3. Build the Email

1. Go to `/admin/campaign/new`
2. Select **Flow type:** `Single-step landing page`
3. Fill in campaign details:
   - **Name** - For your reference
   - **Subject** - The email subject line
   - **Email body** - The HTML email content
4. In the email body, use these placeholders:

| Placeholder | What It Does |
|-------------|-------------|
| `{{TRACK_LINK}}` | Unique tracking link per recipient |
| `{{PIXEL}}` | Invisible image that tracks email opens |
| `{{CANARY_URL}}` | URL-based canary token |
| `{{CANARY_IMAGE}}` | Image-based canary token |
| `{{FINGERPRINT_SCRIPT}}` | Browser fingerprint collector |

**Example email body:**
```html
<h2>Verify your account</h2>
<p>Please click the link below to verify your account details.</p>
<a href="{{TRACK_LINK}}">Verify Now</a>
{{PIXEL}}
```
<img width="721" height="406" alt="image" src="https://github.com/user-attachments/assets/3dc35525-60ce-40c1-a73d-e53338dfc355" />

### 4. Design the Landing Page

The landing page is the fake login page where credentials get captured.

1. In the same campaign editor, find the **Landing page** section
2. Build your page using HTML/CSS. Use these placeholders:

| Placeholder | What It Does |
|-------------|-------------|
| `{{TOKEN}}` | Recipient's unique token (required for tracking) |
| `{{TRACK_LINK}}` | Tracking link |
| `{{PIXEL}}` | Tracking pixel |
| `{{FINGERPRINT_SCRIPT}}` | Browser fingerprint collector |

**Example landing page:**
```html
<html>
<body>
  <h2>Login Required</h2>
  <form method="POST" action="/track/{{TOKEN}}/credential">
    <input type="hidden" name="token" value="{{TOKEN}}">
    <input type="text" name="username" placeholder="Email">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Login</button>
  </form>
  {{FINGERPRINT_SCRIPT}}
</body>
</html>
```
<img width="692" height="293" alt="image" src="https://github.com/user-attachments/assets/48a5d123-3aa9-4092-96aa-3ed4bb6ce115" />
<img width="689" height="281" alt="image" src="https://github.com/user-attachments/assets/660c7ea4-9060-4bb8-8bff-117a38df2ce6" />

### 5. Add Recipients

1. In the campaign editor, go to the **Recipients** section
2. Paste email addresses (one per line)
3. Optionally import a CSV file
4. Suppressed emails are automatically filtered out

<img width="695" height="254" alt="image" src="https://github.com/user-attachments/assets/d4a49e7d-d931-4c03-931e-d51eeda5eb34" />

### 6. Pre-flight Checks

Before sending, validate your setup:

1. Go to the campaign page
2. Click **Validate** or check:
   - SMTP connection works
   - SPF record is set up for your sending domain
   - DKIM is properly configured (if using)
   - Your domain is not on any blacklists
   - Token signing is working

<img width="501" height="575" alt="image" src="https://github.com/user-attachments/assets/fcc2d660-7521-4639-8dcf-9ff046a6eef8" />

### 7. Send the Campaign

1. Click **Send** on the campaign page
2. DropoutJeep sends emails in the background
3. You can monitor progress in the admin dashboard
4. The campaign status changes: `draft` -> `running` -> `completed`

### 8. Analyze Results

After sending, track what happens:

- **Dashboard** (`/admin`) - Overview of opens, clicks, credential captures
- **Events** (`/events`) - Detailed event log (opens, clicks, submissions)
- **Funnel** (`/admin/campaign/<id>/funnel`) - Visual funnel (sent -> opened -> clicked -> submitted)
- **Export** - Download data as CSV or PDF

<img width="762" height="149" alt="image" src="https://github.com/user-attachments/assets/5954362c-bffc-4e38-9ad9-98c413630e88" />
<img width="741" height="521" alt="image" src="https://github.com/user-attachments/assets/d0cc3c71-8fb1-446d-83ce-ac8496ca331d" />

---

## Reverse Proxy / MITM Campaigns

Instead of a fake landing page, you can proxy a real website through DropoutJeep. The victim sees the actual site, but all traffic goes through your server first.

### How It Works

1. Create a campaign with **Flow type:** `Reverse Proxy (MITM)`
2. Configure the target URL (e.g., `https://login.microsoft.com`)
3. Add content manipulation rules (strip headers, inject scripts, etc.)
4. Send victims the proxy URL instead of the real URL
5. When they enter credentials, you capture them transparently

### Creating a Proxy Campaign

1. Go to `/admin/campaign/new`
2. Select **Flow type:** `Reverse Proxy (MITM)`
3. Fill in name, subject, sending profile, recipients
4. Save, then go to the proxy config page at `/admin/campaign/<id>/proxy`
5. Set:
   - **Target URL** - The real site to proxy
   - **Static Prefix** - Random string for injected assets
   - **Upstream Proxy** - Optional egress proxy
   - **Enabled Plugins** - Check the plugins you want
   - **Content Manipulation Rules** - JSON rule array
6. Click **Save Config**

<img width="791" height="496" alt="image" src="https://github.com/user-attachments/assets/d450767e-7c8b-480a-b7e0-4ee1db5b9c43" />


### Proxy URL Structure

```
http://localhost:5000/proxy/15/login
_____________________  _  ____
     DropoutJeep     ID  target path
```

- `/proxy/15/` - Proxies the target root
- `/proxy/15/login` - Proxies `/login` on the target
- `/proxy/15/static/logo.png` - Proxies `/static/logo.png`

### Content Manipulation Rules - Script Kiddie Blocked, figure it out yourself

Rules tell the proxy what to modify. Format:

```json
```

### Upstream Egress Proxy

Route proxy traffic through an upstream proxy (HTTP, HTTPS, SOCKS5):

1. Open proxy config for your campaign
2. Set **Upstream Proxy** to:
   - `http://user:pass@proxy:8080`
   - `https://proxy:8080`
   - `socks5://127.0.0.1:1080`
   - `socks5h://127.0.0.1:1080`
3. Save

---

## All Features

### Email Features

- Rich HTML email builder with live preview
- SMTP sending with DKIM signing
- DKIM keypair generation and DNS record formatting
- SPF, DKIM, DMARC validation before sending
- IP/domain blacklist checking
- SMTP relay validation
- Recipient management (one per line or batch import)
- Email template marketplace with built-in templates
- A/B testing with weighted distribution
- Sender rotation pools (rotate across multiple identities)
- Quick-launch API (create and send in one call)
- Campaign scheduling (one-time or cron-based recurring)
- Campaign cloning with parent-child tracking
- Campaign versioning (snapshot state before changes)
- Enterprise mailer backend for high deliverability
- HTML smuggling (encode file payloads into HTML)
- Calendar invite simulation (ICS files)
- QR code generation per recipient
- Clean URLs (`/l/<token>` instead of raw tracking links)
- Redirector chain support with health checking
- Per-recipient proxy URL assignment (multi-domain)

### Landing Page Features

- Jinja2-style templates with placeholders
- Credential capture (form submissions logged as events)
- MFA relay (capture and relay MFA codes in real time)
- Browser fingerprinting (JavaScript fingerprint collector)
- Canary tokens (URL and image based)
- Landing page variants for A/B testing
- Success/acknowledgment pages
- Post-capture training pages
- Probe beacon (mouse movement and webdriver detection)

### Proxy Features

- Transparent reverse proxy of any target URL
- Content manipulation rules (JSON-based)
- Strip security headers (X-Frame-Options, CSP, etc.)
- Inject JavaScript into pages
- Replace form actions to POST through proxy
- Raw string replacement in responses
- CSS selector-based element replacement
- Request and response header modification
- Conditional rules (based on risk score or click count)
- YAML plugin system (declarative rules)
- Python plugin system (advanced logic)
- Cookie capture (intercept Set-Cookie and Cookie headers)
- Cookie validation (replay captured cookies to check if sessions are still valid)
- Credential extraction (parse POST bodies for passwords)
- MFA relay through proxy
- Full request/response logging
- Upstream egress proxy (HTTP, HTTPS, SOCKS5)
- Per-recipient proxy URLs (`/proxy/<id>/t/<token>/path`)
- Standalone async proxy server (port 8080) with WebSocket support
- Template variable interpolation in rules
- TLS fingerprint spoofing (JA3 impersonation via curl_cffi)
- Browser-in-the-middle rendering (Playwright/Chromium with CAPTCHA detection)
- Heatmap JS injection (track click coordinates on pages)

### OAuth and SAML Phishing

**OAuth Phishing:**
- Build OAuth2 authorization URLs that redirect victims to real providers (Microsoft, Google, etc.)
- Capture authorization codes after victim authenticates
- Exchange captured codes for access/refresh/id tokens
- State parameter encodes campaign ID and recipient token (base64)
- Captured tokens stored in `OAuthTokenCapture` and `CapturedOAuthToken` tables

<img width="695" height="590" alt="image" src="https://github.com/user-attachments/assets/ebcb7f4c-3c90-452c-813f-a86211fb3b4d" />


**SAML Relay:**
- Intercept base64-encoded SAMLResponse assertions from identity providers
- Decode and store SAML assertions for analysis
- Relay captured SAMLResponse to the real service provider's ACS URL (stealth mode)
- Maintain victim's legitimate session after capture
- Track relay status per recipient

### Tracking and Analytics

- Event types: open, click, credential_attempt, mfa_attempt, flow_complete, fingerprint, calendar_download, training_started, training_completed, user_report, probe, exfil_http, exfil_dns, bounce, saml_response_capture, oauth_auth_code_capture
- Per-recipient HMAC-signed tracking tokens
- MITRE ATT&CK technique mapping on events
- Event triage (acknowledge/dismiss)
- Real-time WebSocket dashboard
- Campaign funnel analysis
- Heatmap generation for landing pages (JavaScript captures click coordinates and CSS selectors)
- Recipient timeline (chronological events)
- Campaign comparison
- CSV and PDF export
- Domain reputation scoring (VirusTotal integration, warmup volume limits)
- Timing analytics (sent-to-open, click-to-credential, percentiles p50/p90/p95)
- Risk scoring (open=1, click=3, credential=7, mfa=10; 0-100 scale with buckets)
- JWT id_token parsing (decode claims without signature validation)
- HTTP and DNS exfiltration recording (base64/hex encoded data capture)

### Anti-Detection

- Sandbox evasion (detect Cuckoo, Any.Run, VirusTotal, headless Chrome, Selenium)
- Browser fingerprint correlation (track recipients across campaigns)
- Header rotation (browser-like User-Agent and Accept headers)
- Referer-chain simulation
- Polymorphic payloads (unique variants per recipient: OOXML comment injection, binary trailer append, text comment insertion)
- Timing analytics (detect automated analysis)
- TLS fingerprint spoofing (impersonate Chrome, Safari, Firefox JA3 fingerprints)
- Browser-in-the-middle rendering (real Chromium with CAPTCHA detection)

<img width="692" height="402" alt="image" src="https://github.com/user-attachments/assets/11736379-080e-4744-8bca-4a3968696066" />


### C2 Connectors

DropoutJeep can push captured credentials and session cookies to C2 frameworks automatically in a background thread.

**Supported frameworks:**

| Framework | Transport | Config Keys |
|-----------|-----------|-------------|
| Cobalt Strike | HTTP(S) POST | `url`, `password`/`secret` (Bearer auth), `team_server` |
| Mythic | HTTP(S) POST | `url`, `api_token` (Bearer auth), `callback_uuid` |
| Sliver | gRPC or HTTP(S) | `grpc_url` (gRPC mode), `url` (HTTP fallback), `api_token`/`password`/`secret` |

**How dispatch works:**
- When a credential or cookie is captured by the proxy or landing page, all active C2 connectors receive the payload
- Dispatch runs in a background thread (2-worker pool) so it never blocks the proxy response
- Payload format: `{type, data, timestamp}` with framework-specific fields (team_server, callback_uuid)

**Setup:**
1. Go to `/admin/c2-connectors/`
2. Create a connector: select framework, enter URL and auth credentials
3. Toggle connectors on/off per framework
4. API endpoints: `/api/c2/connectors/` (bearer token auth with `campaigns:read`/`campaigns:write` scopes)

<img width="630" height="521" alt="image" src="https://github.com/user-attachments/assets/17110814-9dce-4731-a6e3-5f11130a624d" />


### Auto-Reply Engine

IMAP-based auto-reply system with rule matching and manual approval workflow.

**How it works:**
1. Connects to IMAP (SSL/TLS or plaintext) and polls for UNSEEN messages
2. Filters messages against rules (regex patterns for sender and subject)
3. Builds templated replies with `Re:` prefix and `{subject}` placeholder
4. Either auto-sends or stages as `PendingReply` for manual operator approval

**Rule configuration:**
- `filter_sender_pattern` - Regex to match sender email
- `filter_subject_pattern` - Regex to match subject line
- `reply_template_html` - HTML reply body
- `reply_subject_template` - Subject line (use `{subject}` for original subject)
- `max_replies_per_session` - Limit replies per IMAP polling session
- `delay_seconds` - Delay between sends
- `auto_approve` - Skip manual approval queue

**Setup:**
1. Configure IMAP: set `IMAP_HOST`, `IMAP_USER`, `IMAP_PASS` environment variables, or use a SendingProfile's IMAP settings
2. Go to `/admin/auto-reply/` and create rules
3. Manually fetch, review, approve, or reject pending replies
4. Or enable auto-approve for hands-off operation via APScheduler

**Bounce processing:**
- Automatically parses NDR (bounce) messages to extract failed email addresses
- Logs `bounce` events linked to recipients
- Admin UI at `/admin/bounce/` for manual testing
- Background processing via `mail_ingest.py`

### Webhooks

Outbound webhook dispatch with HMAC-SHA256 signed payloads and configurable event filtering.

**Setup:**
1. Go to `/admin/webhooks/`
2. Create a webhook with:
   - **Name** - For your reference
   - **URL** - Your receiving endpoint
   - **Secret** - For HMAC signature verification
   - **Event types** - Select which events trigger the webhook
   - **Campaign scope** - Optional: limit to a specific campaign
3. Save

**Supported event types:** sent, open, click, credential_attempt, mfa_attempt, proxy_credential_capture, proxy_mfa_capture, proxy_session_cookie_capture, canary_triggered, fingerprint, flow_complete, training_started, training_completed, send_failed

**Verifying webhooks:**
- Each POST includes an `X-DropoutJeep-Signature` header
- Format: `sha256=<hmac-sha256-of-body-using-secret>`
- Verify the HMAC matches to confirm the payload is authentic

**Status tracking:**
- Each webhook records `last_status` (HTTP status code or error) and `last_sent_at`
- Dispatch runs in a background thread (4-worker pool)

<img width="644" height="472" alt="image" src="https://github.com/user-attachments/assets/ed93ce3e-17d8-4aae-8805-00d334e35810" />

### Suppression List

Block specific emails or domains from receiving campaign emails.

**Features:**
- Suppress by exact email address or entire domain
- Source tracking for audit trail
- CSV import (with `email` header) and plain text import (one per line)
- CSV export with email, domain, source, created_at columns
- Automatic deduplication and validation during import
- Campaigns automatically filter suppressed recipients before sending

**Setup:**
1. Go to the suppression list in the admin UI
2. Add emails/domains manually or import a CSV
3. Suppressed entries are respected across all campaigns

### Infrastructure

- Role-based access control (admin, operator, viewer)
- Multi-user support with password hashing
- Audit logging (every admin request logged)
- API tokens (bearer-token auth with scoped permissions)
- Rate limiting (per-path limits)
- Settings management (key-value store)
- Data retention (configurable event purge, default 90 days)
- Database migration (idempotent additive schema upgrades)
- Payload staging (encrypted at rest, per-recipient polymorphism)
- Clean URLs (`/l/<token>` instead of raw tracking links)
- Redirector chain support with health checking and open-redirect obfuscation
- Per-recipient proxy URL assignment via wildcard subdomains
- Domain routing (multi-domain proxy support with auto DNS/TLS provisioning)

<img width="786" height="323" alt="image" src="https://github.com/user-attachments/assets/2952e225-f0d6-46ad-b486-d54530afc4a8" />

---

## How to Run a Successful Campaign

### Before You Start

1. **Get written authorization** from management. Never run phishing tests without approval.
2. **Define your scope** - who is being tested, what you're measuring, timeline.
3. **Set up your infrastructure** - make sure SMTP, DNS, and TLS are working.
4. **Warm up your sending domain** - don't send hundreds of emails from a cold domain.

### Planning

1. **Pick a realistic scenario** - fake password reset, IT notification, HR announcement, shipping notification.
2. **Know your target audience** - adjust language and urgency for technical vs non-technical staff.
3. **Set up proper tracking** - use the pre-flight checks to validate SPF/DKIM/DMARC.
4. **Prepare your landing page** - make it look like a real login page your organization uses.

### Sending

1. **Start small** - send to 5-10 people first, verify everything works.
2. **Check deliverability** - monitor bounce rates and spam complaints.
3. **Stagger sends** - don't blast everyone at once. Use rate limiting.
4. **Time it right** - send during business hours for realistic engagement.

### After Sending

1. **Monitor events** in real time via the dashboard.
2. **Wait 24-48 hours** before analyzing results.
3. **Look at the funnel** - sent -> opened -> clicked -> submitted.
4. **Identify patterns** - which departments clicked, what time, what device.
5. **Export results** for your report.

### Tips for Better Results

- Use `{{TRACK_LINK}}` prominently in the email body
- Make the subject line urgent but believable
- The landing page should match your organization's real login page
- Use `{{FINGERPRINT_SCRIPT}}` to correlate recipients across devices
- Set up A/B testing to compare different approaches
- Use canary tokens to detect who shares the email
- For MFA targets, set up the MFA relay to capture codes in real time
- Enable QR codes (`{{QR_CODE}}`) for mobile-targeted campaigns
- Use redirector chains with open-redirect obfuscation to avoid URL blocking
- Set up sender rotation pools to spread sends across multiple identities
- Enable cookie validation to check if captured sessions are still valid
- Configure C2 connectors to push captures to your engagement framework
- Use wildcard proxy domains for cleaner per-recipient URLs (`<token>.domain.com`)
- Enable TLS fingerprint spoofing to avoid JA3-based detection
- Use the auto-reply engine to respond to out-of-office messages automatically

### Reporting

1. Export the campaign data (CSV or PDF)
2. Include: total sent, opens, clicks, credential captures, MFA captures
3. Calculate click-through rate and credential submission rate
4. Note any patterns (departments, time of day, device types)
5. Provide recommendations for training based on results

---

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `FLASK_SECRET` | random UUID | Session signing and encryption key |
| `ADMIN_USERNAME` | — | Initial admin username |
| `ADMIN_PASSWORD` | — | Initial admin password |
| `BASE_URL` | `http://localhost:5000` | Public URL for tracking links |
| `HMAC_SECRET` | `change-me-big-secret` | Signs recipient tracking tokens |
| `DATABASE_URL` | `sqlite:///phish.db` | Database connection string |
| `AUDIT_LOG` | `audit.log` | Audit log file path |
| `RETENTION_DAYS` | `90` | Event purge age |
| `HOST` | `0.0.0.0` | Flask bind address |
| `PORT` | `5000` | Flask bind port |
| `PROXY_HOST` | `0.0.0.0` | Standalone proxy bind address |
| `PROXY_PORT` | `8080` | Standalone proxy bind port |
| `FLASK_DEBUG` | `0` | Enable debug mode |
| `USE_PROXYFIX` | `0` | Enable Werkzeug ProxyFix |
| `PROXYFIX_X_FOR` | `1` | Trusted X-Forwarded-For hops |
| `PROXYFIX_X_PROTO` | `1` | Trust X-Forwarded-Proto |
| `FERNET_KEY` | derived from FLASK_SECRET | Encryption key for stored passwords |
| `PHISH_DOMAIN` | — | Public phishing domain (Docker/Caddy) |
| `DIALER_POOL_SIZE` | `2` | SMTP connection pool size |
| `ENABLE_PLUGINS_UI` | off | Show Python plugin UI to admins |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal API key for domain reputation scoring |
| `IMAP_HOST` | — | IMAP server for auto-reply and bounce processing |
| `IMAP_USER` | — | IMAP username |
| `IMAP_PASS` | — | IMAP password |

---

## Running Behind a Reverse Proxy

If you put DropoutJeep behind Cloudflare, a load balancer, or another proxy, enable ProxyFix:

```bash
export USE_PROXYFIX=1
export PROXYFIX_X_FOR=1
export PROXYFIX_X_PROTO=1
```

Optional:

```bash
export PROXYFIX_X_HOST=0
export PROXYFIX_X_PORT=0
export PROXYFIX_X_PREFIX=0
```

Make sure your upstream proxy strips untrusted `X-Forwarded-*` headers from end users.

---

## Security Notes

- **Authorization required.** Only use for authorized testing.
- **Credentials are encrypted by default.** Each campaign has a toggle to store captured credentials in plaintext or encrypted form; encrypted values are decrypted only in the admin UI for authorized users.
- **Encrypt secrets.** Set a strong `FERNET_KEY` or `FLASK_SECRET` for at-rest encryption.
- **Restrict admin access.** Put the admin UI behind VPN, IP allowlist, or authenticated proxy.
- **No built-in TLS.** Run behind nginx, Caddy, Cloudflare, or another TLS proxy in production.
- **Validate email config.** Check SPF/DKIM/DMARC before sending to protect deliverability.
- **ProxyFix caution.** Without a trusted upstream proxy, visitors can spoof their IP.

---

## Compliance

Use DropoutJeep only in accordance with your organization's security policy and applicable law. Unauthorized phishing is illegal in most jurisdictions.
