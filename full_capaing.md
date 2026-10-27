# DropoutJeep: The Complete Beginner's Guide
## From "I don't know what a VPS is" to "My first campaign is live"

**Hello!** This guide is written for regular humans — accountants, managers, students, or anyone who has been asked to run a security-awareness phishing simulation and feels overwhelmed. We will go slowly. No step is skipped. Think of this as building a food truck: first we need a kitchen (the server), a sign (the domain), ingredients (templates), a menu (campaign), and then we start serving customers (sending emails).

> **Important safety note:** DropoutJeep is a powerful red-team / phishing-simulation tool. Only use it against people and organizations that have given you **written permission**. Unauthorized phishing is illegal in almost every country.

---

## Table of Contents

1. [What is DropoutJeep?](#what-is-dropoutjeep)
2. [What you need before you start](#what-you-need-before-you-start)
3. [Step 1: Buy a VPS (your kitchen)](#step-1-buy-a-vps-your-kitchen)
4. [Step 2: Buy a domain (your sign)](#step-2-buy-a-domain-your-sign)
5. [Step 3: Point your domain at your VPS](#step-3-point-your-domain-at-your-vps)
6. [Step 4: Install DropoutJeep](#step-4-install-dropoutjeep)
7. [Step 5: Configure your environment](#step-5-configure-your-environment)
8. [Step 6: First login](#step-6-first-login)
9. [Step 7: The dashboard](#step-7-the-dashboard)
10. [Step 8: Create a subsidiary (your sending identity)](#step-8-create-a-subsidiary-your-sending-identity)
11. [Step 9: Set up email authentication (DKIM, SPF, DMARC)](#step-9-set-up-email-authentication-dkim-spf-dmarc)
12. [Step 10: Create a sending profile (SMTP)](#step-10-create-a-sending-profile-smtp)
13. [Step 11: Build an email template](#step-11-build-an-email-template)
14. [Step 12: Build a landing page](#step-12-build-a-landing-page)
15. [Step 13: Create a campaign](#step-13-create-a-campaign)
16. [Step 14: Add recipients](#step-14-add-recipients)
17. [Step 15: Run preflight checks](#step-15-run-preflight-checks)
18. [Step 16: Send the campaign](#step-16-send-the-campaign)
19. [Step 17: Watch results](#step-17-watch-results)
20. [Step 18: Clean up and retire data](#step-18-clean-up-and-retire-data)
21. [All the other features (the long list)](#all-the-other-features-the-long-list)
22. [Troubleshooting](#troubleshooting)

---

## What is DropoutJeep?

DropoutJeep is a web application that helps security teams run **phishing simulations**. In plain English: it sends realistic-looking test emails to employees, tracks who opens them and clicks the links, and records who types credentials into a fake login page. The goal is to train people to recognize real attacks, not to trick them maliciously.

It has a lot of advanced features (proxy servers, C2 connectors, exfiltration channels, MFA relay, etc.) but you do not need all of them to send your first campaign. This guide starts simple and then explains the advanced toys later.

---

## What you need before you start

You do not need to be a programmer, but you need:

1. **A credit card or PayPal** to rent a VPS and buy a domain.
2. **A computer with an SSH client.**
   - Windows 10/11: open PowerShell or Command Prompt. `ssh` is built in.
   - Mac: open Terminal.
   - Linux: you already know.
3. **An SMTP server** to send emails. This can be:
   - A business email service like Amazon SES, Mailgun, SendGrid, or Microsoft 365.
   - Your own mail server.
   - A cheap transactional-email provider.
4. **Patience.** The first setup takes 1–2 hours. After that, each campaign takes 10 minutes.

---

## Step 1: Buy a VPS (your kitchen)

A **VPS** (Virtual Private Server) is just a computer in someone else's data center that you rent by the month. DropoutJeep needs to run 24/7 so that tracking links and landing pages work when recipients click them hours or days later.

### Recommended VPS providers

- **Linode** (now Akamai)
- **DigitalOcean**
- **Vultr**
- **Hetzner** (cheap, EU-based)
- **AWS Lightsail**

### What specs do you need?

For small simulations (a few thousand emails):

| Item | Minimum | Comfortable |
|---|---|---|
| RAM | 2 GB | 4 GB |
| CPU | 1 core | 2 cores |
| Disk | 25 GB SSD | 50 GB SSD |
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |
| Location | Same country as targets | Same country as targets |

### Steps to buy

1. Create an account with the provider.
2. Click "Create Linode" / "Create Droplet" / "Deploy Instance".
3. Choose **Ubuntu 22.04 LTS**.
4. Choose the smallest plan that meets the table above.
5. Choose a data center close to your target audience.
6. Add an SSH key (recommended) or use a root password.
7. Create the server.
8. Write down the **IP address** the provider gives you. It looks like `203.0.113.45`.

### Log in to your VPS

Open your terminal and run:

```bash
ssh root@203.0.113.45
```

Replace `203.0.113.45` with your real IP. Type `yes` if it asks about fingerprints, then enter your password.

Once you see a prompt like `root@ubuntu:~#`, you are in.

---

## Step 2: Buy a domain (your sign)

A **domain** is the address people type to reach you, like `example.com`. For phishing simulations, you usually want a domain that looks similar to a real brand but is clearly owned by you. For example, if you are simulating a Microsoft login, you might buy `micros0ft-security-alert.com` (with a zero). Never use a real brand's domain without permission.

### Where to buy

- **Namecheap**
- **Cloudflare Registrar**
- **Porkbun**
- **GoDaddy** (more expensive, works fine)

### Tips

- Turn on **Whois privacy** so your personal address and phone number are hidden.
- Buy a `.com`, `.net`, or country-specific domain (`.co.uk`, `.de`, etc.).
- Avoid free domains like `.tk` — email providers block them.

After purchase, the registrar will show you a **DNS management** page. Leave it open; we return in Step 3.

---

## Step 3: Point your domain at your VPS

DNS is like the phone book of the internet. When someone types your domain, DNS tells their browser which server IP to call. You need to create an **A record** that points your domain to your VPS IP.

### Subdomains you will need

For a basic setup, you need at least:

| Subdomain | Purpose |
|---|---|
| `@` (root) | The admin dashboard |
| `bounce` | Receiving bounced emails |

For advanced setups you may also want:

| Subdomain | Purpose |
|---|---|
| `*.campaigns` | Per-campaign proxy/landing pages |
| `track` | Tracking links |

### How to create the records

In your registrar's DNS page:

1. Find the section called **DNS Records**, **Manage DNS**, or **Advanced DNS**.
2. Add an **A record**:
   - Host: `@` (or leave blank, depending on registrar)
   - Value: your VPS IP
   - TTL: 300 or Auto
3. Add another **A record**:
   - Host: `bounce`
   - Value: your VPS IP
   - TTL: 300 or Auto
4. If you want wildcard campaign domains later, add:
   - Host: `*.campaigns`
   - Value: your VPS IP
   - TTL: 300 or Auto

### Wait for DNS to spread

DNS changes take time. Usually 5–30 minutes, sometimes up to a few hours. You can check with:

```bash
nslookup yourdomain.com
```

When it shows your VPS IP, you are ready.

---

## Step 4: Install DropoutJeep

### Install Docker

On your VPS, run:

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
```

Log out and back in so the group applies. Check it worked:

```bash
docker --version
docker compose version
```

Both commands use `docker compose` with a space. The old `docker-compose` with a hyphen is version 1 and is not installed by that script.

### Download DropoutJeep

```bash
sudo mkdir -p /opt/dropoutjeep
sudo chown $USER /opt/dropoutjeep
git clone https://github.com/Lulztigre/DropoutJeep.git /opt/dropoutjeep
cd /opt/dropoutjeep
```

If you have local changes that are not pushed, upload your ZIP or archive to `/opt` and unpack it there instead.

Before you launch, create the `.env` file described in step 5 below. For the full server setup, meaning DNS, TLS and hardening, follow `VPS_DEPLOYMENT.md` instead of this page. It covers the same ground with more detail and it is kept current.

### Build and run with Docker (the easy way)

DropoutJeep ships with a `docker-compose.yml` file that runs two containers:

- `dropoutjeep`: the application.
- `caddy`: a reverse proxy that handles HTTPS automatically.

Run:

```bash
docker compose up -d
```

or, if you installed the plugin:

```bash
docker compose up -d
```

The first build takes a few minutes. When it finishes, run:

```bash
docker compose ps
```

You should see both containers as `Up`.

### The manual way (if you hate Docker)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python dropoutjeep.py
```

This starts the app on port 5000. You would still need Caddy or Nginx in front for HTTPS.

---

## Step 5: Configure your environment

DropoutJeep reads settings from environment variables. The easiest way is to create a `.env` file in the project root.

### Create the .env file

```bash
nano /opt/DropoutJeep/.env
```

Paste this, replacing every placeholder:

```env
# The domain you bought
PHISH_DOMAIN=yourdomain.com

# A long random string. Generate one with:
# python3 -c "import secrets; print(secrets.token_hex(32))"
FLASK_SECRET=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# Another long random string for signing tracking links
HMAC_SECRET=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

# Initial admin login. Change these!
ADMIN_USERNAME=admin
ADMIN_PASSWORD=UseAVeryStrongPassword123!

# How many hours a "Remember me" session lasts. Default 8.
SESSION_LIFETIME_HOURS=8

# Optional: use PostgreSQL instead of SQLite for bigger deployments
# DATABASE_URL=postgresql+psycopg2://user:password@host/db
```

### Generate real secrets

Run these on your VPS:

```bash
python3 -c "import secrets; print('FLASK_SECRET=' + secrets.token_hex(32))"
python3 -c "import secrets; print('HMAC_SECRET=' + secrets.token_hex(32))"
```

Copy the outputs into your `.env` file.

### Restart the app

```bash
cd /opt/DropoutJeep
docker compose down
docker compose up -d
```

### Check HTTPS

Caddy automatically requests an SSL certificate from Let's Encrypt. After a minute, open:

```
https://yourdomain.com
```

You should see a login page.

---

## Step 6: First login

1. Open `https://yourdomain.com` in your browser.
2. Enter the `ADMIN_USERNAME` and `ADMIN_PASSWORD` from your `.env` file.
3. The page asks **"Remember me on this device."**
   - **Leave it unchecked** on shared computers. This logs you out when you close the browser.
   - **Check it** on your own secure computer. It keeps you logged in for the number of hours set in `SESSION_LIFETIME_HOURS`.
4. Click **[ AUTHENTICATE ]**.

You are now on the dashboard.

---

## Step 7: The dashboard

The dashboard is called **Command Center**. It shows three big cards:

1. **Active Campaigns** — how many campaigns exist.
2. **Total Recipients** — how many people are in the system.
3. **Critical Events (24h)** — opens, clicks, credential attempts, etc.

Below that is a live event stream and links to every module. Do not worry about all the links yet. We will use them one by one.

### User roles

There are three permission levels:

| Role | Can do |
|---|---|
| **admin** | Everything: users, settings, delete data |
| **operator** | Create/edit/send campaigns, view results |
| **viewer** | View-only access to dashboards and reports |

As the first user, you are `admin`. Later you can create other users from **Admin → Users**.

---

## Step 8: Create a subsidiary (your sending identity)

A **subsidiary** in DropoutJeep is the identity your emails come from. It stores:

- The sending domain.
- The display name (what the recipient sees as the sender).
- The from address.
- DKIM signing keys.
- Bounce handling domain.

### Steps

1. In the top menu, click **Sending → Subsidiaries**.
2. Click **[ CREATE SUBSIDIARY ]**.
3. Fill in:
   - **Name**: something internal, like "Security Awareness Q3".
   - **Sending Domain**: `yourdomain.com`.
   - **Display Name**: something believable, like "IT Security".
   - **From Address**: `security@yourdomain.com`.
   - **Bounce Subdomain**: `bounce`.
   - **DKIM Selector**: `dkim`.
4. Click **Generate DKIM Keys**. This creates a private key (stored safely) and shows you a public DNS record.
5. Save the subsidiary.

---

## Step 9: Set up email authentication (DKIM, SPF, DMARC)

Email providers (Gmail, Outlook, etc.) check three things to decide if your email is legitimate. If you skip this, your emails go to spam or are rejected.

### DKIM (digital signature)

After you generated DKIM keys in Step 8, DropoutJeep showed you a DNS TXT record like:

```
Host: dkim._domainkey
Value: v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...
```

Add this TXT record in your registrar's DNS page.

### SPF (allowed senders)

Add a TXT record:

```
Host: @
Value: v=spf1 include:your-smtp-provider.com ~all
```

If you are sending directly from your VPS IP:

```
v=spf1 ip4:203.0.113.45 ~all
```

If you use both, combine them:

```
v=spf1 ip4:203.0.113.45 include:your-smtp-provider.com ~all
```

The `~all` means "soft fail" — emails from other sources should be treated suspiciously.

### DMARC (policy)

Add a TXT record:

```
Host: _dmarc
Value: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com; pct=100
```

- `p=quarantine` tells receivers to send failed emails to spam.
- `rua` is where aggregate reports go. Create an email address or mailbox to receive them.

### Test your DNS

Wait 10–30 minutes, then run:

```bash
dig TXT dkim._domainkey.yourdomain.com
dig TXT yourdomain.com
dig TXT _dmarc.yourdomain.com
```

You should see the records you added.

---

## Step 10: Create a sending profile (SMTP)

A **sending profile** tells DropoutJeep how to connect to your email-sending service.

### Steps

1. Click **Sending → Sending Profiles**.
2. Click **[ CREATE SENDING PROFILE ]**.
3. Fill in:
   - **Name**: e.g., "Primary SMTP".
   - **Subsidiary**: choose the one you created.
   - **SMTP Host**: from your email provider, e.g., `smtp.sendgrid.net`.
   - **SMTP Port**: usually `587` (STARTTLS) or `465` (SSL).
   - **SMTP User**: your provider username.
   - **SMTP Password**: your provider password or API key.
   - **Encryption**: STARTTLS or SSL/TLS.
   - **Rate Profile**: choose "Default" for now.
4. Save.

### Test it

DropoutJeep has a preflight tool. We use it in Step 15, but you can also go to **Sending → Sending Profiles**, click your profile, and look for a **Test Connection** option if available.

---

## Step 11: Build an email template

An email template is the message your targets receive. DropoutJeep uses a template language called **Jinja2** — basically HTML with placeholders.

### Steps

1. Click **Templates → Email Templates**.
2. Click **[ CREATE TEMPLATE ]**.
3. Give it a name like "Password Reset Simulation".
4. Write your subject line.
5. Write the email body.

### Important placeholders

DropoutJeep replaces these automatically for each recipient:

| Placeholder | What it becomes |
|---|---|
| `{{ first_name }}` | Recipient's first name |
| `{{ email }}` | Recipient's email address |
| `{{ campaign.name }}` | Campaign name |
| `{{ tracking_link }}` | A unique tracking/landing URL |

### Simple example

```html
<p>Hi {{ first_name }},</p>

<p>We noticed unusual activity on your account. Please verify your identity:</p>

<p><a href="{{ tracking_link }}">Verify Account</a></p>

<p>Thanks,<br>IT Security</p>
```

### Tips

- Keep it short. Real phishing emails are short.
- Do not use words like "URGENT!!!" or all caps — spam filters hate that.
- Test the template with the preview button.
- You can import templates from the **Template Marketplace** which has pre-built scenarios.

---

## Step 12: Build a landing page

A landing page is the fake website the victim sees after clicking the link. It might look like a login page, a document download, or a training page.

### Steps

1. Click **Templates → Landing Templates**.
2. Click **[ CREATE LANDING TEMPLATE ]**.
3. Give it a name.
4. Choose a **flow type**:
   - **credential_attempt**: collects username/password.
   - **training**: shows a training message after clicking.
   - **reverse_proxy**: forwards to a real site while capturing data.
   - **mfa_success**: for MFA-aware flows.
5. Paste HTML or use the visual editor if available.
6. Save.

### Using the branding clone (optional but fancy)

DropoutJeep can clone a real login page. Go to **Tools → Branding Clone**, paste a URL like `https://github.com/login`, and it builds a self-contained copy. This is great for realistic simulations but only clone sites you have permission to mimic.

### Important placeholders for credential pages

| Placeholder | What it becomes |
|---|---|
| `{{FORM_ACTION}}` | Where submitted credentials go |
| `{{USERNAME_FIELD}}` | Name of the username input |
| `{{PASSWORD_FIELD}}` | Name of the password input |

For credential flows, DropoutJeep usually injects a generic form automatically. If you build a custom page, include these placeholders.

---

## Step 13: Create a campaign

A **campaign** ties everything together: template, landing page, sending profile, and recipients.

### Steps

1. Click **Campaigns → New Campaign**.
2. Fill in the basics:
   - **Name**: "Q3 Security Awareness".
   - **Description**: optional notes.
   - **Sending Profile**: choose yours.
   - **Email Template**: choose your email template.
   - **Landing Template**: choose your landing page.
   - **Flow Type**: usually `credential_attempt` or `training`.
3. Configure tracking:
   - **Track Opens**: yes, embeds a hidden pixel.
   - **Track Clicks**: yes, rewrites links.
   - **Sandbox Evasion**: yes, serves a safe page to bots.
4. Optional settings:
   - **Schedule**: send now or later.
   - **Redirector Chain**: obfuscate links through intermediate URLs.
   - **Canary Token**: embed a hidden trap link.
5. Save.

---

## Step 14: Add recipients

Recipients are the people who will receive the email.

### Add one at a time

1. Go to **Campaigns → Your Campaign → Recipients**.
2. Click **[ ADD RECIPIENT ]**.
3. Enter first name, last name, email, and optional notes.

### Bulk import

1. Prepare a CSV or Excel file with columns:
   - `email` (required)
   - `first_name`
   - `last_name`
   - `department`
   - `notes`
2. Go to **Recipients → Import**.
3. Upload the file.
4. Map columns if needed.
5. Import.

### Suppression list

If someone opts out or should never be emailed, add them to **Sending → Suppressions**. DropoutJeep will skip them.

---

## Step 15: Run preflight checks

Before sending, DropoutJeep can check that everything looks healthy.

### Steps

1. Open your campaign.
2. Click **Preflight** or **Validate**.
3. It checks:
   - DNS records.
   - SMTP connection.
   - SPF, DKIM, DMARC.
   - Domain reputation.
   - Redirector health.
   - Warmup limits.
4. Fix any red errors.
5. Run again until everything is green.

---

## Step 16: Send the campaign

You have three options:

### Send a test first

Always send a test to your own email addresses first.

1. In the campaign, click **Send Test**.
2. Enter one or two test email addresses.
3. Check that the email arrives, links work, and the landing page looks right.

### Send now

1. Click **Send Campaign**.
2. Confirm the recipient count.
3. Click **Start Sending**.

### Schedule for later

1. Set **Scheduled At** to a future date/time.
2. Save.
3. The scheduler automatically sends it.

---

## Step 17: Watch results

As emails go out, events appear in real time.

### What events mean

| Event | Meaning |
|---|---|
| `sent` | Email left our server. |
| `delivered` | Recipient's server accepted it. |
| `open` | Recipient opened the email (pixel loaded). |
| `click` | Recipient clicked a link. |
| `visit` | Recipient visited the landing page. |
| `credential_attempt` | Recipient typed username/password. |
| `mfa_attempt` | Recipient entered an MFA code (if enabled). |
| `training_complete` | Recipient finished the training module. |
| `bounce` | Email bounced back. |
| `unsubscribe` | Recipient clicked unsubscribe. |

### Where to watch

- **Dashboard** — live event stream.
- **Campaigns → Your Campaign → Analytics** — charts, timeline, geoIP.
- **Campaigns → Your Campaign → Funnel** — conversion funnel with drop-off.
- **Campaigns → Your Campaign → Credentials** — captured credentials (encrypted).
- **Campaigns → Your Campaign → Heatmap** — where people clicked.

### Triage events

If an event is a false positive or you have handled it, click **Acknowledge** or **Dismiss** to clean the stream.

---

## Step 18: Clean up and retire data

Security tools accumulate sensitive data. Clean up regularly.

### Steps

1. **Stop finished campaigns** so they no longer send.
2. **Purge old events** from **Admin → Purge Data**. You can purge by age, campaign, or event type.
3. **Rotate credentials** if you captured real passwords.
4. **Back up** the database before purging if you need records for compliance.
5. **Renew your domain** before it expires.

---

## All the other features (the long list)

DropoutJeep has many advanced modules. Here is what each one does, in plain English.

### Sending & deliverability

- **Rate Profiles**: limit how many emails per hour/day/month so providers do not block you.
- **Sender Rotation**: rotate between multiple sending identities so no single address gets burned.
- **Warmup**: gradually increase send volume to build reputation.
- **Domain Reputation**: checks VirusTotal, blacklists, and DNS auth status.
- **Bounce Handling**: reads an IMAP inbox and records bounced emails.
- **Auto-Reply**: polls an inbox and sends templated replies automatically.
- **Feedback Loop (FBL)**: registers complaint feedback loops with providers.

### Landing pages & tracking

- **Clean URLs**: short opaque links like `/l/abc123`.
- **QR Codes**: generate per-recipient QR codes for physical phishing tests.
- **Calendar Invites**: attach `.ics` invites that can track opens.
- **Canary Tokens**: hidden links/images that alert you when someone shares or scans them.
- **Fingerprinting**: JavaScript collects device info to detect sandboxes and correlate visits.
- **Heatmap**: visual map of where recipients click.
- **Sandbox Evasion**: serves a safe/decoy page to bots, sandboxes, headless browsers, and EDR tools.
- **HTML Smuggling**: delivers payloads inside obfuscated HTML.

### Proxy & capture

- **Reverse Proxy**: when a campaign is set to `reverse_proxy`, DropoutJeep sits between the victim and a real website, capturing credentials, cookies, and MFA codes.
- **MFA Relay**: captures an MFA code and replays it to the real site in real time.
- **Cookie Validation**: tests whether captured session cookies are still valid.
- **Credential Capture**: parses login forms automatically.
- **Proxy Rules**: YAML/JSON rules to rewrite pages, inject scripts, strip headers, etc.
- **Python Plugins**: custom proxy plugins with hooks for requests/responses.

### C2 & payloads

- **C2 Connectors**: push captured data to Cobalt Strike, Mythic, or Sliver.
- **Payload Generators**: build macro documents, HTA files, remote templates, search-ms shortcuts, OneNote packages, and hardened stagers.
- **Loot Exfil**: browser/implant endpoint for stolen secrets.
- **WebSocket C2**: live command-and-control over WebSockets.
- **Exfil Channels**: DNS-over-HTTPS, ICMP, and image steganography.

### Identity & deception

- **OSINT**: LinkedIn scraping and breach lookup.
- **Pretext Generator**: auto-generates plausible email scenarios.
- **Branding Clone**: clones real login pages for landing pages.
- **Domain Fronting / SaaS Mimicry**: makes traffic look like Teams/Slack/etc.
- **Redirector Chains**: multi-hop URL obfuscation.
- **Multi-Hop Proxy**: chains multiple proxies.

### Analytics & reporting

- **Funnel**: sent → delivered → opened → clicked → credentials.
- **Risk Scoring**: per-recipient and campaign-level risk.
- **A/B Testing**: test multiple email variants with weighted traffic.
- **Campaign Comparison**: side-by-side metrics.
- **CSV/PDF Export**: download events and reports.
- **MITRE ATT&CK Mapping**: map campaign actions to MITRE techniques.
- **Timing Analytics**: when recipients interact.
- **GeoIP**: where recipients are located.

### Security & administration

- **RBAC**: admin, operator, viewer roles.
- **API Tokens**: scoped bearer tokens for automation.
- **Audit Logging**: every authenticated request is logged.
- **CSRF Protection**: prevents cross-site request forgery.
- **Rate Limiting**: slows down brute-force attacks.
- **Data Retention**: configurable purge by age or campaign.
- **Suppression List**: honor opt-outs.

---

## Troubleshooting

### I cannot reach the web UI

1. Check that Docker containers are running: `docker compose ps`.
2. Check logs: `docker compose logs dropoutjeep`.
3. Check that DNS points to your VPS: `nslookup yourdomain.com`.
4. Check firewall: port 80 and 443 must be open.

### HTTPS does not work

1. Wait 2 minutes for Caddy to request a certificate.
2. Check Caddy logs: `docker compose logs caddy`.
3. Make sure your domain's A record points to the server IP.
4. Make sure port 443 is open.

### Emails go to spam

1. Verify DKIM, SPF, and DMARC records.
2. Use a clean domain with good reputation.
3. Warm up the domain slowly.
4. Avoid spammy words and all caps.
5. Use a reputable SMTP provider.
6. Check blacklist status in **Sending → Domain Reputation**.

### I forgot the admin password

1. SSH into the VPS.
2. Run:
   ```bash
   cd /opt/DropoutJeep
   docker compose exec dropoutjeep python - <<'PY'
   from dropoutjeep import app
   from dropoutjeep_lib.models import User
   from dropoutjeep_lib import db
   with app.app_context():
       u = User.query.filter_by(username='admin').first()
       u.set_password('newpassword')
       db.session.commit()
   PY
   ```
3. Log in with the new password.

### Tracking links do not work

1. Make sure `PHISH_DOMAIN` in `.env` matches the domain in the campaign.
2. Make sure DNS points to the VPS.
3. Make sure the campaign status is `running` or `sent`.

### The app is slow

1. Upgrade the VPS RAM to 4 GB.
2. Switch from SQLite to PostgreSQL by setting `DATABASE_URL`.
3. Reduce the number of recipients per batch.

---

## Final checklist before your first real campaign

- [ ] VPS rented and accessible via SSH.
- [ ] Domain purchased and DNS A records point to VPS.
- [ ] DropoutJeep running with Docker.
- [ ] `.env` has strong secrets and correct `PHISH_DOMAIN`.
- [ ] HTTPS works when visiting `https://yourdomain.com`.
- [ ] Admin user can log in.
- [ ] Subsidiary created with correct domain and from address.
- [ ] DKIM, SPF, DMARC records published and tested.
- [ ] Sending profile created and connection works.
- [ ] Email template created and preview looks correct.
- [ ] Landing template created and preview looks correct.
- [ ] Campaign created with correct template, landing page, and sending profile.
- [ ] Recipients imported or added.
- [ ] Test emails sent to yourself and colleagues.
- [ ] Preflight checks passed.
- [ ] Legal/HR approval obtained.
- [ ] Campaign sent.
- [ ] Results monitored.

---

**You did it!** DropoutJeep is a big tool, but you only need a small slice of it to run professional security-awareness campaigns. Start simple, test everything with your own inbox first, and only scale up after you are confident.
