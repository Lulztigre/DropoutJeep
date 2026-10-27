---
tags: [dropoutjeep, guide, phishing-simulation, security, ELI5]
aliases: [dropoutjeep-guide, campaign-playbook, djp-playbook]
created: 2026-07-30
---

# DropoutJeep — The Complete "Explain It Like I'm 5" Campaign Playbook

> [!info] Who this is for
> You know how to open File Explorer. You know how to type a web address. You know what email is. That's it. This guide assumes **zero** technical knowledge beyond that. Every button, every menu, every step — explained in plain English with no jargon left unexplained.

> [!warning] One rule before you start
> **Never, ever run a campaign without written permission from someone who owns or is responsible for the people you're testing.** This is like a fire drill — you don't pull the fire alarm as a prank. You do it because someone asked you to test whether everyone knows where the exits are.

---

## Table of Contents

- [[#Part 0 — What Is DropoutJeep (The 30-Second Version)|Part 0 — What Is DropoutJeep]]
- [[#Part 1 — Setting Up DropoutJeep (The Installation)|Part 1 — Setting Up]]
- [[#Part 2 — The Dashboard Tour (Where Everything Lives)|Part 2 — The Dashboard Tour]]
- [[#Part 3 — Phase 1: Before You Send (Preparation)|Part 3 — Phase 1: Preparation]]
- [[#Part 4 — Phase 2: Building the Campaign|Part 4 — Phase 2: Building the Campaign]]
- [[#Part 5 — Phase 3: Sending and Monitoring|Part 5 — Phase 3: Sending and Monitoring]]
- [[#Part 6 — Phase 4: After the Campaign (Results and Reporting)|Part 6 — Phase 4: Results and Reporting]]
- [[#Part 7 — Advanced Features (The Full Toolbox)|Part 7 — Advanced Features]]
- [[#Part 8 — The Gap Analysis Features (What Was Just Added)|Part 8 — New Gap Analysis Features]]
- [[#Part 9 — Troubleshooting|Part 9 — Troubleshooting]]
- [[#Part 10 — Quick Reference Cheat Sheet|Part 10 — Cheat Sheet]]
- [[#What changed in this revision|What changed in this revision]]

---

## Part 0 — What Is DropoutJeep (The 30-Second Version)

> [!abstract] The elevator pitch
> DropoutJeep is a **phishing simulation platform**. It sends fake phishing emails to your own employees to see who clicks. Think of it as a fire drill for email security. You send a fake "password expired" email, see who clicks the link and types their password, then train the people who fell for it.

It does three main things:

1. **Sends emails** that look like real phishing emails (but to your own people, with your permission)
2. **Builds fake login pages** that capture the credentials people type in (so you know who fell for it)
3. **Tracks everything** — who opened the email, who clicked the link, who typed their password

> [!tip] The analogy
> Imagine you're the building manager. You want to know if people lock the back door. Instead of waiting for a real burglar, you try the door yourself and make a note of who left it open. DropoutJeep is that — for email.

---

## Part 1 — Setting Up DropoutJeep (The Installation)

> [!info] Local machine or server?
> This part runs the app on your own machine with Python, which is right for testing and for reading the dashboard on localhost. A real engagement runs on a VPS behind Caddy with a real certificate, and that path is documented in `VPS_DEPLOYMENT.md`, with the automation in `deploy/`. The two are not interchangeable: the VPS path adds TLS, the proxy container, boot-time secrets and the admin allowlist.

> [!note] What you need first
> - A computer (Windows, Mac, or Linux)
> - Python installed (version 3.11 or newer)
> - The DropoutJeep folder downloaded to your computer
> - An SMTP server (this is the thing that sends email — your company's IT team can give you the details)

### Step 1: Open the folder

1. Open **File Explorer** (the yellow folder icon on your taskbar)
2. Navigate to the DropoutJeep folder (wherever you saved it)
3. You should see files like `dropoutjeep.py`, `requirements.txt`, and a folder called `dropoutjeep_lib`

### Step 2: Open a command prompt in this folder

> [!tip] How to open a command prompt
> 1. In File Explorer, click inside the address bar at the top (where it shows the folder path)
> 2. Type `cmd` and press Enter
> 3. A black window opens — this is your command prompt. It's like a text-based version of File Explorer

### Step 3: Create a virtual environment

> [!info] What's a virtual environment?
> Think of it like a sandbox. Everything DropoutJeep needs gets installed inside this sandbox so it doesn't mess up anything else on your computer.

Type this in the black command window and press Enter:

```
python -m venv venv
```

Wait a few seconds. You'll see a new folder called `venv` appear in File Explorer.

### Step 4: Turn on the virtual environment

On **Windows**, type:
```
venv\Scripts\activate
```

On **Mac/Linux**, type:
```
source venv/bin/activate
```

You'll know it worked when the line in your command window shows `(venv)` at the start.

### Step 5: Install the dependencies

> [!info] What are dependencies?
> DropoutJeep needs other software packages to work — like how a car needs gas, oil, and tires. This step installs all of that at once.

Type:
```
pip install -r requirements.txt
```

This will download and install everything. It takes a few minutes. You'll see lots of text scrolling by — that's normal. When it finishes, you'll see your prompt again.

### Step 6: Set the environment variables

> [!info] What are environment variables?
> These are like the settings on your microwave — they tell the program how to behave. You need to set a few before DropoutJeep will start.

On **Windows** (in the same command window, type each line and press Enter after each):

```
set FLASK_SECRET=any-random-long-string-here-make-it-weird
set ADMIN_USERNAME=admin
set ADMIN_PASSWORD=your-password-here
set BASE_URL=http://localhost:5000
set HMAC_SECRET=another-random-string-here
```

On **Mac/Linux**, use `export` instead of `set`:
```
export FLASK_SECRET="any-random-long-string-here-make-it-weird"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="your-password-here"
export BASE_URL="http://localhost:5000"
export HMAC_SECRET="another-random-string-here"
```

> [!warning] Important
> Replace `your-password-here` with an actual password you'll remember. This is what you'll use to log into DropoutJeep's admin panel.

### Step 7: Start DropoutJeep

Type:
```
python dropoutjeep.py
```

You'll see some text appear. When you see something like `Running on http://localhost:5000`, it's ready.

### Step 8: Open the admin panel

1. Open your web browser (Chrome, Firefox, Edge — any browser)
2. Type this in the address bar: `http://localhost:5000/admin`
3. You'll see a login screen
4. Type the username and password you set in Step 6
5. You're in!

> [!success] You did it!
> DropoutJeep is now running. Keep the black command window open — if you close it, DropoutJeep stops. To stop it manually, press `Ctrl+C` in the command window.

---

## Part 2 — The Dashboard Tour (Where Everything Lives)

> [!abstract] What you see when you log in
> The admin dashboard is like a car's dashboard — it shows you everything at a glance and gives you controls for every feature.

### Main sections (left sidebar or top menu):

| Menu Item | What It Does | When You Use It |
|-----------|-------------|-----------------|
| **Dashboard** | Home page — shows counts of campaigns, emails sent, people who clicked | Check the big picture |
| **Campaigns** | Create, manage, and send phishing campaigns | The main work area |
| **Templates** | Pre-made email templates you can reuse | When you want a quick start |
| **Subsidiaries** | Who the email appears to come from | Set up once, use forever |
| **Sending Profiles** | How DropoutJeep sends email (SMTP settings) | Set up once per email server |
| **Events** | Every action every recipient took | Investigating who did what |
| **Recipients** | Lists of people you're testing | Managing who gets emails |
| **Proxy** | MITM (Man-in-the-Middle) proxy settings | For advanced campaigns |
| **C2 Connectors** | Connect to external security frameworks | Advanced — for integration |
| **Auto-Reply** | Automatically respond to replies to phishing emails | For realistic conversations |
| **Settings** | System-wide configuration | Fine-tuning behavior |
| **Suppression List** | People who should never get test emails | Protecting VIPs or opt-outs |
| **Webhooks** | Send data to other systems automatically | Integration with other tools |
| **API Tokens** | Create keys for programmatic access | Advanced automation |

---

## Part 3 — Phase 1: Before You Send (Preparation)

> [!important] Do this before anything else
> You can't just start sending emails. You need to set up three things first: **who sends** (Subsidiary), **how they send** (Sending Profile), and **who receives** (Recipients). Think of it like setting up a mail merge in Outlook.

### 3.1 — Create a Subsidiary (Who the email is from)

> [!info] What's a subsidiary?
> A subsidiary defines the "from" identity — the name and email address the recipient sees in their inbox. It also holds the email authentication settings (SPF, DKIM, DMARC) that tell email providers your email is legitimate.

**Steps:**

1. Click **Subsidiaries** in the sidebar menu
2. Click the **New Subsidiary** button
3. Fill in the form:

| Field | What to Put | Example |
|-------|-------------|---------|
| **Name** | Internal label (only you see this) | IT Security Team |
| **Sending domain** | The domain after the @ sign | yourcompany.com |
| **Display name** | What recipients see as the sender name | IT Security |
| **From address** | The email address recipients see | security@yourcompany.com |
| **DKIM selector** | A label for your DKIM key — use `default` if unsure | default |
| **DKIM private key** | Optional — click "Generate" to create one automatically | (auto-generated) |

4. Click **Save**

> [!tip] What is DKIM?
> DKIM is like a wax seal on an envelope — it proves the email really came from you and wasn't tampered with. When you click "Generate," DropoutJeep creates a key pair (a private key and a public key). You put the public key in your DNS records (ask IT), and DropoutJeep uses the private key to "seal" every email.

> [!tip] What is SPF?
> SPF is like a guest list — it tells email providers which servers are allowed to send email from your domain. You add an SPF record to your DNS (ask IT to add `v=spf1 include:your-mail-server ~all`).

> [!tip] What is DMARC?
> DMARC is like a bouncer — it tells email providers what to do if an email fails SPF or DKIM checks. You add a DMARC record to your DNS (ask IT to add `v=DMARC1; p=quarantine; rua=mailto:postmaster@yourcompany.com`).

### 3.2 — Create a Sending Profile (How the email gets sent)

> [!info] What's a sending profile?
> A sending profile is the mailroom — it tells DropoutJeep which email server to use, what login credentials to use, and how to connect.

**Steps:**

1. Click **Sending Profiles** in the sidebar
2. Click **New Sending Profile**
3. Fill in the form:

| Field | What to Put | Example |
|-------|-------------|---------|
| **Name** | Internal label | Company SMTP |
| **SMTP host** | Your email server's address | smtp.yourcompany.com |
| **SMTP port** | Usually 587 (with TLS) or 465 (SSL) | 587 |
| **SMTP username** | Login for the email server | mailer@yourcompany.com |
| **SMTP password** | Password for the email server | ******** |
| **Use TLS** | Check this if using port 587 | ✓ |
| **Subsidiary** | Select the subsidiary you created above | IT Security Team |

4. Click **Validate SMTP** — this tests the connection. If it says "OK," you're good.
5. Click **Save**

> [!warning] If SMTP validation fails
> Check with your IT team that:
> - The SMTP host address is correct
> - The port is right (587 for TLS, 465 for SSL, 25 for plain)
> - The username and password are correct
> - Your IP address is allowed to send through that SMTP server

### 3.3 — Add Recipients (Who gets the email)

> [!info] What are recipients?
> Recipients are the people you're testing. You can add them one at a time, paste a list, or import a CSV file.

**Steps:**

1. You can add recipients directly when building a campaign (see Part 4), or pre-import them
2. To pre-import: Click **Recipients** in the sidebar
3. You can paste email addresses (one per line) or upload a CSV file with an `email` column
4. Suppressed emails (people on your suppression list) are automatically filtered out

### 3.4 — Set Up the Suppression List (Who should NEVER get emails)

> [!important] Do this before sending anything
> The suppression list is your safety net. Add anyone who should never receive a test email — executives, legal, external contractors, anyone who's opted out.

1. Click **Suppression List** in the sidebar
2. Add emails or entire domains (e.g., `@external-vendor.com` blocks everyone from that domain)
3. You can import a CSV file too
4. Suppressed emails are automatically filtered from every campaign — you don't have to remember

### 3.5 — Domain Reputation and Warmup

> [!info] What's domain warmup?
> If you suddenly send 1,000 emails from a brand-new domain, Gmail and Outlook will think you're a spammer and block you. You need to "warm up" the domain by sending small amounts first, then gradually increasing. It's like building credit — you can't get a mortgage on day one.

**How to warm up:**

1. Start by sending 10-20 emails per day for the first week
2. Increase to 50-100 per day in week 2
3. Increase to 500 per day in week 3
4. By week 4, you can send up to 5,000 per day

DropoutJeep can automate this with the **Warmup Manager** (Part 8, Section 8.2).

> [!warning] Volume alone is not warmup
> Sending 10, then 50, then 250 messages a day to mailboxes nobody reads builds no reputation, because reputation is earned by recipient engagement: opens, replies, moves out of spam. Automated warmup helps only when the recipients are real and reacting. For an enterprise target the stronger signal is domain age itself, since Proofpoint, Mimecast and Defender all hold newly registered domains against you for roughly the first 30 days, and no amount of ramp compensates for a domain registered last week.

**Domain reputation scoring:**

DropoutJeep checks your domain reputation using:
- **VirusTotal** — checks if your domain is flagged as malicious
- **WHOIS** — checks your domain age (newer = riskier)
- **DNSBL** — checks if your domain is on email blacklists
- A score from 0-100, with 10 warmup levels (0 = brand new, 10 = fully warmed up)

### 3.6 — Deliverability reality: what decides whether the mail lands

This playbook assumes no allowlisting. If the client's mail team whitelists your sending domain, the test measures nothing, and the click rate flatters everyone. The point of the tool is to find out what the gateway does when nobody is expecting you. That means the gateway is part of the target, and its verdict is a finding, not a failure.

What decides it, in order of weight

| Factor | Why it matters | What you can do |
|---|---|---|
| Domain age | Proofpoint, Mimecast and Defender keep newly registered domain lists with roughly a 30 day window. A domain from last week carries a penalty no content trick removes | Buy simulation domains before you need them, park them with mail and authentication live, send from the oldest |
| URL categorisation | An uncategorised domain reads as suspicious on its own in BrightCloud, Talos, FortiGuard, Webroot and Symantec | Publish a real root page, then submit the domain to each vendor as Business or Technology. One to four weeks |
| Authentication | SPF, DKIM and DMARC all present and aligned. A missing DMARC policy is a scoring hit by itself | The DNS records in Part 3, plus DKIM generated on the subsidiary so the key is actually stored |
| Sending IP | Shared hosting IPs carry the reputation of every other tenant, and get throttled | Pilot on shared hosting, then move the real send to a relay with a dedicated IP, same sending domain |
| Message shape | First contact from an unknown domain with a single link is the hardest shape to land | Plain text plus HTML, role-specific pretext, or an attachment, calendar invite or QR code instead of a bare link |
| Click-time scanning | URL Defense, TAP and Safe Links fetch the landing when the recipient clicks, from known sandbox ranges | Keep the IP and ASN filters on, and test them with a public scanner before the campaign |

What the tool cannot fix, and what to say about it

A domain registered this week will get a share of the list quarantined. That is the control working. Report it as three separate numbers, never one blended click rate:

1. Proportion quarantined by the gateway.
2. Proportion delivered.
3. Proportion clicked, counted against those delivered.

A blended rate over a list that was mostly blocked makes the client look better trained than they are and hides the control that actually caught you.

How to actually measure the quarantine number, since the app cannot

The tool only knows what reached it. Anything the gateway dropped never generates an event, so the blocked count has to come from outside:

1. Ask the client's mail team for a mail-flow export for the send window before you send. That is a reporting request, not an allowlist, and it does not change what the gateway does.
2. Or place one seed mailbox per department or tenant, on a domain the gateway also protects, so you can count what arrived in each.
3. Reconcile: recipients imported, minus addresses with a `sent` event, minus bounces, equals the gap you need to explain. If that gap is large, get the gateway numbers rather than guessing.

Without one of those, report delivered and clicked only, and say plainly that the blocked count is unmeasured. An invented number is worse than a missing one in a client deliverable.

Ramp inside the campaign rather than blasting the list: roughly 10 percent, then 25 percent a day later, then the rest, in the target's business hours, at 30 to 60 messages per minute.

Before the send, check the things the app cannot check for you

- [ ] The landing template has no absolute URLs pointing at the real site. Branding Clone strips them on generation and reports what it removed, but a hand-edited template can reintroduce one.
- [ ] Open tracking is off if the target runs a gateway that fetches pixels.
- [ ] The campaign timezone is set, not left at UTC.
- [ ] The bounce mailbox exists and is configured on the sending profile, otherwise the bounce rate reads zero.
- [ ] The sending domain is the oldest one you have, not the newest.

---

## Part 4 — Phase 2: Building the Campaign

> [!abstract] This is where the magic happens
> A campaign is the full package: the email, the landing page, the recipients, the sending settings, and the tracking. Let's build one from scratch.

### 4.1 — Create a New Campaign

1. Click **Campaigns** in the sidebar
2. Click **New Campaign**
3. Choose a **Flow Type**:

| Flow Type | What It Does | When to Use |
|-----------|-------------|-------------|
| **Single-step landing page** | Email → fake login page → credentials captured | Standard phishing test |
| **Reverse Proxy (MITM)** | Email → real website proxied through DropoutJeep | Advanced — target sees the real site |

4. Fill in the campaign details:

| Field | What to Put | Example |
|-------|-------------|---------|
| **Name** | Internal name for this campaign | Q3 Security Awareness Test |
| **Subject** | The email subject line | Action Required: Verify Your Account |
| **Sending Profile** | Select the profile you created | Company SMTP |
| **Subsidiary** | Select the subsidiary you created | IT Security Team |

### 4.2 — Write the Email

> [!info] Email body format
> The email body is written in HTML (the language web pages use). But you don't need to be a web developer — you can use a template, or write simple HTML.

**Special placeholders you can use:**

| Placeholder | What It Does |
|-------------|-------------|
| `{{TRACK_LINK}}` | A unique link for each recipient — when they click it, you know |
| `{{PIXEL}}` | An invisible image that tells you when the email was opened |
| `{{CANARY_URL}}` | A special URL that tells you if someone shared the email |
| `{{CANARY_IMAGE}}` | An image version of the canary |
| `{{FINGERPRINT_SCRIPT}}` | Collects browser info (what browser, what screen size) |
| `{{QR_CODE}}` | Generates a QR code for each recipient (for mobile campaigns) |

**Example email body:**

```html
<h2>Action Required: Verify Your Account</h2>
<p>Dear Employee,</p>
<p>We've detected unusual activity on your account. Please verify your
identity by clicking the link below.</p>
<p><a href="{{TRACK_LINK}}">Verify Now</a></p>
<p>If you did not request this, please disregard this email.</p>
<p>— IT Security Team</p>
{{PIXEL}}
```

> [!tip] Subject line tips
> - Make it urgent but not alarming: "Action Required" beats "URGENT!!!"
> - Reference something real: "Q3 Password Audit" beats "Security Update"
> - Don't use words that trigger spam filters: "FREE", "CLICK HERE", "ACT NOW"
> - Keep it under 60 characters

### 4.3 — Choose a Template (Optional Shortcut)

Instead of writing from scratch, you can use a pre-made template:

1. Click **Templates** in the sidebar
2. Browse the template marketplace
3. Categories include:
   - **IT Help Desk** — fake IT support emails
   - **OAuth Login** — fake "sign in with Microsoft/Google" pages
   - **Payroll** — fake payroll notification emails
   - **Shipping** — fake package delivery emails
   - **Finance** — fake payment confirmation emails (NEW)
   - **HR** — fake onboarding/employee emails (NEW)
   - **Legal** — fake contract review emails (NEW)
   - **Engineering** — fake security patch emails (NEW)
   - **Sales** — fake CRM credential emails (NEW)
   - **Executive** — fake board meeting materials (NEW)
4. Click a template to use it in your campaign

> [!tip] Role-specific templates
> The new role-specific templates (Finance, HR, Legal, Engineering, Sales, Executive) are designed for specific departments. Use the Finance template for finance staff, the HR template for HR staff, etc. People are more likely to click when the email references something they recognize from their daily work.

### 4.4 — Design the Landing Page

> [!info] What's a landing page?
> When someone clicks the link in the email, they go to a landing page. This is a fake login page that looks real. When they type their username and password, DropoutJeep captures it and records the event.

**Steps:**

1. In the campaign editor, find the **Landing Page** section
2. Write HTML for your fake login page

**Placeholders you can use:**

| Placeholder | What It Does |
|-------------|-------------|
| `{{TOKEN}}` | Each recipient's unique tracking token (REQUIRED in the form) |
| `{{TRACK_LINK}}` | The tracking link |
| `{{PIXEL}}` | Tracking pixel |
| `{{FINGERPRINT_SCRIPT}}` | Browser fingerprint collector |

**Example landing page:**

```html
<html>
<body>
  <h2>Sign In</h2>
  <form method="POST" action="/landing/{{TOKEN}}">
    <input type="hidden" name="token" value="{{TOKEN}}">
    <input type="text" name="username" placeholder="Email">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Sign In</button>
  </form>
  {{FINGERPRINT_SCRIPT}}
</body>
</html>
```

> [!warning] The form action matters
> The form's `action` must point to `/landing/{{TOKEN}}` — that's the route that records the `credential_attempt` event. `/track/<token>` is a GET-only click beacon; POSTing to `/track/{{TOKEN}}/credential` returns 404 and nothing is recorded. Omitting `action` entirely also works, since the page is served at `/landing/<token>`.

### 4.5 — Branding Clone (Quick Landing Page Creation)

> [!new] New feature
> Instead of designing a landing page from scratch, you can clone the look of a real login page.

1. Go to **Branding Clone** (Part 8, Section 8.5)
2. Enter the target company's login URL (e.g., `https://login.microsoft.com`)
3. Click **Clone**
4. DropoutJeep fetches the real page, extracts the CSS, logo, colors, and favicon
5. It generates a matching landing page template with `{{FORM_ACTION}}`, `{{USERNAME_FIELD}}`, and `{{PASSWORD_FIELD}}` placeholders
6. Use this template in your campaign

### 4.6 — Add Recipients to the Campaign

1. In the campaign editor, find the **Recipients** section
2. Paste email addresses (one per line) OR import a CSV file
3. Suppressed emails are automatically removed
4. You can also add recipients by importing from a previous campaign

### 4.7 — A/B Testing

> [!info] What's A/B testing?
> A/B testing means sending two different versions of an email to see which one gets more clicks. Version A goes to half the people, Version B goes to the other half. You compare the results.

1. In the campaign editor, find the **A/B Testing** section
2. Create variants with different:
   - Subject lines
   - Email bodies
   - Landing pages
3. Set the weight (percentage) for each variant
4. DropoutJeep distributes them automatically

### 4.8 — Pre-flight Checks (Before You Send)

> [!important] Always do this before sending
> Pre-flight checks are like the pilot's checklist before takeoff. They verify everything is configured correctly.

**Go to the campaign page and click "Validate":**

DropoutJeep checks:

| Check | What It Verifies |
|-------|-----------------|
| **SMTP connection** | Can DropoutJeep connect to your email server? |
| **SPF record** | Does your sending domain have an SPF DNS record? |
| **DKIM record** | Does your DKIM DNS record exist and match your key? |
| **DKIM key stored** | Does the subsidiary actually hold the private key? Without it every message goes out unsigned |
| **DMARC record** | Does your domain have a DMARC policy? |
| **Bounce mailbox** | Is IMAP configured? Without it bounces are never recorded and the bounce rate reads zero |
| **Blacklist check** | Is your domain or IP on any email blacklists? |
| **Domain reputation** | What's your VirusTotal reputation score? |
| **Spoof alignment** | Does the From header match the envelope sender? |

> [!note] BIMI and FBL are deliberately not part of pre-flight
> BIMI needs a paid Verified Mark Certificate and a trademark, so it is weeks of work for no benefit to a simulation. Feedback loops matter to bulk senders, not to a few hundred simulated messages. ARC only helps when mail is forwarded, and a self-generated seal carries no weight.

> [!tip] If pre-flight fails
> - **SPF fails**: Ask IT to add an SPF record to your DNS
> - **DKIM fails**: Make sure you generated a key and published the DNS record
> - **Blacklist**: Your domain or IP is flagged — don't send until it's resolved
> - **SMTP fails**: Check your sending profile credentials and port

### 4.9 — Campaign Settings (Advanced)

Before sending, you can configure these optional settings:

| Setting | What It Does |
|---------|-------------|
| **Schedule** | Send at a specific date/time, or set up recurring sends |
| **Rate limit** | How many emails per minute (don't flood the mail server) |
| **Sender rotation** | Rotate across multiple sending identities to spread the load |
| **Redirector chains** | Route tracking links through intermediate servers to avoid URL blocking |
| **Clean URLs** | Use `/l/<token>` instead of long tracking URLs |
| **EDR detection** | Serve a safe page if the visitor's machine has antivirus/EDR (NEW) |
| **IP reputation filter** | Serve a safe page if the visitor's IP is a known security scanner (NEW) |
| **Safe Links mode** | Handle O365 Safe Links URL rewriting (NEW) |

---

## Part 5 — Phase 3: Sending and Monitoring

### 5.1 — Send the Campaign

1. Go to your campaign page
2. Click the **Send** button
3. DropoutJeep starts sending emails in the background
4. The campaign status changes: `draft` → `running` → `completed`
5. You can watch progress on the dashboard

> [!tip] Start small
> For your first campaign, send to 5-10 people (maybe yourself and a few colleagues). Verify everything works before sending to hundreds of people.

### 5.2 — Real-Time Monitoring

> [!info] While the campaign runs
> You can watch everything happen in real time. It's like watching security camera footage — you see every door open, every person walk by.

**Dashboard** (`/admin`):
- Total emails sent
- How many were opened
- How many links were clicked
- How many credentials were captured
- How many MFA codes were captured

**Events** (`/events`):
- Every individual action, timestamped
- Filter by event type, campaign, or recipient
- Event types include: open, click, credential_attempt, mfa_attempt, fingerprint, bounce, training_started, training_completed, and many more

**Funnel** (`/admin/campaign/<id>/funnel`):
- Visual representation: Sent → Opened → Clicked → Submitted
- Shows where people drop off
- Percentage at each stage

**WebSocket Dashboard:**
- Real-time updates without refreshing the page
- Events appear as they happen

### 5.3 — What Happens When Someone Clicks

Here's the full chain of events when a recipient interacts with your campaign:

1. **Email arrives** in their inbox
2. They **open** it → `{{PIXEL}}` fires → you see an "open" event
3. They **click** the link → `{{TRACK_LINK}}` redirects them to your landing page → you see a "click" event
4. DropoutJeep checks:
   - Is this a sandbox/security scanner? → serve safe page (if evasion enabled)
   - Is this the same browser that opened the email? → fingerprint check
   - Does this IP look like a security researcher? → serve safe page (if IP reputation enabled)
5. They see your **landing page** (fake login)
6. They **type their credentials** → captured → you see a "credential_attempt" event
7. They see a **success page** or **training page** (you configure this)

### 5.4 — Auto-Reply Engine

> [!info] What if someone replies to the phishing email?
> The auto-reply engine monitors the sending mailbox (via IMAP) and can automatically respond to replies. This makes the campaign more realistic — if someone replies asking "Is this real?", the system can reply with a convincing response.

**Setup:**

1. Set IMAP environment variables:
   - `IMAP_HOST` — your IMAP server (e.g., imap.yourcompany.com)
   - `IMAP_USER` — the mailbox username
   - `IMAP_PASS` — the mailbox password
2. Go to **Auto-Reply** in the sidebar
3. Create rules:
   - **Filter sender pattern** — regex to match who the reply is from
   - **Filter subject pattern** — regex to match the subject line
   - **Reply template** — HTML for the auto-reply
   - **Auto-approve** — if checked, replies send automatically; if unchecked, they wait for your approval
4. Review pending replies and approve/reject them manually

---

## Part 6 — Phase 4: After the Campaign (Results and Reporting)

### 6.1 — Analyze Results

**Dashboard overview:**
- Total sent vs. total opened vs. total clicked vs. total credentials captured
- Click-through rate (percentage who clicked)
- Credential submission rate (percentage who typed their password)

**Funnel analysis:**
- Sent → Opened: Tells you if your subject line works
- Opened → Clicked: Tells you if your email body is convincing
- Clicked → Submitted: Tells you if your landing page is convincing
- Each stage has a percentage and time-to-action

**Event timeline:**
- Chronological view of every recipient's actions
- Filter by event type, date range, recipient

**Heatmap:**
- Visual map of where people clicked on the landing page
- Shows which elements attracted attention

**Timing analytics:**
- How long between send and open (p50, p90, p95 percentiles)
- How long between open and click
- How long between click and credential submission
- Helps identify automated vs. human behavior

**Risk scoring:**
- Each action has a risk score: open=1, click=3, credential=7, MFA=10
- Combined score per recipient on a 0-100 scale
- Helps prioritize who needs training most

### 6.2 — Export Results

1. Go to the campaign page
2. Click **Export**
3. Choose format:
   - **CSV** — spreadsheet (open in Excel)
   - **PDF** — formatted report (for management)
4. The export includes: recipient email, events, timestamps, risk score, credentials captured

### 6.3 — Reporting

> [!tip] What to include in your report
> 1. **Executive summary**: X% of staff clicked the phishing link, Y% submitted credentials
> 2. **By department**: Which departments had the highest click rates
> 3. **Timeline**: How quickly people clicked (some in under 5 minutes = need immediate training)
> 4. **Patterns**: Time of day, device type, browser
> 5. **Recommendations**: Who needs training, what type of training
> 6. **Trend**: Compare to previous campaigns (are things improving?)

> [!warning] Report three numbers, not one
> Quarantined by the gateway, delivered, and clicked among delivered. A single blended click rate hides the mail control that caught you and makes the training look better than it is. If the client's gateway blocked 40 percent of the list, that is the headline finding, and the click rate should be quoted against the 60 percent who ever saw the mail.

### 6.4 — Training Integration

After someone submits credentials on the landing page, you can:
- Show a **training page** instead of a success page
- The training page explains they just fell for a phishing test
- Include tips on how to spot phishing
- Track training completion as a separate event

---

## Part 7 — Advanced Features (The Full Toolbox)

> [!abstract] Everything DropoutJeep can do
> This section covers every feature in the system. You don't need all of these for a basic campaign, but they're available for more sophisticated operations.

### 7.1 — Reverse Proxy / MITM (Man-in-the-Middle)

> [!info] What's a MITM proxy?
> Instead of a fake landing page, DropoutJeep can proxy the REAL website. The target sees the actual login page (e.g., the real Microsoft login), but all traffic goes through DropoutJeep first. When they type their password, DropoutJeep captures it AND forwards it to the real site — so the login actually works and the target doesn't suspect anything.

**How to set up a MITM campaign:**

1. Create a campaign with **Flow Type: Reverse Proxy (MITM)**
2. Save the campaign, then go to the proxy config page
3. Set the **Target URL** (e.g., `https://login.microsoft.com`)
4. Set a **Static Prefix** (random string for injected assets)
5. Configure **Content Manipulation Rules** (JSON):
   - Strip security headers (X-Frame-Options, CSP)
   - Inject JavaScript into pages
   - Replace form actions to POST through the proxy
   - Replace text on the page
   - Replace HTML elements by CSS selector
6. Enable **Plugins** (pre-configured rule bundles)
7. Optionally set an **Upstream Egress Proxy** (HTTP, HTTPS, SOCKS5)

**Proxy URL structure:**
```
http://localhost:5000/proxy/15/login
                        |    |
                    Campaign ID  Target path
```

**Built-in plugins:**

| Plugin | What It Does |
|--------|-------------|
| `strip_security_headers` | Removes headers that prevent the page from being embedded |
| `inject_hook` | Adds a tracking script to all pages |
| `replace_login_form` | Replaces login forms to capture credentials |
| `steal_session_js` | Replaces JavaScript files to steal session tokens |

**Advanced proxy features:**

| Feature | What It Does |
|---------|-------------|
| **Cookie capture** | Intercepts Set-Cookie and Cookie headers |
| **Cookie validation** | Replays captured cookies to check if sessions are still valid |
| **Credential extraction** | Parses POST bodies for passwords |
| **MFA relay** | Captures and relays MFA codes in real time |
| **TLS fingerprint spoofing** | Makes the proxy look like a real browser (JA3 impersonation) |
| **Browser-in-the-middle** | Uses real Chromium to render pages (handles CAPTCHAs) |
| **Heatmap injection** | Tracks where people click on the page |
| **Full request/response logging** | Records everything for analysis |

### 7.2 — OAuth Phishing

> [!info] What's OAuth phishing?
> Instead of capturing a password, you capture an OAuth token — the thing that lets you access someone's account without their password. You trick the target into "authorizing" your app, and they grant you access to their Microsoft/Google/other account.

**How it works:**

1. DropoutJeep generates an OAuth2 authorization URL
2. The URL redirects the target to the real provider (Microsoft, Google)
3. They log in and "approve" your fake app
4. DropoutJeep captures the authorization code
5. DropoutJeep exchanges the code for access/refresh tokens
6. You now have access to their account

**Setup:**

1. Create a campaign with OAuth flow
2. Configure the OAuth provider (Microsoft, Google, etc.)
3. Set the client ID and redirect URI
4. The state parameter automatically encodes campaign ID and recipient token

### 7.3 — SAML Relay

> [!info] What's SAML relay?
> SAML is how many companies handle single sign-on (SSO). DropoutJeep can intercept the SAML response (the "ticket" that says "this person is authenticated") and replay it to access the real service.

**How it works:**

1. Target authenticates through DropoutJeep's proxy
2. The identity provider sends a SAML response
3. DropoutJeep captures and decodes the SAML assertion
4. DropoutJeep can relay it to the real service provider (stealth mode)
5. The target's legitimate session is maintained

### 7.4 — C2 Connectors (External Framework Integration)

> [!info] What's a C2 connector?
> If you're using a security framework like Cobalt Strike, Mythic, or Sliver, DropoutJeep can automatically push captured credentials and cookies to those frameworks. This is for advanced red team operations.

**Supported frameworks:**

| Framework | Transport | What Gets Pushed |
|-----------|-----------|------------------|
| Cobalt Strike | HTTP(S) POST | Credentials, cookies, tokens |
| Mythic | HTTP(S) POST | Credentials, cookies, tokens |
| Sliver | gRPC or HTTP | Credentials, cookies, tokens |

**Setup:**

1. Go to **C2 Connectors** in the sidebar
2. Create a connector: select framework, enter URL and auth credentials
3. Toggle connectors on/off
4. When credentials are captured, they're automatically pushed in a background thread

### 7.5 — Webhooks

> [!info] What's a webhook?
> A webhook is like a forwarding address — when something happens in DropoutJeep, it automatically sends a notification to another system. For example, when someone clicks a phishing link, you can have DropoutJeep send a notification to your Slack channel.

**Setup:**

1. Go to **Webhooks** in the sidebar
2. Create a webhook with:
   - **URL** — where to send the notification
   - **Secret** — for HMAC signature verification
   - **Event types** — which events trigger the webhook
   - **Campaign scope** — optional: limit to a specific campaign
3. Each notification includes an `X-DropoutJeep-Signature` header for verification

**Available event types:**
sent, open, click, credential_attempt, mfa_attempt, proxy_credential_capture, proxy_mfa_capture, proxy_session_cookie_capture, canary_triggered, fingerprint, flow_complete, training_started, training_completed, send_failed

### 7.6 — API Tokens

> [!info] What are API tokens?
> If you want to automate DropoutJeep (e.g., create campaigns from a script), you need an API token. It's like a password for the API.

1. Go to **API Tokens** in the sidebar
2. Create a token with scoped permissions:
   - `campaigns:read` — view campaigns
   - `campaigns:write` — create/modify campaigns
   - (other scopes available)
3. Use the token in API requests as a Bearer token

### 7.7 — HTML Smuggling

> [!info] What's HTML smuggling?
> Instead of attaching a file to an email, you embed the file inside an HTML page. When the recipient opens the page, JavaScript automatically downloads the file. This bypasses email filters that block attachments.

**How to use:**

1. Upload your payload file (DOCX, EXE, etc.)
2. DropoutJeep encodes it as base64 and embeds it in an HTML page
3. The HTML page uses obfuscated JavaScript (JJEncode + XOR chunks) to:
   - Wait for a mouse movement (interaction gate — defeats automated scanners)
   - Check for `navigator.webdriver` (headless browser detection)
   - Assemble the payload from 8 XOR'd chunks
   - Download the file automatically
4. Send the HTML page as the landing page or attachment

### 7.8 — Payload Types

DropoutJeep supports multiple payload delivery formats:

| Payload Type | Extension | What It Does |
|-------------|-----------|-------------|
| DOCX | .docx | Word document (with polymorphic variants) |
| XLSX | .xlsx | Excel spreadsheet |
| PPTX | .pptx | PowerPoint presentation |
| HTA | .hta | HTML Application (executes code) |
| LNK | .lnk | Windows shortcut file |
| ISO | .iso | Disk image |
| VHD/VHDX | .vhd/.vhdx | Virtual hard disk |
| BIN | .bin | Raw binary |

**Polymorphic payloads:**
Every recipient gets a slightly different file. DropoutJeep modifies the file in ways that don't affect functionality but change the file hash — so antivirus can't use one signature to catch all copies.

### 7.9 — Calendar Invites (ICS)

DropoutJeep can generate fake calendar invites that appear in the recipient's calendar. When they click "Accept," they're taken to the landing page.

### 7.10 — QR Codes

Generate a unique QR code per recipient. Useful for mobile-targeted campaigns — the recipient scans the QR code with their phone and goes to the landing page.

### 7.11 — Sender Rotation

If you're sending a large volume, you can rotate across multiple sending identities. Each email comes from a different sender, which helps avoid rate limits and spam filters.

### 7.12 — Redirector Chains

Route tracking links through intermediate servers (redirectors) before reaching the landing page. This makes the final URL harder to block. Redirectors are health-checked automatically.

---

## Part 8 — The Gap Analysis Features (What Was Just Added)

> [!abstract] 38 new features implemented
> A comprehensive gap analysis identified 38 areas where DropoutJeep needed improvement. All 38 have been implemented. Here's what they do and how to use them.

### 8.1 — Email Deliverability Improvements

#### 8.1.1 — Sim Headers Removed

> [!success] Fixed
> DropoutJeep used to add two headers to every email: `X-Mailer: DropoutJeep Mailer` and `X-DropoutJeep-Sim: true`. These were like writing "THIS IS A FAKE EMAIL" in invisible ink that Gmail and Outlook could read. They've been removed.

**What you need to do:** Nothing. This is automatic.

#### 8.1.2 — List-Unsubscribe Headers (opt-in)

Only sent when you configure a target. Set `UNSUBSCRIBE_TARGET` to an https URL and every message carries `List-Unsubscribe` plus `List-Unsubscribe-Post: List-Unsubscribe=One-Click` for RFC 8058. Set it to a mailbox address and you get the mailto form only. Leave it unset and no header is added at all, which is the right default: the old behaviour advertised `unsubscribe@<domain>` on every message even when that mailbox did not exist, and a bounce-generating unsubscribe address is a small negative signal.

**What you need to do:** Decide whether a simulated phishing mail should offer an unsubscribe link at all. Usually it should not.

#### 8.1.3 — Self-Asserted Authentication-Results (Removed)

> [!warning] Do not reintroduce the forged header
> The mailer used to add an `Authentication-Results` header claiming `dkim=pass, spf=pass, dmarc=pass`. It is gone as of this revision. RFC 8601 requires receivers to discard AR headers from untrusted sources, so gateway software deletes it and scores the attempt as deception. Worse, when SPF or DKIM actually fails in transit the message carries a header asserting the opposite, which is exactly the pattern filters hunt for.

**What you need to do:** Nothing. The real result comes from SPF, DKIM and DMARC in DNS, and publishing all three is the only way to earn it.

#### 8.1.4 — Randomized Message-ID

Message IDs are now generated using `uuid4()` (random) instead of `sha1(time+domain)` (predictable). Gmail used to cluster messages with similar Message-ID patterns.

**What you need to do:** Nothing. This is automatic.

#### 8.1.5 — DKIM Header Coverage

DKIM signatures now cover: From, To, Subject, Date, Message-ID, Reply-To, List-Unsubscribe, MIME-Version, Content-Type, Content-Transfer-Encoding. Previously, Message-ID and Reply-To weren't signed — a weak signal for Gmail's verifier.

**What you need to do:** Nothing. This is automatic.

#### 8.1.6 — Text/Plain Auto-Generation

Every HTML email now automatically gets a text/plain alternative (HTML tags stripped). Without this, Gmail shows a "View entire message" link and some spam filters score HTML-only mail higher.

**What you need to do:** Nothing. This is automatic. You can still provide your own plain_body if you want.

#### 8.1.7 — BIMI Support (not recommended for simulations)

> [!info] What's BIMI?
> BIMI (Brand Indicators for Message Identification) lets Gmail and Outlook display your company logo next to your email in the inbox. This dramatically increases open rates and signals legitimacy.

**How to use:**

1. Generate a BIMI DNS record: `default._bimi.yourdomain.com IN TXT "v=BIMI1; l=https://yourdomain.com/logo.svg"`
2. Publish it in your DNS
3. Note: Gmail requires a VMC (Verified Mark Certificate) — you obtain this separately
4. There is no pre-flight check for BIMI. It was removed: a VMC costs money, needs a trademark, and takes weeks, for no measurable gain in a simulation.

#### 8.1.8 — ARC Chain Support (low value here)

> [!info] What's ARC?
> When email is forwarded (common in corporate environments), the original DKIM signature breaks. ARC (Authenticated Received Chain) lets intermediate forwarders re-sign and attest to the original authentication. Without ARC, forwarded mail fails DMARC.
>
> [!warning] Not worth it for a simulation
> ARC seals only carry weight from intermediaries a receiver already trusts. A seal you generate yourself is ignored, and the feature costs time you could spend on domain age and categorisation.

**How to use:**

1. Enable ARC on your sending profile (toggle: "Enable ARC")
2. Set an ARC selector (e.g., `arc1`)
3. DropoutJeep generates ARC-Authentication-Results, ARC-Message-Signature, and ARC-Seal headers

#### 8.1.9 — FBL Registration Helper (not needed for simulations)

> [!info] What's FBL?
> FBL (Feedback Loop) programs let you receive notifications when someone marks your email as spam. Without FBL registration, you have no visibility into spam complaint rates.

**How to use:**

1. Go to **FBL Registration** (`/admin/fbl`)
2. Select your sending domain
3. Choose FBL programs: Gmail FBL, Microsoft SNDS, Microsoft JMRP, Comcast, Yahoo, Verizon
4. Generate DNS records and confirmation emails for each
5. Publish the DNS records and send the confirmation emails
6. Monitor spam complaint rates in the dashboard

#### 8.1.10 — Automated Domain Warmup (volume alone is not warmup)

> [!info] What's automated warmup?
> Instead of manually sending increasing volumes, DropoutJeep can automate the 30-day warmup process. It sends benign emails (newsletters, memos) daily, ramping from 10/day to 5,000/day.

**How to use:**

1. Go to **Warmup Manager** (`/admin/warmup`)
2. Select your sending profile
3. Click **Start Warmup**
4. DropoutJeep sends benign content daily and tracks progress
5. The warmup schedule is:
   - Day 1: 10 emails
   - Day 7: ~50 emails
   - Day 14: ~250 emails
   - Day 21: ~1,200 emails
   - Day 30: 5,000 emails

### 8.2 — Evasion and Anti-Detection

#### 8.2.1 — Western EDR Detection

> [!info] What's EDR?
> EDR (Endpoint Detection and Response) is the antivirus/security software running on the target's computer — Windows Defender, CrowdStrike, SentinelOne, Carbon Black, Cisco AMP, Sysmon.

DropoutJeep's landing page can now detect if the visitor's machine has EDR software running. If EDR is detected, it serves a safe training page instead of the payload page.

**How to use:**

1. In campaign settings, enable **EDR detection** toggle
2. DropoutJeep checks for EDR via:
   - Browser plugin enumeration
   - WebGL renderer string (VM GPUs indicate sandbox)
   - JavaScript execution timing (EDR-instrumented execution is slower)
3. If EDR detected → serve training page (safe)
4. If no EDR → serve real landing page

**Detected EDR products:**
Windows Defender (MsMpEng), CrowdStrike (CSFalconService), SentinelOne (SentinelAgent), Carbon Black (CbDefense), Cisco AMP (ampdaemon), Trend Micro (Tmmbg), Sysmon, McAfee (mcshield), Malwarebytes (mbam)

#### 8.2.2 — Conditional Execution by IP/ASN

> [!info] Why check IP?
> Security researchers and automated scanners have known IP ranges. If someone from VirusTotal, Any.Run, or Microsoft Defender's sandbox visits your landing page, you want to serve them a safe page — not the real payload.

**How to use:**

1. In campaign settings, enable **IP reputation filter** toggle
2. DropoutJeep checks the visitor's IP against:
   - Known sandbox ranges (VirusTotal, Any.Run, Joe Sandbox, Microsoft Defender sandbox, CrowdStrike research)
   - Known corporate VPN ranges
   - Residential ISP ranges (safe to serve)
3. If sandbox IP → serve training page
4. If residential/corporate IP → serve real landing page

#### 8.2.3 — Updated Browser Profiles

Browser profiles updated to current versions:
- Chrome 131 (Windows + macOS)
- Firefox 133 (Windows)
- Edge 131 (Windows)
- Safari 17.6 (macOS)

All profiles now include Sec-CH-UA, Sec-Fetch-*, and Upgrade-Insecure-Requests headers for Chromium-based browsers.

**What you need to do:** Nothing. Profiles are updated automatically.

#### 8.2.4 — Safe Links Detection and Bypass

> [!info] What are Safe Links?
> Microsoft Defender for Office 365 rewrites all URLs in emails to `safelinks.protection.outlook.com/...` and intercepts clicks. This means your tracking link gets rewritten and the target sees a Microsoft URL, not yours.

**How to use:**

1. DropoutJeep detects Safe Links rewriting by checking the Referer header for `*.safelinks.protection.outlook.com`
2. It parses the original URL from the Safe Links wrapper
3. It logs the rewrite event (indicates the target is on O365 with Defender)
4. For future sends to this recipient, consider:
   - Using attachment-based delivery instead of links
   - Using internal relay URLs (`\\server\share\file`)
   - Using `.searchConnector-ms` files

#### 8.2.5 — Proofpoint/Mimecast Detection

Similar to Safe Links, DropoutJeep detects URL rewriting by Proofpoint (`*.proofpoint.com`) and Mimecast (`*.mimecast.com`), logs the gateway type, and warns the operator to use attachment-based delivery for these targets.

### 8.3 — Payload Delivery (New Exploits)

#### 8.3.1 — CVE-2017-11882 (Equation Editor)

> [!info] What is this?
> A vulnerability in Microsoft Office's Equation Editor that allows code execution when a specially crafted DOCX is opened. No macros, no "Enable Content" prompt — the target just opens the document.

**How to use:**

1. Go to **Payload Generators** → **Equation Editor** tab
2. Enter the payload URL (where the beacon/malware will be downloaded from)
3. Click **Generate DOCX**
4. Download the generated file
5. Attach it to your campaign email

#### 8.3.2 — CVE-2017-0199 (Remote Template)

> [!info] What is this?
> A DOCX that references a remote template. When Word opens the DOCX, it fetches the template from your server. Your server returns an HTA file that executes code.

**How to use:**

1. Go to **Payload Generators** → **Remote Template** tab
2. Enter your server URL (where Word will fetch the template from)
3. Click **Generate DOCX**
4. Click **Generate HTA** (this is what your server returns)
5. Host the HTA on your server at the template URL
6. Attach the DOCX to your campaign email

#### 8.3.3 — search-ms Protocol LNK Builder

> [!info] What is this?
> A Windows shortcut (.lnk) file that uses the `search-ms:` protocol to make Windows Explorer connect to your WebDAV server and load a payload DLL — without the Mark of the Web (MOTW) that normally blocks downloaded files.

**How to use:**

1. Go to **Payload Generators** → **search-ms LNK** tab
2. Enter your WebDAV server URL
3. Click **Generate LNK**
4. Click **Generate searchConnector-ms**
5. Host the payload DLL on your WebDAV server
6. Attach the LNK (or ZIP containing LNK + searchConnector-ms) to your email

#### 8.3.4 — OneNote Delivery

> [!info] What is this?
> A `.one` file (OneNote) with an embedded executable. When opened in OneNote, the executable appears as a clickable attachment. Double-click executes it.

**How to use:**

1. Go to **Payload Generators** → **OneNote** tab
2. Upload your payload file (EXE/DLL)
3. Click **Generate .one**
4. Download the OneNote file
5. Attach it to your campaign email

#### 8.3.5 — VBA Macro Generator

> [!info] What is this?
> Generates `.docm` (modern format) or `.doc` (old binary format) files with auto-open VBA macros. The old `.doc` format bypasses some gateway scanners that only scan modern OOXML files. Includes macro obfuscation.

**How to use:**

1. Go to **Payload Generators** → **VBA Macro** tab
2. Enter the payload URL
3. Choose obfuscation method:
   - `chr` — Chr() encoding (characters as numbers)
   - `concat` — string concatenation
   - `callbyname` — CallByName indirection
   - `mixed` — all combined
4. Choose format: `.docm` or `.doc`
5. Click **Generate**
6. Download the file

#### 8.3.6 — HTML Smuggler Rewrite

The HTML smuggler has been completely rewritten:
- JS is JJEncode-obfuscated (no plaintext patterns)
- Payload is split into 8 XOR'd chunks (assembled at runtime)
- Mouse movement required before assembly (defeats automated scanners)
- `navigator.webdriver` detection (defeats headless browsers)
- Fake "loading..." animation while waiting for interaction

### 8.4 — C2 and Exfiltration

#### 8.4.1 — CDN Domain Fronting

> [!info] What's domain fronting?
> The beacon (your backdoor) connects to a CDN edge node (e.g., `ajax.microsoft.com`), but sends a Host header pointing to your backend. The firewall sees a connection to Microsoft — not to your server.

**How to use:**

1. Go to **C2 Configuration** → **Domain Fronting** section
2. Choose a CDN provider:

| Provider | Front Domain |
|----------|--------------|
| Azure | ajax.microsoft.com |
| Cloudflare | *.workers.dev |
| Fastly | global.prod.fastly.net |
| Amazon | *.cloudfront.net |

3. Configure your backend on the CDN
4. Test the fronting (note: some CDNs have deprecated SNI/Host mismatch)

#### 8.4.2 — Teams/Slack Traffic Mimicry

> [!info] What's traffic mimicry?
> Your C2 beacon wraps its data in Microsoft Teams or Slack API call formats. Corporate monitoring sees normal Teams/Slack traffic — not a beacon.

**How to use:**

1. Go to **C2 Configuration** → **SaaS Mimicry** section
2. Choose protocol: Teams or Slack
3. For Teams: beacon data goes in the `clientData` field of a `/v1/me/activityNotifications` request
4. For Slack: beacon data goes in the `text` field of a `/api/chat.postMessage` request (base64-encoded)

#### 8.4.3 — DoH (DNS-over-HTTPS) Exfiltration

> [!info] What's DoH?
> Instead of standard DNS (which network monitoring can see), DoH sends DNS queries over HTTPS — encrypted and indistinguishable from normal web traffic.

**How to use:**

1. Go to **Exfiltration** → **DoH** tab
2. Choose provider: Google or Cloudflare
3. Enter the base domain (e.g., `exfil.yourdomain.com`)
4. Enter data to exfiltrate
5. Click **Send**
6. Data is encoded as DNS subdomain labels and sent over HTTPS

#### 8.4.4 — ICMP Tunnel Exfiltration

> [!info] What's ICMP tunneling?
> Sends data inside ping (ICMP echo) packets. Most firewalls allow ping traffic, so this bypasses DNS and HTTP restrictions.

**How to use:**

1. Go to **Exfiltration** → **ICMP** tab
2. Enter destination IP (your controlled server)
3. Enter encryption key
4. Enter data
5. Click **Send**
6. Requires root/admin privileges for raw socket access

#### 8.4.5 — Image Steganography Exfiltration

> [!info] What's steganography?
> Hides data inside the pixels of an image. The image looks normal, but the least significant bits of each pixel encode your data. Corporate DLP (Data Loss Prevention) can't detect this.

**How to use:**

1. Go to **Exfiltration** → **Steganography** tab
2. Enter data to hide
3. Optionally upload a cover image (or use auto-generated noise)
4. Choose bits per channel (1 = stealthiest, 3 = most capacity)
5. Click **Embed & Upload** (uploads to your S3/R2 bucket) or **Embed Only** (download the image)
6. On the server side, use the extract function to recover the data

#### 8.4.6 — Multi-Hop Proxy Chain

> [!info] What's a multi-hop proxy chain?
> Instead of connecting directly, traffic bounces through multiple proxy servers in different locations. Each hop only sees the previous hop's IP. This breaks network correlation — nobody can trace the traffic back to you.

**How to use:**

1. Go to **Proxy Chain** (`/admin/proxy-chain`)
2. Add hops (proxy servers): host, port, username, password, TLS toggle
3. Click **Health Check** to verify all hops are reachable
4. Click **Test Connection** to verify the full chain works
5. Export the chain config for your beacon to use

#### 8.4.7 — WebSocket C2

> [!info] What's WebSocket C2?
> A persistent connection on port 443 (HTTPS port) that passes through corporate firewalls. No periodic beaconing pattern — real-time tasking.

**How to use:**

1. WebSocket endpoint: `wss://yourdomain.com/ws/c2/<token>`
2. The beacon connects and stays connected
3. You can queue tasks (commands) from the admin UI
4. Results come back in real time

#### 8.4.8 — Dead-Drop Resolver

> [!info] What's a dead drop?
> Instead of connecting directly to C2, the beacon checks public internet content (GitHub Gist, Pastebin, Reddit profile bio) for base64-encoded instructions. The operator and beacon never talk directly.

**How to use:**

1. Go to **C2 Configuration** → **Dead-Drop Resolver**
2. Choose source type: GitHub Gist, Pastebin, or Reddit
3. Enter the source URL or username
4. Click **Resolve**
5. DropoutJeep fetches the content, extracts base64-encoded instructions (from markers like `<!-- cmd: BASE64 -->`), and decodes them
6. ETag-based caching avoids repeated downloads

### 8.5 — Pretext and OSINT

#### 8.5.1 — LinkedIn OSINT Scraper

> [!info] What's OSINT?
> OSINT (Open Source Intelligence) is information gathered from public sources. The LinkedIn OSINT module scrapes a target's LinkedIn profile to learn their job title, department, manager name, and recent posts — then generates pretexts (fake email scenarios) that reference real people and projects.

**How to use:**

1. Go to **OSINT Dashboard** (`/admin/osint`) → **LinkedIn** tab
2. Enter target name and company (email optional)
3. Click **Scrape**
4. Review results: job title, department, manager name, recent posts, company news
5. Click **Generate Pretext Brief**
6. Review suggested subject lines and body templates that reference real projects and people

#### 8.5.2 — Breach Data Lookup

> [!info] What's breach data?
> Public databases of leaked passwords (HaveIBeenPnwd, DeHashed, IntelX). If you know the target's password from a breach, you can send an email that references their actual password — the most convincing pretext possible.

**How to use:**

1. Go to **OSINT Dashboard** → **Breach Data** tab
2. Enter target email
3. Enter API key (DeHashed or IntelX — paid services)
4. Choose provider
5. Click **Lookup**
6. Review results: known passwords, breach sources, breach dates
7. Click **Generate Pretext** — creates an email that says "Your password Winter2024! has been found in a public database. Reset immediately: [link]"

#### 8.5.3 — Current-Events Pretext Generator

> [!info] What's a pretext generator?
> Automatically pulls current news, weather alerts, CVEs, and SEC filings to generate realistic email pretexts that reference real current events.

**How to use:**

1. Go to **Pretext Generator** (`/admin/pretext-gen`)
2. Enter company name (optional), sector (optional), location (for weather)
3. Click **Generate Pretexts**
4. Review suggestions:
   - Company news (from Google News RSS)
   - Weather alerts (from National Weather Service API)
   - CVE alerts (from NVD)
   - Pretext suggestions combining all sources

#### 8.5.4 — Corporate Branding Clone

> [!info] What's branding clone?
> Fetches a target company's real login page, extracts the CSS, logo, colors, and favicon, and generates a matching landing page template. Your fake login page looks identical to the real one.

**How to use:**

1. Go to **Branding Clone** (`/admin/branding-clone`)
2. Enter the target company's login URL
3. Click **Clone**
4. Review extracted: logo, color scheme, CSS, favicon
5. Download the generated landing page template
6. Use it in your campaign's landing page section

### 8.6 — Persistence and Evasion

#### 8.6.1 — PHANTOMKERNEL Persistence

> [!info] What's persistence?
> After you capture credentials, you need to maintain access — install a "backdoor" that survives reboots, password changes, and EDR scanning. DropoutJeep can generate persistence configurations for three techniques:

**Three persistence methods:**

| Method | What It Does | Why It Works |
|--------|-------------|-------------|
| **COM Hijack** | Registers a fake CLSID under HKCU that loads your DLL | Defender doesn't check HKCU COM well |
| **.NET Profiler** | Sets COR_ENABLE_PROFILING env var to load your DLL into every .NET process | Defender doesn't check env vars |
| **IFEO Debugger** | Sets the Debugger for the EDR's own executable — when EDR restarts, your implant runs instead | Hijacks the EDR's own recovery mechanism |

**How to use:**

1. Go to **Persistence Modules** (`/admin/persistence`)
2. Choose a method
3. Configure: CLSID (auto-generate), DLL path, target EDR (for IFEO)
4. Click **Generate Config**
5. Copy the PowerShell install command
6. Send it via C2 connector to the compromised machine

#### 8.6.2 — Stager Evasion (AMSI/ETW/Syscalls)

> [!info] What's stager evasion?
> The "stager" is the first piece of code that runs on the target — it downloads and executes the main payload. If the stager gets caught, nothing else works. This module hardens the stager with:

| Technique | What It Does |
|-----------|-------------|
| AMSI bypass | Bypasses Windows Anti-Malware Scan Interface using hardware breakpoints |
| ETW patching | Patches 8 ETW functions to prevent telemetry from reaching the EDR |
| Direct syscalls | Calls Windows kernel functions directly, bypassing ntdll hooks |
| Sleep obfuscation | Encrypts the payload in memory during sleep periods to avoid memory scanning |

**How to use:**

1. Go to **Evasion Settings** → **Stager Evasion** section
2. Select techniques: AMSI bypass, ETW patch, Direct syscalls, Sleep obfuscation
3. Enter beacon URL and sleep duration
4. Click **Build Hardened Stager**
5. Download as shellcode, EXE, or DLL

#### 8.6.3 — Anti-Forensic Proxy Mode

> [!info] What's anti-forensic mode?
> If your proxy server is seized, the default behavior stores the entire campaign on disk — credentials, cookies, request/response bodies. Anti-forensic mode prevents this:

| Setting | What It Does |
|---------|-------------|
| **No body logging** | Request/response bodies are not stored |
| **DB encryption** | Session data encrypted with an in-memory key (lost on process exit) |
| **Secure delete** | Files overwritten with random data before deletion |
| **Wipe on disconnect** | Session data zeroed when the proxy session ends |
| **Memory-only** | No data written to disk at all |

**How to use:**

1. Go to **Evasion Settings** → **Anti-Forensic Mode** section
2. Toggle "Enable forensic-safe mode"
3. Configure sub-settings (body logging, DB encryption, etc.)
4. Click **Wipe All Sessions** to immediately destroy all stored data

### 8.7 — Proxy-Based Payload Delivery

> [!info] What's proxy payload delivery?
> When using the MITM proxy, DropoutJeep can inject a JavaScript payload downloader into the pages the target browses. The target sees the real website. In the background, the injected JS downloads and executes your beacon.

**How to use:**

1. Go to **Proxy Payload Delivery** (`/admin/proxy-payload`)
2. Create a rule:
   - URL pattern to match (e.g., all pages, or specific paths)
   - Action: `deliver_payload`
   - Payload URL: where the beacon is hosted
   - Execution delay: how long to wait before downloading
   - Require interaction: wait for mouse movement before executing
   - Payload type: script (JS execution) or download (file download)
3. Save the rule
4. When the target browses through the proxy, the JS is injected automatically

---

## Part 9 — Troubleshooting

### Common Issues and Solutions

| Problem | Cause | Solution |
|---------|-------|----------|
| **Emails go to spam** | Sim headers (FIXED), missing SPF/DKIM/DMARC, cold domain | Check pre-flight, warm up domain, verify DNS records |
| **SMTP validation fails** | Wrong host/port/credentials, firewall blocking | Verify with IT, check port (587=TLS, 465=SSL, 25=plain) |
| **No one clicks the link** | Subject line not convincing, email looks fake | Use role-specific templates, reference real events, A/B test |
| **Landing page doesn't capture credentials** | Form action wrong, token missing | Ensure `action="/landing/{{TOKEN}}"` (or no `action`) and hidden token field |
| **Dashboard shows no events** | Tracking not configured, BASE_URL wrong | Verify BASE_URL is reachable, check HMAC_SECRET is set |
| **Safe Links rewriting URLs** | O365 Defender active on target | Use attachment-based delivery, or internal relay URLs |
| **Proofpoint stripping tracking pixel** | Corporate email gateway | Use attachment-based delivery or DNS exfil |
| **EDR catches payload** | Antivirus detects the file | Use polymorphic payloads, try different delivery formats |
| **Bounce rate high** | Invalid email addresses, domain blacklisted | Validate emails, check blacklists, warm up domain |
| **Auto-reply not working** | IMAP not configured | Set IMAP_HOST, IMAP_USER, IMAP_PASS environment variables |
| **400 "The referrer header is missing" on login** | Old build sent `Referrer-Policy: no-referrer` while Flask-WTF demands a Referer on HTTPS POSTs | Fixed in this revision. If you see it, you are on an old image: rebuild |
| **502 from Caddy, log says `lookup dropoutjeep ... server misbehaving`** | The app container is not running, so Docker DNS cannot resolve the service name | `docker compose ps`, then `docker compose logs --tail 40 dropoutjeep` |
| **`database is locked` during a campaign** | Two processes writing the same SQLite file without WAL | Fixed in this revision. Also confirm the proxy uses the same DATABASE_URL as the app |
| **`dkim=fail` after an environment change** | FERNET_KEY or FLASK_SECRET was rotated, so the stored private key no longer decrypts | Restore the previous `.env`, or regenerate the DKIM pair and republish the TXT |
| **Certificate never issues** | The hostname in the Caddyfile does not resolve to the VPS, often because the root A points at hosting or parking | `Resolve-DnsName <host>` must return the VPS IP before Caddy can validate |
| **404 "Not found" on `/admin` from your own IP** | The admin allowlist, and your public IP changed | Update `remote_ip` in the Caddyfile, a /24 for your ISP survives DHCP |
| **A cloned landing page loads but nothing is captured** | The form action still points at the real site, not `/landing/<token>` | Search the template for `action=` and set it to `/landing/{{TOKEN}}` |

### Error Messages

| Error | What It Means | What to Do |
|-------|-------------|------------|
| `No SPF record found` | Your domain doesn't have an SPF DNS record | Ask IT to add `v=spf1 include:your-mail-server ~all` as a TXT record |
| `DKIM check error` | Can't find the DKIM DNS record | Make sure you published the DKIM record for your selector |
| `Domain blacklisted` | Your domain or IP is on a blacklist | Use a different domain, or request delisting |
| `SMTP connection refused` | Can't connect to the email server | Check host, port, firewall, and credentials |
| `Token signing failed` | HMAC_SECRET not set | Set the HMAC_SECRET environment variable |
| `The CSRF session token is missing` | The session cookie was not sent, usually a Secure cookie over plain HTTP | Serve over HTTPS, or set SESSION_COOKIE_SECURE=0 for local testing |

---

## Part 10 — Quick Reference Cheat Sheet

### The Campaign Checklist

- [ ] 1. Written authorization obtained
- [ ] 2. Domain aged, root page live, DNS A record pointed at the app host
- [ ] 3. Subsidiary created (who the email is from)
- [ ] 4. DKIM generated through the subsidiary so the key is stored, TXT published
- [ ] 5. Sending profile created and validated (SMTP works, IMAP for bounces)
- [ ] 6. SPF, DKIM and DMARC DNS records published and checked from outside
- [ ] 7. Domain submitted for URL categorisation
- [ ] 8. Suppression list configured (VIPs protected)
- [ ] 9. Campaign created (email body, landing page, recipients, timezone set)
- [ ] 10. Landing template checked for absolute URLs pointing at the real site
- [ ] 11. Pre-flight checks passed
- [ ] 12. Test send to your own Gmail and Outlook, headers show spf/dkim/dmarc pass
- [ ] 13. Full send, ramped, with quarantine counted separately from clicks

### Environment Variables Quick Reference

```
PHISH_DOMAIN=<public hostname, used by compose to build BASE_URL>
BASE_URL=https://<public hostname>
FLASK_SECRET=<random string>
HMAC_SECRET=<random string>
FERNET_KEY=<32 random bytes, urlsafe base64. Set once, never change>
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<your password, only read when the user table is empty>
SESSION_LIFETIME_HOURS=8
SESSION_COOKIE_SECURE=1
RETENTION_DAYS=180
SCHEDULE_TIMEZONE=UTC
UNSUBSCRIBE_TARGET=<optional https URL or mailbox. Unset means no header>
LOGIN_RATE_LIMIT=5 per minute
DATABASE_URL=sqlite:////app/instance/phish.db
AUDIT_LOG=/app/instance/audit.log
VIRUSTOTAL_API_KEY=<optional, for reputation scoring>
IMAP_HOST=<optional, for auto-reply and bounce parsing>
IMAP_USER=<optional>
IMAP_PASS=<optional>
ENABLE_PLUGINS_UI=<leave unset. Exposes the Python proxy plugin editor>
```

> [!warning] Four of these cannot be changed later without consequences
> `FERNET_KEY` and `FLASK_SECRET` decrypt everything stored (SMTP and IMAP passwords, DKIM keys, captured credentials). `HMAC_SECRET` signs every tracking link. `DATABASE_URL` decides which database the app and the proxy write to, and they must agree. Everything else is safe to edit and restart.

### Key URLs

| URL | What It Is |
|-----|-----------|
| `http://localhost:5000/admin` | Admin dashboard |
| `http://localhost:5000/admin/campaign/new` | Create new campaign |
| `http://localhost:5000/admin/subsidiary/new` | Create subsidiary |
| `http://localhost:5000/admin/sending_profile/new` | Create sending profile |
| `http://localhost:5000/events` | Event log |
| `http://localhost:5000/admin/campaign/<id>/funnel` | Campaign funnel |
| `http://localhost:5000/admin/campaign/<id>/validate` | Pre-flight checks |
| `http://localhost:5000/admin/osint` | OSINT dashboard (NEW) |
| `http://localhost:5000/admin/pretext-gen` | Pretext generator (NEW) |
| `http://localhost:5000/admin/branding-clone` | Branding clone (NEW) |
| `http://localhost:5000/admin/payloads` | Payload generators (NEW) |
| `http://localhost:5000/admin/exfil` | Exfiltration channels (NEW) |
| `http://localhost:5000/admin/evasion` | Evasion settings (NEW) |
| `http://localhost:5000/admin/persistence` | Persistence modules (NEW) |
| `http://localhost:5000/admin/warmup` | Warmup manager (NEW) |
| `http://localhost:5000/admin/fbl` | FBL registration (NEW) |
| `http://localhost:5000/admin/proxy-chain` | Multi-hop proxy (NEW) |
| `http://localhost:5000/admin/proxy-payload` | Proxy payload delivery (NEW) |

### Email Placeholders

| Placeholder | What It Does |
|-------------|-------------|
| `{{TRACK_LINK}}` | Unique tracking link per recipient |
| `{{PIXEL}}` | Invisible open-tracking image |
| `{{CANARY_URL}}` | URL canary (detects email sharing) |
| `{{CANARY_IMAGE}}` | Image canary |
| `{{FINGERPRINT_SCRIPT}}` | Browser fingerprint collector |
| `{{QR_CODE}}` | Per-recipient QR code |

### Landing Page Placeholders

| Placeholder | What It Does |
|-------------|-------------|
| `{{TOKEN}}` | Recipient's unique token (REQUIRED) |
| `{{TRACK_LINK}}` | Tracking link |
| `{{PIXEL}}` | Tracking pixel |
| `{{FINGERPRINT_SCRIPT}}` | Browser fingerprint collector |

### Event Types

| Event | When It Happens |
|-------|----------------|
| `sent` | Email sent successfully |
| `open` | Email opened (pixel loaded) |
| `click` | Tracking link clicked |
| `credential_attempt` | Credentials submitted on landing page |
| `mfa_attempt` | MFA code submitted |
| `fingerprint` | Browser fingerprint collected |
| `flow_complete` | Full flow completed (open → click → submit) |
| `bounce` | Email bounced (undeliverable) |
| `training_started` | Training page displayed |
| `training_completed` | Training completed |
| `user_report` | User reported the email as phishing |
| `canary_triggered` | Canary token triggered (email shared) |
| `proxy_credential_capture` | Credentials captured via proxy |
| `proxy_mfa_capture` | MFA captured via proxy |
| `proxy_session_cookie_capture` | Session cookies captured via proxy |
| `saml_response_capture` | SAML assertion captured |
| `oauth_auth_code_capture` | OAuth authorization code captured |
| `exfil_http` | HTTP exfiltration event |
| `exfil_dns` | DNS exfiltration event |
| `c2_beacon` | C2 beacon received (NEW) |
| `c2_result` | C2 task result (NEW) |
| `spam_complaint` | FBL spam complaint (NEW) |
| `safelinks_rewrite` | Safe Links URL rewrite detected (NEW) |
| `proofpoint_rewrite` | Proofpoint URL rewrite detected (NEW) |
| `mimecast_rewrite` | Mimecast URL rewrite detected (NEW) |

---

> [!quote] Final word
> DropoutJeep is a powerful tool. Use it responsibly, with authorization, and with the goal of making your organization more secure. Every person who clicks a phishing link in a test is one fewer person who'll click a real one.

---

## What changed in this revision

Code changes, each one verified rather than assumed:

- The mailer no longer adds a self-asserted `Authentication-Results` header. Receivers discard untrusted AR headers and score the attempt as deception.
- Auto-replies no longer carry an `X-DropoutJeep-Auto-Reply` header naming the tool.
- The DKIM generator stores the private key on the matching subsidiary and never renders it to the browser. Generated without a subsidiary, the key is discarded and the page says so.
- Branding Clone strips remote scripts, stylesheets, frames, hotlinked images, outbound links, meta refresh, base tags and CSS `url()` fetches, and returns a per-category count of what it removed.
- Admin pages send `Referrer-Policy: same-origin`, public pages keep `no-referrer`. Before this, HTTPS logins failed with "The referrer header is missing".
- SQLite runs in WAL with a 5 second busy timeout in both the app and the proxy, so concurrent writes stop losing events.
- The session cookie is `Secure; HttpOnly; SameSite=Lax`.
- `List-Unsubscribe` is only sent when `UNSUBSCRIBE_TARGET` is configured. No more dead mailto address on every message.
- The audit log rotates at 20 MB with three backups. Docker logs rotate at 10 MB with three files.
- The login rate limit is configurable with `LOGIN_RATE_LIMIT`.
- The proxy warns at startup when `DATABASE_URL` points at a file with no DropoutJeep tables.
- Pre-flight warns when the subsidiary has no stored DKIM key, when the key cannot be decrypted, and when the sending profile has no IMAP mailbox.
- `[upgrade] Added {col}` now names the column instead of printing the template.
- Compose: `DATABASE_URL` uses four slashes so SQLite gets an absolute path, the proxy joins the shared network, and its port binds loopback only.

> [!warning] This is a breaking-ish update for an existing deployment
> Rebuild the image, then check that `PRAGMA journal_mode` returns `wal` and that a test sign-in works. Existing `.env` files keep working, but a `.env` without `FERNET_KEY` still derives the encryption key from `FLASK_SECRET`, which is the fragile behaviour this revision documents.

---

## Related Notes

- [[DROPOUTJEEP_GAP_ANALYSIS]] — The full gap analysis document
- [[UI_UPDATE_GUIDE]] — Guide for the UI agent to add new features
- [[VPS_DEPLOYMENT]] — Production deployment guide

## Tags

#dropoutjeep #guide #phishing-simulation #security #ELI5 #campaign-playbook #setup-guide
