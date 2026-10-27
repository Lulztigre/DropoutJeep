# Deploying DropoutJeep on a VPS: the beginner version

This is the deployment guide for someone who has never rented a server. Every command is copy-paste. Every step says what you should see before you move on.

You end up with DropoutJeep running at `https://yourdomain.com`, a real TLS certificate, the admin dashboard behind a login, and a database that survives restarts.

Read it once before you start. Budget 45 to 90 minutes, most of it waiting on DNS and the first Docker build.

Use it only against people and organizations that have given you written permission. That is not a legal footnote, it is the thing that keeps the campaign defensible when HR asks who approved it.

---

## What you are actually building

Three pieces, and it helps to picture them separately.

1. The app. A Python web app that sends email, serves landing pages and records events. It runs in a Docker container.
2. Caddy. A small web server in front of the app. It answers on ports 80 and 443 and gets a free certificate, so the site is HTTPS. It runs in a second container.
3. The database. One SQLite file inside a Docker volume. Campaigns, recipients, captured events and the audit log all live there. Delete the volume and you delete the engagement.

Docker Compose starts the first two together and keeps them running. You never touch Python on the server directly.

---

## Before you start

- A card that can pay for a VPS, roughly 5 to 15 dollars a month.
- A domain you own, or a subdomain of one you control.
- An SSH client. On Windows, PowerShell already has `ssh` and `scp`.
- An SMTP relay account: Amazon SES, Mailgun, SendGrid, Postmark, or the client's Microsoft 365 tenant. You cannot send mail straight off the VPS, explained in step 1.
- The signed authorization or scope document for the engagement. Have it before the first email, not after.

---

## Want this done for you?

`deploy/bootstrap.sh` performs steps 2 through 7 on the server in one run, and `deploy/deploy.ps1` drives it from Windows: pack, upload, run, and optionally create the DNS record at Cloudflare. Providers with cloud-init take a rendered file and skip SSH entirely.

```powershell
cd C:\Users\moyoo\DropoutJeep
.\deploy\deploy.ps1 -Domain yourdomain.com -ServerIp SERVER_IP -AdminIp YOUR_HOME_IP
```

What stays manual: paying for the server, the abuse policy ticket, and buying the domain. Flags, variables and the failure table are in `deploy/README.md`. The steps below are the same thing by hand, which is what you want the first time, or when something breaks and you need to know which part.

---

## Step 1: rent the right VPS

### Which provider to pick

Any of these works. Pick one, do not spend a day comparing.

| Provider | Plan to choose | Roughly | Why pick it |
|---|---|---|---|
| Hetzner Cloud | 2 vCPU, 4 GB RAM, 40 GB disk | 5 to 10 USD/mo | Best price for the specs. Regions in Germany, Finland, Virginia, Oregon, Singapore. Default pick. |
| DigitalOcean | Basic Droplet, 2 GB RAM, 1 vCPU, 50 GB disk | about 12 USD/mo | Simplest console and the clearest docs. Move to the 4 GB plan if you plan to use the reverse proxy. |
| Vultr or Linode (Akamai) | smallest 2 GB plan in the region you need | 6 to 12 USD/mo | Use when you need a country Hetzner has no region in. |

Prices move. Check the provider's own pricing page before you commit, and do not chase a two dollar difference.

Hourly billing changes the sums, so cost the exact number of days rather than the monthly sticker. Hetzner bills by the hour and caps at the monthly price, so a three-week engagement costs about three quarters of a month and destroying the server stops the meter. Cloudzy's promotional half-price figure is a monthly or annual rate; the hourly rate quoted in their calculator matches the full list price instead, which is roughly double, so confirm which one the cart applies before you pay.

If you have no reason to pick otherwise: **Hetzner Cloud, 2 vCPU / 4 GB, Ubuntu 24.04, in the region closest to the people you are simulating against.**

### Specs, in plain words

- 1 vCPU and 2 GB RAM handles a few thousand recipients with no proxy.
- 2 vCPU and 4 GB is the comfortable floor if you will run the reverse proxy, the browser renderer, or lists over a few thousand people.
- 40 GB of disk is plenty. The app is small. Browsers and logs are what grow.
- Always 64-bit x86. Skip ARM plans, some Python wheels here are fussy about it and you do not need the trouble.

### Two provider rules that catch people out

**Port 25 is blocked.** Hetzner, DigitalOcean, AWS and Google block outbound port 25 by default to cut spam. The VPS cannot deliver mail to the internet directly. Send through an SMTP relay instead: create a sending profile pointing at SES, Mailgun, SendGrid or the client's mail server. Inbound mail for bounces works normally, that is IMAP on 993.

**Most acceptable use policies ban phishing, including simulations.** Providers suspend first and read the ticket later, usually mid-campaign. Before you build anything, open a support ticket, attach the client's authorization and scope, say this is an authorized internal security awareness exercise, and keep the reply. Use a separate account and a separate card from your main infrastructure. On AWS, use the penetration testing request form. This one step has saved more engagements than any technical control on this page.

### Location

Pick the region in or near the target's country. Two reasons: tracking links and landing pages should look local, and some corporate networks geofence or flag foreign logins, which corrupts your results.

### Create the server

1. Create or log in to the provider account.
2. Create a new server or droplet.
3. Image: **Ubuntu 24.04 LTS** (22.04 also works), x86_64.
4. Plan: from the table above.
5. Region: nearest to the target.
6. Authentication: paste an SSH public key. Do not use a root password.
7. Create it, then write down the public IP address. It looks like `203.0.113.45`.

If you do not have an SSH key yet, make one in PowerShell on your own machine:

```powershell
ssh-keygen -t ed25519 -C "dropoutjeep"
```

Press Enter through the prompts. Print the public half and paste that into the provider's key box:

```powershell
Get-Content $env:USERPROFILE\.ssh\id_ed25519.pub
```

Take a provider snapshot once everything works at the end of this guide. Restoring a snapshot beats rebuilding by hand.

---

## Step 2: log in and lock the door

Connect from PowerShell:

```bash
ssh root@SERVER_IP
```

Type `yes` at the fingerprint prompt. You should land on a prompt like `root@ubuntu:~#`.

Create a normal user, so you are not living as root:

```bash
adduser deploy
usermod -aG sudo deploy
mkdir -p /home/deploy/.ssh
cp /root/.ssh/authorized_keys /home/deploy/.ssh/authorized_keys
chown -R deploy:deploy /home/deploy/.ssh
chmod 700 /home/deploy/.ssh
chmod 600 /home/deploy/.ssh/authorized_keys
```

Open a second PowerShell window and confirm the new user works before you close the root session:

```bash
ssh deploy@SERVER_IP
```

Now the firewall. Ubuntu ships ufw, and Docker opens 80 and 443 for itself when the stack starts:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
sudo ufw status
```

You should see three allow rules and `Status: active`.

From here on, every command runs as `deploy`, not root.

---

## Step 3: install Docker

Use Docker's own installer. The version in Ubuntu's apt repo is old and gives you the wrong `compose` command:

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker deploy
```

Log out and back in so the group applies, then check:

```bash
exit
ssh deploy@SERVER_IP
docker --version
docker compose version
```

You should see a Docker version line and a Compose version line. Both commands are `docker compose` with a space, not `docker-compose` with a hyphen.

---

## Step 4: buy the domain and point it at the server

### Where to buy it

- **Cloudflare Registrar**: wholesale pricing, no upsell, free DNS with an API. The domain has to use Cloudflare's nameservers.
- **Porkbun** or **Namecheap**: similar prices, free WHOIS privacy, far less pushy than GoDaddy.
- **Njalla**: privacy focused and takes crypto, costs more, and stands as the registrant rather than you. Read what that means before using it for a client.

Budget 10 to 15 USD a year for a `.com`. Look at the renewal price, not the first-year offer: some TLDs are cheap now and 40 dollars next year. Turn on WHOIS privacy, it is free at all three of the first options.

Decide who owns the domain before you buy. For a client engagement, either register it on a company card and hand it over at the end, or register it inside the client's account and get delegated access to the DNS. Moving a domain mid-engagement is a lost week.

### Pick a name that survives a mail filter

- Close enough to be plausible, different enough to be clearly not the brand: a hyphenated variant (`brand-portal.com`), a suffix word (`brand-secure.net`), a different TLD, or a single-character typo you can defend in the report.
- Avoid free TLDs (`.tk`, `.ml`, `.ga`). Mail gateways score them into the ground.
- Avoid a domain with history. A cheap expired domain that used to send spam arrives pre-poisoned, and no amount of DKIM fixes that. Search the name before you pay.
- Short beats clever. If the recipient cannot retype it from memory, the click never happens.
- Never register the real brand as the registrable domain. That is the line between a simulation and trademark infringement.

### Put the DNS somewhere you can automate

Two sane choices. The registrar's own DNS, which is zero setup and fine. Or Cloudflare's free plan, which propagates faster, has an API, and lets `deploy.ps1` create the record for you. If you pick Cloudflare, change the nameservers at the registrar and wait, usually minutes, occasionally a few hours, before doing anything else.

### Create the records

Type A, TTL 300 or auto, value is the server IP:

| Host | Value | Needed for |
|---|---|---|
| `@` | SERVER_IP | the app and the admin dashboard |
| `campaigns` | SERVER_IP | optional, clean per-campaign domains later |
| `*.campaigns` | SERVER_IP | optional, wildcard clean URLs later |

The SPF, DKIM and DMARC TXT records go in the same zone later, in step 9.

### Verify before you continue

```powershell
Resolve-DnsName yourdomain.com -Type A
```

When it returns your server IP you are ready. Caddy cannot issue a certificate before this is true.

If the domain is on Cloudflare, the record has to be **DNS only**, grey cloud. The orange proxy hides the real IP, and the HTTP challenge fails in a way that looks like a Caddy bug.

---

## While you wait for the domain

Registrar transfers and DNS propagation are dead time, and almost nothing here depends on them. Use it.

**Prep the box.** Steps 1 to 3, plus the code, `.env` and the Caddyfile, all work without DNS:

```powershell
.\deploy\deploy.ps1 -Domain yourdomain.com -ServerIp SERVER_IP -AdminIp YOUR_HOME_IP -PrepOnly
```

That installs everything, builds the image, writes the secrets and prepares the admin allowlist, then stops before starting the stack. When DNS resolves, one command finishes it:

```bash
ssh root@SERVER_IP "cd /opt/dropoutjeep && docker compose up -d --build"
```

Starting after DNS avoids a log full of failed certificate attempts, and the prebuilt image means the site is up in under a minute.

**Open the relay account.** If you are using Amazon SES, request production access today. Sandbox approval is the longest wait in the entire process, usually a day, and it needs a registered domain, not a working site.

**Stage the DNS records.** SPF and DMARC are TXT records on the root and `_dmarc`, so they do not care whether the A record exists. Add them as soon as the zone is live. DKIM has to wait, the key pair is generated inside the app.

**Note your public IP for the allowlist.** Check it from the machine you will administer from, not the server. If it changes, edit `ADMIN_IP` and rerun the script, the Caddyfile is rewritten and Caddy reloads.

**Set up backups now.** The backup command in the next section needs nothing but the volume, so put it in cron before the first campaign rather than after the first loss.

What genuinely cannot happen before DNS: the certificate, and therefore the site itself. Everything else can be finished and tested later the same day.

---

## Step 5: get the app onto the server

The repo is public, so clone it on the server. That gives you a clean way to update later:

```bash
sudo mkdir -p /opt/dropoutjeep
sudo chown deploy:deploy /opt/dropoutjeep
git clone https://github.com/Lulztigre/DropoutJeep.git /opt/dropoutjeep
cd /opt/dropoutjeep
ls
```

You should see `dropoutjeep.py`, `docker-compose.yml`, `Caddyfile`, `requirements.txt` and the rest.

If you have local changes that are not pushed yet, ship those as an archive instead. On your Windows machine:

```powershell
cd C:\Users\moyoo
tar --exclude=DropoutJeep/venv --exclude=DropoutJeep/logs --exclude=DropoutJeep/__pycache__ --exclude=DropoutJeep/.pytest_cache -czf dropoutjeep.tgz DropoutJeep
scp dropoutjeep.tgz deploy@SERVER_IP:~/
```

Then on the server, unpack over the clone:

```bash
tar xzf ~/dropoutjeep.tgz
rsync -a ~/DropoutJeep/ /opt/dropoutjeep/
```

Either way, do not copy your local `instance/` folder, your local `venv/`, or any `*.db` file onto the box. The server starts empty, which is what you want.

The `.env` you are about to create sits inside the repo directory. It is ignored by `git`, and it must stay that way. A committed `.env` means your `FLASK_SECRET`, `HMAC_SECRET` and admin password end up in a public repository.

---

## Step 6: write the environment file

Generate two secrets on the server. Run the line twice, copy each output:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Create the file:

```bash
cd /opt/dropoutjeep
nano .env
```

Paste this and replace the placeholders:

```env
PHISH_DOMAIN=yourdomain.com
FLASK_SECRET=PASTE_THE_FIRST_SECRET
HMAC_SECRET=PASTE_THE_SECOND_SECRET
ADMIN_USERNAME=admin
ADMIN_PASSWORD=PASTE_A_LONG_PASSWORD
SESSION_LIFETIME_HOURS=8
RETENTION_DAYS=180
```

Save with `Ctrl+O`, `Enter`, then `Ctrl+X`.

What each one does:

| Variable | What it is | Notes |
|---|---|---|
| `PHISH_DOMAIN` | the public hostname | compose builds `BASE_URL` from it, do not set `BASE_URL` yourself |
| `FLASK_SECRET` | signs session cookies | random, 64 hex chars |
| `HMAC_SECRET` | signs recipient tracking tokens | random, and different from the one above |
| `FERNET_KEY` | encrypts secrets stored in the database | generate on day one, never change it, see the warning below |
| `ADMIN_USERNAME` | first admin login | created only when the database has no users |
| `ADMIN_PASSWORD` | first admin password | same rule, it is not re-applied later |
| `SESSION_LIFETIME_HOURS` | how long "remember me" lasts | default 8 |
| `RETENTION_DAYS` | how long events are kept | pick something you can defend |
| `DATABASE_URL` | database location | leave unset, it defaults to the SQLite file on the volume |
| `ENABLE_PLUGINS_UI` | exposes the Python proxy plugin editor | leave unset unless you know exactly why you want it |
| `AUDIT_LOG` | where the audit log is written | compose already points it into the volume |

Two things that bite people:

- `ADMIN_PASSWORD` is only read when the user table is empty. Changing it later in `.env` does nothing. Change the password in the UI, or use the reset snippet in troubleshooting.
- Pointing `DATABASE_URL` at PostgreSQL fails at boot. The image ships no Postgres driver. Add `psycopg2-binary` to `requirements.txt` and rebuild if you really need Postgres.

And one thing that ruins an engagement:

`FERNET_KEY` encrypts every secret the app stores: SMTP and IMAP passwords, DKIM private keys, captured credentials, uploads, exfil data. If it is missing, the app derives one from `FLASK_SECRET`, so changing `FLASK_SECRET` silently makes all of that unreadable, including the DKIM keys that sign your outbound mail. Set `FERNET_KEY` on a fresh install, back it up with `.env`, and never change either value on a live box. `bootstrap.sh` refuses to rotate secrets on an existing install unless you pass `FORCE_ENV_CONFIRM=YES`.

---

## Step 7: start it

```bash
cd /opt/dropoutjeep
docker compose up -d --build
```

The first build takes a few minutes, it installs the Python dependencies inside the image. Then:

```bash
docker compose ps
```

Both `dropoutjeep` and `caddy` should say `running`. Watch the certificate being issued:

```bash
docker compose logs -f caddy
```

Look for a line about `certificate obtained successfully` for your domain. Press `Ctrl+C` to stop following.

Open `https://yourdomain.com`. The root redirects to the login page at `/admin/login`, with a padlock. If the browser warns about the certificate, give it two minutes and reload. If it still fails, see troubleshooting.

If the app container keeps restarting:

```bash
docker compose logs --tail 100 dropoutjeep
```

The usual causes are a missing `FLASK_SECRET` or a `.env` that was never saved.

---

## Step 8: first login

1. Open `https://yourdomain.com`, which lands on `/admin/login`.
2. Log in with `ADMIN_USERNAME` and `ADMIN_PASSWORD`.
3. Leave "remember me" unchecked on a shared machine.
4. Change the password right away in the admin user settings.
5. Create a separate `operator` account for anyone else running campaigns. Do not share the admin login.

What comes next, meaning subsidiaries, DKIM, sending profiles, templates and campaigns, is covered step by step in `full_capaing.md`. This guide stops at a working deployment.

---

## Step 9: make email actually arrive

The app sends through an SMTP relay, not from the VPS itself. Set this up before the first campaign, because a relay that rejects you looks exactly like a broken app.

### Why the server cannot send on its own

Port 25 outbound is blocked by Hetzner, DigitalOcean, AWS, Google and most others, and a brand new IP has no sending reputation even if it were open. Receiving is fine, that is IMAP on 993.

### Pick a relay and get credentials

| Relay | What you get | Watch out for |
|---|---|---|
| Amazon SES | cheapest at volume, good reputation | starts in sandbox, you can only send to verified addresses until production access is granted, usually a day |
| Mailgun, SendGrid, Brevo | quick start, free monthly tier | shared IP pool unless you pay for a dedicated one, reputation is shared with strangers |
| Postmark | best inbox placement of the bunch | strict about who they accept, priced accordingly |
| Client's Microsoft 365 or Google Workspace | the best possible reputation for an internal simulation | SMTP AUTH is normally disabled and an admin has to enable it for the sending mailbox |

Each of these has an abuse policy, and phishing simulation is on the list. Same ticket as the VPS: authorization attached, before the campaign, not after the first complaint.

### Fill in the sending profile

In the app: **Sending, Sending Profiles, Create**.

| Field | What goes in it |
|---|---|
| SMTP host | from the relay dashboard |
| SMTP port | 587 with STARTTLS, or 465 with SSL |
| SMTP user | the relay username. On SES this is the SMTP username from the console, not your IAM access key |
| SMTP password | relay password or API key. On SES you derive it once from the secret key |
| Encryption | STARTTLS when the port is 587 |
| Rate per minute | 30 to 60 on a fresh domain, raise it after the first clean batch |
| IMAP host, port, user, password | the bounce mailbox, port 993 with TLS |

The SMTP and IMAP passwords are encrypted with `FERNET_KEY` before they touch the database. Which is why that key is generated once and never rotated.

### Publish three DNS records

All three go in the same zone as the A record you created in step 4.

1. **SPF**, a TXT record on the root. Use the include your relay documents: `v=spf1 include:amazonses.com ~all`. One SPF record only, never two.
2. **DKIM**, generate the key pair in the app under the subsidiary, then add the TXT record it shows at `<selector>._domainkey`. Remember the selector, it goes in the sending profile.
3. **DMARC**, a TXT record at `_dmarc`: `v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com`. Start at `p=none` while testing, move to `quarantine` for the real send.

Check them from your laptop after a few minutes:

```powershell
Resolve-DnsName yourdomain.com -Type TXT
Resolve-DnsName dkim._domainkey.yourdomain.com -Type TXT
Resolve-DnsName _dmarc.yourdomain.com -Type TXT
```

### Test in this order, not in a different one

1. Send a campaign test to a mailbox you control on Gmail and another on Outlook.
2. Open the received mail, view the headers, confirm `spf=pass`, `dkim=pass` and `dmarc=pass`.
3. Click the tracked link. Confirm the landing page loads and the click appears in the dashboard.
4. Only now import the real recipient list.

One failed DKIM check sends the whole campaign to spam and teaches the client that the tool is broken. Ten minutes of header reading prevents that.

---

## Step 10: keep the admin panel off the public internet

Right now anyone on the internet can reach the login page and your dashboard, and the login is the only thing standing there. Put a second lock on it.

Edit the Caddyfile on the server:

```bash
cd /opt/dropoutjeep
nano Caddyfile
```

Replace the whole file with this, putting your own IP where `203.0.113.10` is. Find it by searching "what is my ip".

```caddy
{$PHISH_DOMAIN} {
    @private path /admin*
    handle @private {
        @notme not remote_ip 203.0.113.10
        respond @notme "Not found" 404
        reverse_proxy dropoutjeep:5000
    }
    handle {
        reverse_proxy dropoutjeep:5000
    }
}
```

The matcher is `/admin*` because the whole dashboard, login page included, lives under `/admin`. I tested exactly this block against Caddy 2.11: `/admin`, `/admin/login` and `/admin/users` return `404 Not found` for an address that is not on the list, while `/` and `/proxy/...` pass through normally.

Apply it:

```bash
docker compose restart caddy
```

Test it. The login page works from your own connection, and returns a plain "Not found" from a phone on mobile data. Keep your SSH session open while you test so you cannot lock yourself out.

If your IP changes constantly, use Caddy basic auth on the same path block instead, or reach the admin over an SSH tunnel. The tunnel is the safest option when you are moving between networks.

`/internal/*` is deliberately not in the path matcher. Caddy calls `/internal/caddy-ask` from inside the Docker network for wildcard certificates later, and blocking it breaks that.

---

## Step 11 (optional): clean URLs with the reverse proxy

Out of the box, landing links look like `https://yourdomain.com/proxy/<id>/`. A clean URL looks like `https://login.yourdomain.com/portal`. That needs the standalone proxy container.

1. In the admin UI, open **/admin/proxy-domains** and add the hostname you want, mapped to a reverse proxy campaign.
2. Point a DNS A record for that hostname at the server IP.
3. Start the proxy stack:

```bash
cd /opt/dropoutjeep
docker compose -f docker-compose.proxy.yml up -d
```

4. Add a site block to the Caddyfile so Caddy terminates TLS for that hostname and forwards to the proxy:

```caddy
login.yourdomain.com {
    reverse_proxy dropoutjeep-proxy:8080
}
```

5. Reload Caddy:

```bash
docker compose restart caddy
```

Two details matter here and are easy to miss:

- Both compose files share the Docker network `dropoutjeep-net`. That is why `dropoutjeep-proxy:8080` resolves from inside Caddy. If you rename the folder or copy only one compose file to the server, this name lookup is the first thing to check.
- The proxy speaks plain HTTP inside the Docker network and Caddy adds TLS. Its host port is published on `127.0.0.1:8080` only. Do not change that to a bare `8080:8080`, which would expose captured traffic over plain HTTP to the internet.

For wildcard campaign domains, use Caddy on-demand TLS, which asks the app before issuing each certificate. Two pieces are required: a global `on_demand_tls` block that names the ask endpoint, and `tls { on_demand }` on the site. Both use the app service name, not `127.0.0.1`, because Caddy runs in its own container:

```caddy
{
    on_demand_tls {
        ask http://dropoutjeep:5000/internal/caddy-ask
    }
}

*.campaigns.yourdomain.com {
    tls {
        on_demand
    }
    reverse_proxy dropoutjeep-proxy:8080
}
```

That shape validates against Caddy 2.11. Nesting `ask` inside `on_demand { }` does not, which is the mistake the old comment in the shipped Caddyfile made.

---

## Where your data lives, and where a cloned page sits

| Location | What is in it | Survives a rebuild |
|---|---|---|
| Docker volume `dropoutjeep_dropoutjeep-data`, mounted at `/app/instance` | the database and `audit.log`: campaigns, recipients, email and landing templates, captured credentials (encrypted), events, settings | yes, until you delete the volume |
| Caddy volumes `caddy-data` and `caddy-config` | TLS certificates and account keys | yes, which is why a redeploy does not re-issue certificates |
| Image filesystem `/app` | the code and the built-in templates in `dropoutjeep_lib/data/templates/*.json` | no, replaced by the next build, then re-seeded into the database at boot |
| Container `/tmp` and anything outside `/app` | scratch files, generated payloads | no, gone when the container is recreated |

The rule that matters: if it is in the database, it is on the volume and it is in your backup. If it is a file in the image, the next build deletes it.

### Where a cloned page actually sits

Branding Clone (**Tools, Branding Clone**) fetches the target page server side, inlines the CSS, and embeds the logo and favicon as base64 data URIs. The HTML comes back to your browser, and you save it as a landing template. From that moment it lives in the database, in the `landing_html` column, and it is served when a recipient clicks:

- landing page: `https://yourdomain.com/l/<token>`
- tracking pixel: `https://yourdomain.com/track/<token>`

Nothing is written to the container disk by the UI, so a rebuild does not lose a clone. The database is the only copy, which is the whole argument for the backup in the next section.

Two things to check on a clone before you send it:

- Open the saved template and search for `https://` inside `src=` and `href=`. Assets under the size cap are embedded, but oversized images and remote stylesheets stay as links, and a hotlinked logo tells anyone who looks that the page is a copy.
- Very heavy pages produce very large templates. If the editor gets slow, trim the images before saving.

---

## Updating an existing deployment

The old guide did not cover this. Three things can change and they need different commands.

### Always back up first

Schema upgrades run automatically at boot and they are additive, but a backup costs 10 seconds:

```bash
cd /opt/dropoutjeep
docker compose stop dropoutjeep
docker run --rm -v dropoutjeep_dropoutjeep-data:/data -v "$PWD":/backup alpine tar czf /backup/backup-$(date +%F-%H%M).tgz -C /data .
docker compose start dropoutjeep
```

You end up with a `backup-....tgz` in `/opt/dropoutjeep`. If your folder has a different name, the volume name differs too, because Docker prefixes it with the project name. Run `docker volume ls | grep dropoutjeep` once and use that name in the command.

Pull a copy to your laptop and keep it somewhere that is not the VPS:

```powershell
scp deploy@SERVER_IP:/opt/dropoutjeep/backup-*.tgz .
```

### Case A: new code

If you deployed with git:

```bash
cd /opt/dropoutjeep
cp -a /opt/dropoutjeep /opt/dropoutjeep.prev
git pull --ff-only
docker compose up -d --build
docker compose ps
docker compose logs --tail 60 dropoutjeep
```

If you deploy by archive, rebuild it on Windows as in step 5, then:

```bash
cd /opt/dropoutjeep
cp -a /opt/dropoutjeep /opt/dropoutjeep.prev
rsync -a --exclude .env --exclude instance ~/DropoutJeep/ /opt/dropoutjeep/
docker compose up -d --build
docker compose ps
docker compose logs --tail 60 dropoutjeep
```

`--build` is the flag that matters. Without it you keep running the old image. The app runs `db.create_all()` and its inline schema upgrades at boot, so there is no separate migration command.

### Case B: a setting changed

Edit `.env`, then recreate the container so it picks up the new environment:

```bash
docker compose up -d
```

A restart is not enough for environment changes. Compose only re-reads `.env` when it recreates the container.

### Case C: the Caddyfile changed

```bash
docker compose restart caddy
docker compose logs --tail 40 caddy
```

Check the log for a config error. Caddy refuses to start on bad syntax, and the site stays down until you fix it.

### After any update, check these four things

1. `docker compose ps` shows both containers running.
2. `https://yourdomain.com` loads and you can log in.
3. One test email to your own address, and you click the link.
4. The dashboard shows the click.

### Rollback

```bash
cd /opt/dropoutjeep
docker compose down
rm -rf /opt/dropoutjeep
mv /opt/dropoutjeep.prev /opt/dropoutjeep
cd /opt/dropoutjeep
docker compose up -d
```

If the failed version already upgraded the schema, restore the backup from the top of this section before you trust the old code. Additive upgrades mean old code usually still reads the database, and usually is not a guarantee you want during an engagement.

### Moving to a new VPS

1. Back up on the old box.
2. Build the new box through steps 1 to 4.
3. Copy the archive and the backup file across.
4. Unpack the app, start it once, then restore the database into the volume:

```bash
cd /opt/dropoutjeep
docker compose up -d --build
docker compose stop dropoutjeep
docker run --rm -v dropoutjeep_dropoutjeep-data:/data -v "$PWD":/backup alpine sh -c "cd /data && tar xzf /backup/backup-YYYY-MM-DD-HHMM.tgz"
docker compose start dropoutjeep
```

5. Copy `.env` across, it is kept out of the archive on purpose.
6. Change the DNS A record to the new IP, wait for it to propagate, then confirm the old data is there at `https://yourdomain.com`.
7. Keep the old box for a few days before you destroy it.

---

## Backups and housekeeping

- Run the backup command from the update section on a schedule. A cron line at 03:00 is fine. Put the stop, tar and start into a small script rather than a long one-liner in crontab.
- Copy the archives off the box weekly. A backup that only exists on the server you are about to rebuild is not a backup.
- Back up `.env` separately, in your password manager. Losing `HMAC_SECRET` invalidates every tracking link you have already sent.
- `audit.log` and the Docker logs grow. `RETENTION_DAYS` and the purge tool in the admin UI handle the database, and `docker system prune -f` reclaims old images after a few updates.
- Export or purge the database at the end of an engagement, then destroy the server. Captured credentials should not outlive the report.

---

## Testing on your local network first

If you want to rehearse without a domain, run the app directly on a machine in your LAN:

```bash
export BASE_URL=http://192.168.1.100:5000
export HOST=0.0.0.0
python dropoutjeep.py
```

Set `BASE_URL` to the IP the recipients will actually reach, otherwise tracking links in the email point at localhost. This is for rehearsal only. Do not run an engagement over plain HTTP on a LAN you do not control.

---

## Troubleshooting

**The site does not load at all.** Check DNS first: `nslookup yourdomain.com` from your laptop must return the server IP. Then `docker compose ps`, then `docker compose logs --tail 80 caddy`.

**"Bad gateway" or 502.** Caddy is up and the app is not. `docker compose logs --tail 100 dropoutjeep` names the missing setting, usually `FLASK_SECRET` or a `.env` saved to the wrong directory.

**Caddy cannot get a certificate.** Three causes in order of frequency: the DNS record does not point at the server yet, Cloudflare is proxying the record (set it to DNS only), or something else holds port 80. Check with `sudo ss -tulpn | grep :80`.

**The log says `no default admin user created`.** `ADMIN_USERNAME` or `ADMIN_PASSWORD` was missing when the container first started, and it will not add one now. Set both in `.env`, then:

```bash
docker compose up -d --force-recreate
```

If a user already exists, the seed step skips and you need the reset below.

**Forgot the admin password.**

```bash
docker compose exec dropoutjeep python - <<'PY'
from dropoutjeep import app
from dropoutjeep_lib import db
from dropoutjeep_lib.models import User
with app.app_context():
    u = User.query.filter_by(username='admin').first()
    u.set_password('NEWPASSWORD')
    db.session.commit()
    print('password changed')
PY
```

**Emails do not send.** If the sending profile points at port 25 on the VPS itself, it is blocked. Use a relay on 587 with STARTTLS. Then check that SPF, DKIM and DMARC exist for the sending domain, and send to your own inbox first.

**Emails land in spam.** Missing or wrong DKIM, a brand new domain, or a link domain on a blocklist. Warm the domain up slowly, start with low volume, and check the reputation tool in the app.

**The proxy renderer fails.** If a campaign's `renderer` is set to `playwright`, the image needs browsers, which the default image does not include:

```bash
docker compose exec dropoutjeep playwright install --with-deps chromium
```

That adds a few hundred MB. Do it only if you use that renderer.

**Everything is slow under load.** Check memory with `free -h`. SQLite plus the proxy on a 2 GB box will start swapping. Move to the 4 GB plan before you tune anything.

**Never run more than one app process.** The campaign scheduler and the live event feed run inside the app process. Two workers means two schedulers, which means duplicate sends. Do not add gunicorn workers here.

---

## Command cheat sheet

```bash
cd /opt/dropoutjeep
docker compose ps                      # are the containers up
docker compose logs -f dropoutjeep     # app logs, follow mode
docker compose logs --tail 100 caddy   # certificate and routing problems
docker compose up -d --build           # deploy new code
docker compose up -d                   # apply a .env change
docker compose restart caddy           # apply a Caddyfile change
docker compose down                    # stop everything, data stays in the volume
```

---

## What this setup does not do

Be honest with yourself about the ceiling before the client asks:

- One app process on Flask's built-in server. Fine for a few thousand recipients, not built for 50,000 concurrent clicks.
- SQLite in a Docker volume. Solid on one server, painful to share between two.
- No high availability. If the VPS dies mid-campaign, the campaign stops until you restore.
- PostgreSQL is supported by the code and the driver is not in the image. Add `psycopg2-binary` and rebuild if you need it.
- Log rotation, monitoring and alerting are yours to add. A dead box nobody noticed is the most common way an engagement goes wrong.

If any of those limits matter for this engagement, say so up front and plan the upgrade before the send date, not during it.
