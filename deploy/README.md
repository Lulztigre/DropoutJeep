# Deploying DropoutJeep with scripts

Two files do the server work so you do not retype 40 commands:

- `deploy/bootstrap.sh` runs on the server. Installs Docker, creates the `deploy` user, sets the firewall, clones or accepts the code in `/opt/dropoutjeep`, generates secrets into `.env`, optionally locks `/admin` to your IP, builds and starts the stack, then checks the app answers.
- `deploy/deploy.ps1` runs on Windows. Packs this folder, uploads it, and triggers the bootstrap over SSH, or renders a cloud-init file for providers that self-setup on first boot. Optionally creates the DNS record at Cloudflare.

## What is and is not automated

| Step | Automated | Notes |
|---|---|---|
| Buying the VPS | No | Payment, account, region choice. |
| The AUP / abuse ticket | No | Send it before you build, it is the step people skip and regret. |
| Buying the domain | No | Any registrar. |
| DNS A record | Yes, if the domain is on Cloudflare | Otherwise one manual record. |
| Docker, user, firewall | Yes | `bootstrap.sh`. |
| Secrets and `.env` | Yes | 64 hex chars, mode 600, generated on the box. |
| Code checkout | Yes | `git clone` of the public repo, or upload for local changes. |
| TLS certificate | Yes | Caddy, automatic once DNS resolves. |
| Admin allowlist | Yes, when you pass `-AdminIp` | Rewrites the Caddyfile, keeps the original as `Caddyfile.bootstrap`. |
| Stack running | Yes | `docker compose up -d --build` plus a health check on `/admin/login`. |
| Reading the generated password | No | One `ssh` command, it is never sent over the wire by the script. |

## Prerequisites on your machine

- PowerShell 5.1 or newer (ships with Windows).
- The Windows OpenSSH client: `ssh` and `scp` on PATH. Settings, Apps, Optional features, OpenSSH Client.
- `tar`, which Windows 10 and 11 include.
- The server's SSH key added at the provider, so `ssh root@IP` works without a password prompt.

## Path A: SSH upload (works everywhere, including Cloudzy)

```powershell
cd C:\Users\moyoo\DropoutJeep
.\deploy\deploy.ps1 -Domain sim.example.com -ServerIp 203.0.113.45 -AdminIp 41.58.0.10
```

What happens: the folder is packed (no `venv`, no logs, no database), uploaded to `/tmp`, unpacked into `/opt/dropoutjeep`, and `bootstrap.sh` runs as root. Roughly 3 to 6 minutes, most of it the image build.

Add DNS automation when the domain is on Cloudflare:

```powershell
$env:CF_TOKEN = "your-scoped-token"
.\deploy\deploy.ps1 -Domain sim.example.com -ServerIp 203.0.113.45 `
  -AdminIp 41.58.0.10 -CfZone 023e105f4ecef8ad9ca31a8372d0c353
```

The token needs `Zone.DNS Edit` on that zone only. The record is created as DNS only, grey cloud, and the script waits until it resolves or tells you it has not yet.

## Path B: cloud-init (Hetzner, DigitalOcean, Vultr and most others)

Render the file, then paste it into the provider's user data box at server creation:

```powershell
.\deploy\deploy.ps1 -Domain sim.example.com -Mode CloudInit -AdminIp 41.58.0.10
```

It writes `deploy/cloud-init.rendered.yaml`. Create the server with Ubuntu 24.04, paste the whole file including the `#cloud-config` first line, add your SSH key as usual, and wait three to five minutes. No SSH needed from you.

Watch it work:

```bash
ssh root@SERVER_IP "tail -f /var/log/dropoutjeep-bootstrap.log"
```

Then read the generated password:

```bash
ssh root@SERVER_IP "sudo cat /opt/dropoutjeep/.env"
```

Cloud-init runs once, on first boot. This path clones from GitHub, so `deploy/` has to be pushed before you use it. If your local tree has unpushed changes, use Path A.

## Path C: before the domain exists

The box can be fully prepared while DNS is still propagating. Add `-PrepOnly`:

```powershell
.\deploy\deploy.ps1 -Domain sim.example.com -ServerIp 203.0.113.45 -AdminIp 41.58.0.10 -PrepOnly
```

It does everything above except start the stack: packages, Docker, user, firewall, code, `.env` with secrets, the Caddyfile allowlist, and `docker compose build` so the image is ready.

No compose up means no Caddy container attempting certificates for a hostname that does not resolve yet, which keeps the log readable. When DNS lands:

```bash
ssh root@SERVER_IP "cd /opt/dropoutjeep && docker compose up -d --build"
ssh root@SERVER_IP "cd /opt/dropoutjeep && docker compose logs -f caddy"
```

The second start reuses the existing `.env`, so the secrets you generated during prep stay valid.

## What bootstrap.sh does, in order

1. Checks it is running as root on Ubuntu or Debian.
2. Installs `ca-certificates curl git rsync ufw openssl`.
3. Installs Docker from `get.docker.com` if `docker` is missing, and fails loudly if the Compose plugin is absent.
4. Creates the `deploy` user, adds it to `docker`, installs your SSH key from `SSH_PUBKEY` or copies root's keys.
5. Opens 22, 80 and 443 in ufw and enables it.
6. Clones or updates `/opt/dropoutjeep`, or uses files already staged there.
7. Writes `.env` with fresh `FLASK_SECRET`, `HMAC_SECRET` and `FERNET_KEY`, an admin password if you did not supply one, and mode 600.
8. Writes the Caddyfile with the admin allowlist when `ADMIN_IP` is set, backing up the original once.
9. Runs `docker compose up -d --build`.
10. Polls `/admin/login` inside the app container for up to 90 seconds, dumps the app log and fails if it never answers.
11. Prints the URL, admin user, where the password lives, the update command and the backup command.

## Variables

Set these on the server, or pass them through `deploy.ps1`.

| Variable | Default | Meaning |
|---|---|---|
| `DOMAIN` | required | public hostname |
| `ADMIN_USER` | `admin` | first admin login, only used when the database is empty |
| `ADMIN_PASSWORD` | generated | leave empty and the script makes one |
| `ADMIN_IP` | empty | allowlist for `/admin*`, empty means open to the internet |
| `REPO_URL` | public GitHub repo | change for a fork |
| `BRANCH` | `main` | branch to deploy |
| `APP_DIR` | `/opt/dropoutjeep` | install path, changing it changes the Docker volume name too |
| `DEPLOY_USER` | `deploy` | non-root user |
| `RETENTION_DAYS` | `180` | event retention written into `.env` |
| `FORCE_ENV` | `0` | set to 1 to regenerate `.env` and rotate secrets. Refused on an existing install unless `FORCE_ENV_CONFIRM=YES` |
| `PREP_ONLY` | `0` | 1 does everything except start the stack, for use before DNS exists |
| `SKIP_APT` | `0` | 1 skips package install, used by the test rig |

## Rerunning it

Safe. A second run keeps the existing `.env` and secrets, keeps the Caddyfile, pulls the latest code and rebuilds.

Only `FORCE_ENV=1` rotates secrets, and it now refuses to do that on an existing install without `FORCE_ENV_CONFIRM=YES`, because a new `FLASK_SECRET` or `FERNET_KEY` makes every stored secret unreadable: SMTP and IMAP passwords, DKIM private keys, captured credentials. Rotating `HMAC_SECRET` separately invalidates tracking links you have already sent.

## After it finishes

```bash
ssh root@SERVER_IP "cd /opt/dropoutjeep && docker compose logs -f caddy"   # certificate
ssh root@SERVER_IP "cd /opt/dropoutjeep && docker compose ps"              # both up
ssh root@SERVER_IP "cd /opt/dropoutjeep && git pull --ff-only && docker compose up -d --build"   # update
```

## Teardown

```bash
ssh root@SERVER_IP "cd /opt/dropoutjeep && docker compose down -v"
```

`-v` deletes the database volume. Pull a backup first if the engagement has not been reported yet. Then destroy the server at the provider.

## When it goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| `Permission denied (publickey)` | provider key not on the account | add the key, or use the provider console |
| `deploy/bootstrap.sh: No such file` | cloud-init path, `deploy/` not pushed | push it, or use Path A |
| `docker compose plugin missing` | old Docker | `curl -fsSL https://get.docker.com | sh` |
| app did not answer, log shows missing `FLASK_SECRET` | `.env` not written | rerun, check `/opt/dropoutjeep/.env` |
| certificate never appears | DNS not pointing at the box, or Cloudflare proxying | grey cloud, then `docker compose restart caddy` |
| `ufw could not be enabled` | container or restricted host | fine on a VPS, ignore on a test box |
| password unknown | generated and printed once | `sudo grep ADMIN_PASSWORD /opt/dropoutjeep/.env` |
| SMTP password rejected after an env change | `FLASK_SECRET` changed without `FERNET_KEY`, so stored secrets cannot be decrypted | restore the old `.env`, or re-enter every SMTP, IMAP and DKIM secret by hand |

## Security notes

- `.env` is written with mode 600 and owned by `deploy`. It is in `.gitignore`, keep it there.
- The generated admin password is printed to the console once. Save it in your password manager, not in a chat log.
- `ADMIN_PASSWORD` only takes effect while the user table is empty. Changing it later in `.env` does nothing, use the UI or the reset snippet in `VPS_DEPLOYMENT.md`.
- `deploy.ps1` never sends the admin password over SSH. It generates on the box and you read it there.
