#!/usr/bin/env bash
# DropoutJeep VPS bootstrap.
#
# Turns a fresh Ubuntu 22.04/24.04 box into a working deployment:
# docker, a deploy user, firewall, the repo in /opt/dropoutjeep, a generated
# .env with fresh secrets, an optional admin allowlist in the Caddyfile, and
# the stack running.
#
# Idempotent: rerunning it keeps the existing .env and secrets.
#
# Usage on the server (as root):
#   DOMAIN=sim.example.com bash bootstrap.sh
#
# Optional environment:
#   DOMAIN              public hostname (required)
#   ADMIN_USER          first admin login            (default: admin)
#   ADMIN_PASSWORD      first admin password         (default: generated)
#   ADMIN_IP            allow only this IP on /admin* (default: open)
#   REPO_URL            git remote                   (default: public repo)
#   BRANCH              git branch                   (default: main)
#   APP_DIR             install directory            (default: /opt/dropoutjeep)
#   DEPLOY_USER         non-root user                (default: deploy)
#   SSH_PUBKEY          key to install for DEPLOY_USER (optional)
#   RETENTION_DAYS      event retention              (default: 180)
#   SKIP_APT=1          skip package install (used by the test rig)
#   FORCE_ENV=1         regenerate .env and secrets (refused on a live install)
#   PREP_ONLY=1         do everything except start the stack, so you can set the
#                       box up before DNS exists. Finish later with
#                       cd $APP_DIR && docker compose up -d --build

set -Eeuo pipefail

DOMAIN="${DOMAIN:-}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
ADMIN_IP="${ADMIN_IP:-}"
REPO_URL="${REPO_URL:-https://github.com/Lulztigre/DropoutJeep.git}"
BRANCH="${BRANCH:-main}"
APP_DIR="${APP_DIR:-/opt/dropoutjeep}"
DEPLOY_USER="${DEPLOY_USER:-deploy}"
SSH_PUBKEY="${SSH_PUBKEY:-}"
RETENTION_DAYS="${RETENTION_DAYS:-180}"
SKIP_APT="${SKIP_APT:-0}"
FORCE_ENV="${FORCE_ENV:-0}"
PREP_ONLY="${PREP_ONLY:-0}"

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[!] %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m[x] %s\033[0m\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo bash $0)"
[[ -n "$DOMAIN" ]] || die "DOMAIN is required"

if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  case "${ID:-}" in
    ubuntu|debian) : ;;
    *) warn "untested distro: ${ID:-unknown}, continuing" ;;
  esac
fi

# --- packages -------------------------------------------------------------
if [[ "$SKIP_APT" != "1" ]]; then
  log "Installing base packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl git rsync ufw openssl >/dev/null
fi

# --- docker ---------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker"
  curl -fsSL https://get.docker.com | sh >/dev/null
else
  log "Docker already present: $(docker --version | cut -d, -f1)"
fi
if docker compose version >/dev/null 2>&1; then
  log "Compose plugin: $(docker compose version --short 2>/dev/null || echo present)"
else
  die "docker compose plugin missing, install it or use a newer docker"
fi

# --- deploy user ----------------------------------------------------------
if id "$DEPLOY_USER" >/dev/null 2>&1; then
  log "User $DEPLOY_USER exists"
else
  log "Creating user $DEPLOY_USER"
  if command -v adduser >/dev/null 2>&1; then
    adduser --disabled-password --gecos "" "$DEPLOY_USER" >/dev/null
  else
    useradd --create-home --shell /bin/bash "$DEPLOY_USER"
  fi
fi
getent group docker >/dev/null 2>&1 || groupadd docker
usermod -aG docker "$DEPLOY_USER"

install_key() {
  local key="$1" home
  home="$(getent passwd "$DEPLOY_USER" | cut -d: -f6)"
  install -d -m 700 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "$home/.ssh"
  touch "$home/.ssh/authorized_keys"
  grep -qxF "$key" "$home/.ssh/authorized_keys" 2>/dev/null || printf '%s\n' "$key" >> "$home/.ssh/authorized_keys"
  chown "$DEPLOY_USER:$DEPLOY_USER" "$home/.ssh/authorized_keys"
  chmod 600 "$home/.ssh/authorized_keys"
}

if [[ -n "$SSH_PUBKEY" ]]; then
  log "Installing SSH key for $DEPLOY_USER"
  install_key "$SSH_PUBKEY"
elif [[ -s /root/.ssh/authorized_keys ]]; then
  log "Copying root's authorized keys to $DEPLOY_USER"
  while IFS= read -r key; do [[ -n "$key" ]] && install_key "$key"; done < /root/.ssh/authorized_keys
else
  warn "no SSH key found for $DEPLOY_USER, password login is the only way in"
fi

# --- firewall -------------------------------------------------------------
if command -v ufw >/dev/null 2>&1; then
  log "Firewall: allow 22, 80, 443"
  ufw allow OpenSSH >/dev/null 2>&1 || true
  ufw allow 80/tcp >/dev/null 2>&1 || true
  ufw allow 443/tcp >/dev/null 2>&1 || true
  ufw --force enable >/dev/null 2>&1 || warn "ufw could not be enabled in this environment"
  ufw status 2>/dev/null | head -n 6 || true
else
  warn "ufw not present, skipping firewall rules"
fi

# --- code -----------------------------------------------------------------
if [[ -d "$APP_DIR/.git" ]]; then
  log "Updating existing checkout in $APP_DIR"
  git -C "$APP_DIR" fetch --quiet origin "$BRANCH"
  git -C "$APP_DIR" checkout --quiet "$BRANCH"
  git -C "$APP_DIR" pull --quiet --ff-only origin "$BRANCH"
elif [[ -d "$APP_DIR" ]] && [[ -n "$(ls -A "$APP_DIR" 2>/dev/null)" ]]; then
  log "Using pre-staged files in $APP_DIR (no git checkout)"
else
  log "Cloning $REPO_URL into $APP_DIR"
  install -d -o "$DEPLOY_USER" -g "$DEPLOY_USER" "$APP_DIR"
  git clone --quiet --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
fi
chown -R "$DEPLOY_USER:$DEPLOY_USER" "$APP_DIR"
cd "$APP_DIR"
[[ -f docker-compose.yml ]] || die "docker-compose.yml missing in $APP_DIR"
[[ -f Caddyfile ]] || die "Caddyfile missing in $APP_DIR"

# --- secrets and .env -----------------------------------------------------
gen() { openssl rand -hex 32; }

ENV_FILE="$APP_DIR/.env"
GENERATED_PASSWORD=""
if [[ -f "$ENV_FILE" && "$FORCE_ENV" = "1" && "${FORCE_ENV_CONFIRM:-}" != "YES" ]]; then
  die "FORCE_ENV=1 on an existing install regenerates FLASK_SECRET and FERNET_KEY.
    Every secret already stored in the database becomes unreadable: SMTP and IMAP
    passwords, DKIM private keys, captured credentials, exfil data.
    If you really want that, rerun with FORCE_ENV=1 FORCE_ENV_CONFIRM=YES."
fi
if [[ -f "$ENV_FILE" && "$FORCE_ENV" != "1" ]]; then
  log "Keeping existing .env (FORCE_ENV=1 to regenerate)"
  chmod 600 "$ENV_FILE"
  chown "$DEPLOY_USER:$DEPLOY_USER" "$ENV_FILE"
  ADMIN_USER="$(grep -E '^ADMIN_USERNAME=' "$ENV_FILE" | cut -d= -f2- || true)"
else
  log "Writing .env"
  FLASK_SECRET="$(gen)"
  HMAC_SECRET="$(gen)"
  # Fernet key: 32 random bytes, urlsafe base64. Pinned so that rotating
  # FLASK_SECRET later does not orphan stored SMTP/IMAP passwords and DKIM keys.
  FERNET_KEY="$(openssl rand -base64 32 | tr '+/' '-_')"
  if [[ -z "$ADMIN_PASSWORD" ]]; then
    ADMIN_PASSWORD="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)"
    GENERATED_PASSWORD="$ADMIN_PASSWORD"
  fi
  umask 077
  cat > "$ENV_FILE" <<EOF
PHISH_DOMAIN=$DOMAIN
FLASK_SECRET=$FLASK_SECRET
HMAC_SECRET=$HMAC_SECRET
FERNET_KEY=$FERNET_KEY
ADMIN_USERNAME=$ADMIN_USER
ADMIN_PASSWORD=$ADMIN_PASSWORD
SESSION_LIFETIME_HOURS=8
RETENTION_DAYS=$RETENTION_DAYS
EOF
  chown "$DEPLOY_USER:$DEPLOY_USER" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
fi
[[ -s "$ENV_FILE" ]] || die ".env is empty"

# --- Caddyfile (only rewritten when an allowlist is requested) ------------
if [[ -n "$ADMIN_IP" ]]; then
  log "Writing Caddyfile with admin allowlist for $ADMIN_IP"
  [[ -f "$APP_DIR/Caddyfile.bootstrap" ]] || cp "$APP_DIR/Caddyfile" "$APP_DIR/Caddyfile.bootstrap"
  cat > "$APP_DIR/Caddyfile" <<EOF
$DOMAIN {
    header -Server
    @private path /admin*
    handle @private {
        @notme not remote_ip $ADMIN_IP
        respond @notme "Not found" 404
        reverse_proxy dropoutjeep:5000
    }
    handle {
        reverse_proxy dropoutjeep:5000
    }
}
EOF
  chown "$DEPLOY_USER:$DEPLOY_USER" "$APP_DIR/Caddyfile"
else
  log "No ADMIN_IP set, leaving Caddyfile as shipped"
fi

# --- run ------------------------------------------------------------------
if [[ "$PREP_ONLY" = "1" ]]; then
  log "PREP_ONLY=1: stack not started"
  log "Prebuilding the app image so the first start after DNS is quick"
  docker compose build
else
  log "Building and starting the stack"
  docker compose up -d --build

  log "Waiting for the app to answer on /admin/login"
  ok=0
  for _ in $(seq 1 45); do
    if docker compose exec -T dropoutjeep python -c "
import urllib.request, sys
r = urllib.request.urlopen('http://127.0.0.1:5000/admin/login', timeout=5)
sys.exit(0 if r.status == 200 else 1)
" >/dev/null 2>&1; then ok=1; break; fi
    sleep 2
  done
  [[ "$ok" == "1" ]] || { docker compose logs --tail 40 dropoutjeep; die "app did not answer, see logs above"; }

  docker compose ps
fi

if [[ "$PREP_ONLY" = "1" ]]; then
cat <<EOF

------------------------------------------------------------
Prepared, not started. Nothing depends on DNS yet, so this is the
right place to pause.

  Install dir  $APP_DIR
  Env file     $ENV_FILE (mode 600, secrets generated)
  Admin user   $ADMIN_USER
  Admin IP     ${ADMIN_IP:-(open to the internet)}
$([[ -n "$GENERATED_PASSWORD" ]] && printf '  Admin pass   %s\n' "$GENERATED_PASSWORD")

When DNS for $DOMAIN points at this server, start it:

  cd $APP_DIR && docker compose up -d --build
  docker compose logs -f caddy

Until then Caddy has no certificate to fetch and the site will not answer.
Starting it after DNS avoids a day of failed ACME attempts in the log.
------------------------------------------------------------
EOF
else
cat <<EOF

------------------------------------------------------------
DropoutJeep is up.

  URL        https://$DOMAIN
  Login      https://$DOMAIN/admin/login
  Admin user $ADMIN_USER
  Password   stored in $ENV_FILE (mode 600)
$([[ -n "$GENERATED_PASSWORD" ]] && printf '  Generated  %s\n' "$GENERATED_PASSWORD")
  Update     cd $APP_DIR && git pull --ff-only && docker compose up -d --build
  Backup     docker compose stop dropoutjeep
             docker run --rm -v dropoutjeep_dropoutjeep-data:/data \\
               -v "\$PWD":/backup alpine tar czf /backup/backup-\$(date +%F).tgz -C /data .
             docker compose start dropoutjeep

Certificate issuance needs DNS pointing at this server already.
Check with: docker compose logs -f caddy
------------------------------------------------------------
EOF
fi
