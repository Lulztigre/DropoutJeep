#!/usr/bin/env bash
# auto-deploy.sh - pull this repo on the VPS and rebuild only when HEAD moved.
#
# Installed by deploy/install-auto-deploy.sh as a systemd timer (every 2 minutes).
# Logs to /var/log/dj-deploy.log.
#
# Two things are preserved across the reset on purpose:
#   Caddyfile   holds the admin IP allowlist, which is per-deployment, not in git
#   .env        holds FERNET_KEY, HMAC_SECRET and the admin password
# Losing either one takes the portal down or locks you out.

set -euo pipefail

APP_DIR="${APP_DIR:-/opt/dropoutjeep}"
BRANCH="${BRANCH:-main}"
STATE="$APP_DIR/.deployed_rev"
LOG="${LOG:-/var/log/dj-deploy.log}"

mkdir -p "$(dirname "$LOG")"
exec >>"$LOG" 2>&1

echo "[$(date -Is)] check"

cd "$APP_DIR" || { echo "no $APP_DIR"; exit 1; }
if [ ! -d .git ]; then
  echo "not a git checkout, nothing to pull"
  exit 0
fi

git fetch --quiet origin "$BRANCH" || { echo "fetch failed"; exit 1; }
remote="$(git rev-parse "origin/$BRANCH")"
current="$(git rev-parse HEAD)"
last=""
[ -f "$STATE" ] && last="$(cat "$STATE")"

if [ "$remote" = "$current" ] && [ "$remote" = "$last" ]; then
  echo "no change at $current"
  exit 0
fi

echo "deploying $remote (was $current)"

backup="$(mktemp -d)"
[ -f Caddyfile ] && cp Caddyfile "$backup/Caddyfile"
[ -f .env ] && cp .env "$backup/.env"

git checkout -q -B "$BRANCH" "origin/$BRANCH"
git reset -q --hard "origin/$BRANCH"

[ -f "$backup/Caddyfile" ] && cp "$backup/Caddyfile" Caddyfile
[ -f "$backup/.env" ] && cp "$backup/.env" .env
rm -rf "$backup"

docker compose up -d --build
if [ -n "$(docker compose -f docker-compose.proxy.yml ps -q 2>/dev/null || true)" ]; then
  docker compose -f docker-compose.proxy.yml up -d --build
fi

echo "$remote" > "$STATE"
echo "[$(date -Is)] done"
