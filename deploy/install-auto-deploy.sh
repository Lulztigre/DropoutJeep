#!/usr/bin/env bash
# install-auto-deploy.sh - run this once on the VPS as root.
#
#   bash /opt/dropoutjeep/deploy/install-auto-deploy.sh
#
# After this, any push to main lands on the box within two minutes:
#   git push  ->  timer sees a new commit  ->  docker compose up -d --build
#
# Manual run:   systemctl start dj-deploy
# Watch it:     tail -f /var/log/dj-deploy.log
# Stop it:      systemctl disable --now dj-deploy.timer

set -euo pipefail

APP_DIR="${APP_DIR:-/opt/dropoutjeep}"

chmod +x "$APP_DIR/deploy/auto-deploy.sh"
mkdir -p /var/log
touch /var/log/dj-deploy.log

cat >/etc/systemd/system/dj-deploy.service <<EOF
[Unit]
Description=DropoutJeep deploy from git
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$APP_DIR
Environment=APP_DIR=$APP_DIR
ExecStart=/bin/bash $APP_DIR/deploy/auto-deploy.sh
TimeoutStartSec=1800
EOF

cat >/etc/systemd/system/dj-deploy.timer <<EOF
[Unit]
Description=Check for DropoutJeep updates every 2 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
AccuracySec=30s
Unit=dj-deploy.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now dj-deploy.timer

echo "installed."
systemctl list-timers dj-deploy.timer --no-pager || true
echo
echo "next check runs within 2 minutes; tail -f /var/log/dj-deploy.log to watch it"
