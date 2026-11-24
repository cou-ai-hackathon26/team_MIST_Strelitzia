#!/usr/bin/env bash
# One-command demo start: lab containers, brain, dashboard, healthcheck.
export PATH="$HOME/.bun/bin:$PATH"
cd "$(dirname "$0")"
mkdir -p /tmp/prohori
systemctl is-active --quiet docker || sudo systemctl start docker
bun run targets:up
pgrep -f "apps/brain" >/dev/null || (setsid nohup bun run brain >/tmp/prohori/brain.log 2>&1 &)
pgrep -f "next start|next-server" >/dev/null || (setsid nohup bun run web:prod >/tmp/prohori/web.log 2>&1 &)
echo "waiting for services..."; sleep 40
bun run healthcheck
