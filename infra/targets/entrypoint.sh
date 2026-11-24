#!/bin/bash
# Start the role's services with `service` (no systemd in containers), then exec the daemon.
set -u
ROLE=$(cat /etc/prohori-role 2>/dev/null || echo web)
SSH=$(cat /etc/prohori-ssh 2>/dev/null || echo none)
log() { echo "$(date -u +%FT%TZ) [entrypoint] $*"; }

if [ "$SSH" = "server" ]; then
  # Per-container host keys (removed from the image at build time), privilege-separation dir, then sshd on :22.
  ssh-keygen -A >/dev/null
  mkdir -p /run/sshd
  service ssh start || log "ssh failed to start"
fi

if [ "$ROLE" = "web" ]; then
  service php8.3-fpm start || log "php8.3-fpm failed to start"
  service nginx start || log "nginx failed to start"
  if [ -x /etc/init.d/nginxwebui ]; then service nginxwebui start || log "nginxwebui failed to start"; fi
elif [ "$ROLE" = "batch" ]; then
  # cron-style nightly-batch stand-in: runs a PHP CLI job every 60s, nothing listens.
  ( while true; do php /opt/batch/reconcile.php >> /var/log/batch-reconcile.log 2>&1; sleep 60; done ) &
  log "batch loop started (php /opt/batch/reconcile.php every 60s)"
fi

DAEMON=${PROHORI_DAEMON_BIN:-/opt/prohori/bin/prohori-daemon}
while [ ! -f "$DAEMON" ]; do
  log "waiting for $DAEMON (build it: bun run daemon:build)"; sleep 5
done
log "starting prohori-daemon host=${PROHORI_HOST_ID:-?} brain=${PROHORI_BRAIN_URL:-?}"
exec "$DAEMON"
