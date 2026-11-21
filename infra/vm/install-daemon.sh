#!/usr/bin/env bash
# Install prohori-daemon on an Ubuntu 24.04 (systemd) VM.  Run as root:
#   sudo ./install-daemon.sh --binary ./prohori-daemon --brain-url wss://brain.example:4000/agent \
#        --host-id web-a --token <token> [--tier2]
# Without --tier2 the daemon is read-only (inventory + named queries).
# With --tier2 it can run the allowlisted actions via a sudoers drop-in limited to the exact commands.
set -euo pipefail

OSQUERY_VERSION=5.24.1
BINARY=""; BRAIN_URL=""; HOST_ID=""; TOKEN=""; TIER2=false
while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY=$2; shift 2;;
    --brain-url) BRAIN_URL=$2; shift 2;;
    --host-id) HOST_ID=$2; shift 2;;
    --token) TOKEN=$2; shift 2;;
    --tier2) TIER2=true; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ -f "$BINARY" ] && [ -n "$BRAIN_URL" ] && [ -n "$HOST_ID" ] && [ -n "$TOKEN" ] || {
  echo "usage: $0 --binary FILE --brain-url URL --host-id ID --token TOKEN [--tier2]" >&2; exit 2; }

echo "== osquery ${OSQUERY_VERSION}"
if ! command -v osqueryi >/dev/null; then
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/osquery.deb" "https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/osquery_${OSQUERY_VERSION}-1.linux_amd64.deb"
  apt-get install -y "$tmp/osquery.deb"
  rm -rf "$tmp"
fi
command -v iptables >/dev/null || apt-get install -y iptables

echo "== user + files"
id prohori >/dev/null 2>&1 || useradd --system --home /var/lib/prohori --shell /usr/sbin/nologin prohori
install -d -o prohori -g prohori -m 0750 /var/lib/prohori /var/lib/prohori/actions
install -m 0755 "$BINARY" /usr/local/bin/prohori-daemon
install -d -m 0750 -g prohori /etc/prohori
umask 077
cat > /etc/prohori/daemon.json <<JSON
{
  "PROHORI_BRAIN_URL": "${BRAIN_URL}",
  "PROHORI_HOST_ID": "${HOST_ID}",
  "PROHORI_TOKEN": "${TOKEN}",
  "PROHORI_TIER2": "${TIER2}",
  "OSQUERYI": "/usr/bin/osqueryi",
  "PROHORI_STATE_DIR": "/var/lib/prohori"
}
JSON
chown root:prohori /etc/prohori/daemon.json; chmod 0640 /etc/prohori/daemon.json
umask 022

SUDOERS=/etc/sudoers.d/prohori
# Read-only part (always): the firewall inventory needs `iptables -S INPUT` (root-only).
SUDO_RO='prohori ALL=(root) NOPASSWD: /usr/sbin/iptables -S INPUT'
SUDO_T2=""
if [ "$TIER2" = true ]; then
  echo "== tier2: write access to managed config files + action allowlist"
  # File edits (nginx snippet, php.ini) are done by the daemon itself, so grant write access to exactly those paths.
  if [ -d /etc/nginx ]; then
    install -d -o prohori -g root -m 0755 /etc/nginx/prohori
    grep -rqs 'include /etc/nginx/prohori/\*.conf;' /etc/nginx/sites-enabled/ \
      || echo "WARNING: add 'include /etc/nginx/prohori/*.conf;' inside your server block for nginx_block_multipart" >&2
  fi
  # set_config_directive edits exactly the CONFIG_DIRECTIVE_ALLOWLIST files in place (sshd_config: the daemon
  # runs `sshd -t` before restarting ssh and reverts the edit if validation fails).
  for f in /etc/php/8.3/fpm/php.ini /etc/php/8.3/cli/php.ini /etc/php/8.3/apache2/php.ini /etc/ssh/sshd_config; do
    if [ -f "$f" ]; then chgrp prohori "$f"; chmod g+w "$f"; fi
  done
  SUDO_T2=$(cat <<'SUDO'
Defaults!/usr/bin/apt-get env_keep += "DEBIAN_FRONTEND"
Cmnd_Alias PROHORI_APT = /usr/bin/apt-get update, \
  /usr/bin/apt-get install -y --only-upgrade -o Dpkg\:\:Options\:\:=--force-confold *, \
  /usr/bin/apt-get install -y --allow-downgrades -o Dpkg\:\:Options\:\:=--force-confold *
Cmnd_Alias PROHORI_SVC = /usr/sbin/service nginx reload, /usr/sbin/service nginx restart, \
  /usr/sbin/service php8.3-fpm restart, /usr/sbin/service apache2 restart, /usr/sbin/service ssh restart
Cmnd_Alias PROHORI_NGINX = /usr/sbin/nginx -t, /usr/sbin/nginx -T
Cmnd_Alias PROHORI_CFGTEST = /usr/sbin/sshd -t, /usr/sbin/sshd -T, /usr/sbin/php-fpm8.3 -t
Cmnd_Alias PROHORI_FW = \
  /usr/sbin/iptables -I INPUT 1 -p tcp -m tcp --dport * -m comment --comment prohori\:* -j REJECT --reject-with tcp-reset, \
  /usr/sbin/iptables -I INPUT 1 -p udp -m udp --dport * -m comment --comment prohori\:* -j DROP, \
  /usr/sbin/iptables -D INPUT -p tcp -m tcp --dport * -m comment --comment prohori\:* -j REJECT --reject-with tcp-reset, \
  /usr/sbin/iptables -D INPUT -p udp -m udp --dport * -m comment --comment prohori\:* -j DROP
prohori ALL=(root) NOPASSWD: PROHORI_APT, PROHORI_SVC, PROHORI_NGINX, PROHORI_CFGTEST, PROHORI_FW
SUDO
)
fi
printf '# Managed by infra/vm/install-daemon.sh. The daemon validates every parameter before calling these.\nDefaults:prohori !requiretty\n%s\n%s\n' "$SUDO_RO" "$SUDO_T2" > "$SUDOERS.tmp"
visudo -cf "$SUDOERS.tmp"
install -m 0440 "$SUDOERS.tmp" "$SUDOERS"; rm -f "$SUDOERS.tmp"

echo "== systemd unit"
cat > /etc/systemd/system/prohori-daemon.service <<UNIT
[Unit]
Description=Prohori host daemon (osquery inventory + allowlisted actions)
After=network-online.target
Wants=network-online.target

[Service]
User=prohori
Group=prohori
Environment=PROHORI_CONFIG=/etc/prohori/daemon.json
ExecStart=/usr/local/bin/prohori-daemon
Restart=always
RestartSec=5
# osquery needs to see sockets/processes of other users (listening_ports -> owning process):
# CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH let it read /proc/<pid>/fd without running as root.
# Firewall inventory/actions and package/service actions go through sudo (see /etc/sudoers.d/prohori).
# No CapabilityBoundingSet / NoNewPrivileges: they would cripple the sudo'd apt-get/dpkg runs.
AmbientCapabilities=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now prohori-daemon
sleep 2
systemctl --no-pager status prohori-daemon | head -15 || true
echo "logs: journalctl -u prohori-daemon -f"
