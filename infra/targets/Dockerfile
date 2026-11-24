# Prohori demo target. One image, roles selected by build args.
#   ROLE=web   -> nginx + php8.3-fpm (+cli)   (target-a / target-b)
#   ROLE=batch -> php8.3-cli only, no listener (target-c)
#   ROLE=ssh   -> no PHP, no web server        (target-d)
#   PHP_BUILD  -> exact Ubuntu build of every php8.3-* package (web/batch)
#   SSH        -> none | client (openssh-client only) | server (openssh-server + sshd on :22)
#   SSH_BUILD  -> exact Ubuntu build of the openssh-* packages; empty = latest available (noble-security)
#   NGINXWEBUI -> version of the nginxWebUI LAB STUB package to install (empty = none): a local .deb named
#                 "nginxwebui" with a login-page-only HTTP service on :8080 (no command execution), so advisory
#                 judgments of nginxWebUI CVEs have a realistic package + listener to find.
FROM ubuntu:24.04

ARG ROLE=web
ARG PHP_BUILD=8.3.6-0maysync1
ARG SSH=none
ARG SSH_BUILD=
ARG NGINXWEBUI=
ARG OSQUERY_VERSION=5.24.1
# Superseded Ubuntu builds disappear from the live archive; set e.g. 20261101T000000Z to install the pinned
# PHP_BUILD from snapshot.ubuntu.com. Sources are pointed back at the live archive before the image is finished,
# so the upgrade_packages action can still reach the newer (fixed) build at runtime.
ARG APT_SNAPSHOT=

ENV DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC

# NOTE: /var/lib/apt/lists is intentionally kept: the upgrade_packages action needs apt at runtime.
# unattended-upgrades is never installed, so the pinned (vulnerable) build stays put until Prohori upgrades it.
RUN set -eux; \
    rm -f /etc/apt/apt.conf.d/docker-clean; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    if [ -n "$APT_SNAPSHOT" ]; then \
      cp /etc/apt/sources.list.d/ubuntu.sources /tmp/ubuntu.sources.live; \
      sed -i -E "s#https?://(archive|security)\.ubuntu\.com/ubuntu/?#https://snapshot.ubuntu.com/ubuntu/${APT_SNAPSHOT}#" /etc/apt/sources.list.d/ubuntu.sources; \
      apt-get update; \
    fi; \
    apt-get install -y --no-install-recommends curl procps iproute2 tzdata iptables; \
    curl -fsSL -o /tmp/osquery.deb "https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/osquery_${OSQUERY_VERSION}-1.linux_amd64.deb"; \
    apt-get install -y /tmp/osquery.deb; rm -f /tmp/osquery.deb; \
    if [ "$ROLE" = "web" ]; then \
      PKGS="nginx php8.3-fpm=${PHP_BUILD} php8.3-cli=${PHP_BUILD} php8.3-common=${PHP_BUILD} php8.3-opcache=${PHP_BUILD} php8.3-readline=${PHP_BUILD}"; \
    elif [ "$ROLE" = "batch" ]; then \
      PKGS="php8.3-cli=${PHP_BUILD} php8.3-common=${PHP_BUILD} php8.3-opcache=${PHP_BUILD} php8.3-readline=${PHP_BUILD}"; \
    else \
      PKGS=""; \
    fi; \
    V=${SSH_BUILD:+=${SSH_BUILD}}; \
    if [ "$SSH" = "server" ]; then \
      PKGS="$PKGS openssh-server${V} openssh-client${V} openssh-sftp-server${V}"; \
    elif [ "$SSH" = "client" ]; then \
      PKGS="$PKGS openssh-client${V}"; \
    fi; \
    if [ -n "$PKGS" ]; then apt-get install -y --no-install-recommends $PKGS; fi; \
    if [ -n "$APT_SNAPSHOT" ]; then \
      cp /tmp/ubuntu.sources.live /etc/apt/sources.list.d/ubuntu.sources; rm -f /tmp/ubuntu.sources.live; \
      apt-get update; \
    fi; \
    apt-get purge -y unattended-upgrades 2>/dev/null || true; \
    rm -rf /var/cache/apt/archives/*.deb; \
    mkdir -p /var/lib/prohori/actions; \
    if [ "$ROLE" = "web" ]; then mkdir -p /etc/nginx/prohori; fi; \
    dpkg -l 'php8.3-*' 'openssh-*' 2>/dev/null | awk '/^ii/{print $2, $3}'; \
    if [ "$SSH" = "server" ]; then \
      mkdir -p /run/sshd; rm -f /etc/ssh/ssh_host_*; \
      systemctl disable ssh.socket 2>/dev/null || true; \
    fi; \
    echo "$SSH" > /etc/prohori-ssh

# Show the version banner (the "naive scanner" view) and allow uploads.
RUN set -eux; for ini in /etc/php/8.3/*/php.ini; do \
      [ -f "$ini" ] || continue; \
      sed -i -E 's/^;?\s*expose_php\s*=.*/expose_php = On/' "$ini"; \
    done

COPY site/ /opt/prohori-site/
COPY nginxwebui/ /opt/prohori-nginxwebui/
RUN set -eux; \
    if [ -n "$NGINXWEBUI" ]; then \
      P=/tmp/nginxwebui-pkg; mkdir -p $P/DEBIAN $P/opt/nginxwebui $P/etc/init.d $P/etc/nginxwebui; \
      sed "s/__VERSION__/${NGINXWEBUI}/" /opt/prohori-nginxwebui/control > $P/DEBIAN/control; \
      install -m 0755 /opt/prohori-nginxwebui/nginxwebui $P/opt/nginxwebui/nginxwebui; \
      sed -i "s/^my \$VERSION = .*/my \$VERSION = \"${NGINXWEBUI}\";/" $P/opt/nginxwebui/nginxwebui; \
      install -m 0755 /opt/prohori-nginxwebui/nginxwebui.init $P/etc/init.d/nginxwebui; \
      install -m 0644 /opt/prohori-nginxwebui/application.properties $P/etc/nginxwebui/application.properties; \
      dpkg-deb --build --root-owner-group $P /tmp/nginxwebui.deb; dpkg -i /tmp/nginxwebui.deb; rm -rf $P /tmp/nginxwebui.deb; \
      dpkg -l nginxwebui | awk '/^ii/{print $2, $3}'; \
    fi; \
    rm -rf /opt/prohori-nginxwebui
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN set -eux; chmod +x /usr/local/bin/entrypoint.sh; \
    if [ "$ROLE" = "web" ]; then \
      mkdir -p /var/www/bank; cp /opt/prohori-site/*.php /var/www/bank/; \
      mkdir -p /var/www/bank/uploads; chown www-data:www-data /var/www/bank/uploads; \
      cp /opt/prohori-site/nginx-bank.conf /etc/nginx/sites-available/bank; \
      rm -f /etc/nginx/sites-enabled/default; ln -s /etc/nginx/sites-available/bank /etc/nginx/sites-enabled/bank; \
      nginx -t; \
    elif [ "$ROLE" = "batch" ]; then \
      mkdir -p /opt/batch; cp /opt/prohori-site/batch/reconcile.php /opt/batch/; \
    fi; \
    echo "$ROLE" > /etc/prohori-role

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
