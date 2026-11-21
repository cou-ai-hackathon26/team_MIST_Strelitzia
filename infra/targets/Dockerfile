# Prohori demo target. One image, three roles selected by build args.
#   ROLE=web   -> nginx + php8.3-fpm (+cli)   (target-a / target-b)
#   ROLE=batch -> php8.3-cli only, no listener (target-c)
#   PHP_BUILD  -> exact Ubuntu build of every php8.3-* package
FROM ubuntu:24.04

ARG ROLE=web
ARG PHP_BUILD=8.3.6-0maysync1
ARG OSQUERY_VERSION=5.24.1

ENV DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC

# NOTE: /var/lib/apt/lists is intentionally kept: the upgrade_packages action needs apt at runtime.
# unattended-upgrades is never installed, so the pinned (vulnerable) build stays put until Prohori upgrades it.
RUN set -eux; \
    rm -f /etc/apt/apt.conf.d/docker-clean; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl procps iproute2 tzdata iptables; \
    curl -fsSL -o /tmp/osquery.deb "https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/osquery_${OSQUERY_VERSION}-1.linux_amd64.deb"; \
    apt-get install -y /tmp/osquery.deb; rm -f /tmp/osquery.deb; \
    if [ "$ROLE" = "web" ]; then \
      PKGS="nginx php8.3-fpm=${PHP_BUILD} php8.3-cli=${PHP_BUILD} php8.3-common=${PHP_BUILD} php8.3-opcache=${PHP_BUILD} php8.3-readline=${PHP_BUILD}"; \
    else \
      PKGS="php8.3-cli=${PHP_BUILD} php8.3-common=${PHP_BUILD} php8.3-opcache=${PHP_BUILD} php8.3-readline=${PHP_BUILD}"; \
    fi; \
    apt-get install -y --no-install-recommends $PKGS; \
    apt-get purge -y unattended-upgrades 2>/dev/null || true; \
    rm -rf /var/cache/apt/archives/*.deb; \
    mkdir -p /var/lib/prohori/actions /etc/nginx/prohori; \
    dpkg -l 'php8.3-*' | awk '/^ii/{print $2, $3}'

# Show the version banner (the "naive scanner" view) and allow uploads.
RUN set -eux; for ini in /etc/php/8.3/*/php.ini; do \
      sed -i -E 's/^;?\s*expose_php\s*=.*/expose_php = On/' "$ini"; \
    done

COPY site/ /opt/prohori-site/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN set -eux; chmod +x /usr/local/bin/entrypoint.sh; \
    if [ "$ROLE" = "web" ]; then \
      mkdir -p /var/www/bank; cp /opt/prohori-site/*.php /var/www/bank/; \
      mkdir -p /var/www/bank/uploads; chown www-data:www-data /var/www/bank/uploads; \
      cp /opt/prohori-site/nginx-bank.conf /etc/nginx/sites-available/bank; \
      rm -f /etc/nginx/sites-enabled/default; ln -s /etc/nginx/sites-available/bank /etc/nginx/sites-enabled/bank; \
      nginx -t; \
    else \
      mkdir -p /opt/batch; cp /opt/prohori-site/batch/reconcile.php /opt/batch/; \
    fi; \
    echo "$ROLE" > /etc/prohori-role

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
