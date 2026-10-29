#!/bin/sh
# Gets or renews the console's Let's Encrypt certificate (DNS-01 through acme-dns).
# One-time DNS setup: CNAME _acme-challenge.<host> -> the "fulldomain" in console/acme/acme-dns.json
# Debian's lego leaves out its acme-dns provider, so acme-dns-hook.py does that part through lego's "exec" provider.
set -e
HOST="${GUARDIAN_HOSTNAME:?set GUARDIAN_HOSTNAME in /etc/default/ai-guardian}"
DIR=/opt/ai-guardian/console/acme
export EXEC_PATH=/opt/ai-guardian/acme-dns-hook.py EXEC_PROPAGATION_TIMEOUT=180 ACME_DNS_STORAGE_PATH="$DIR/acme-dns.json"
LEGO="lego --accept-tos --email ${ACME_EMAIL:?set ACME_EMAIL} --dns exec --dns.resolvers 1.1.1.1:53 --domains $HOST --path $DIR"
if [ -f "$DIR/certificates/$HOST.crt" ]; then
  $LEGO renew --days 30 --renew-hook "systemctl restart ai-guardian-console"
else
  $LEGO run
  systemctl restart ai-guardian-console
fi
chmod -R go-rwx "$DIR"
