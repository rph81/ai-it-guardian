#!/bin/sh
# Gets or renews the console's Let's Encrypt certificate through acme-dns (DNS-01 challenge).
# One-time DNS setup: CNAME _acme-challenge.<host> -> the "fulldomain" in console/acme/acme-dns.json
set -e
HOST="${GUARDIAN_HOSTNAME:-guardian.hadife.com}"
DIR=/opt/ai-guardian/console/acme
export ACME_DNS_API_BASE=https://auth.acme-dns.io ACME_DNS_STORAGE_PATH="$DIR/acme-dns.json"
if [ -f "$DIR/certificates/$HOST.crt" ]; then
  lego --accept-tos --email "${ACME_EMAIL:-}" --dns acme-dns --domains "$HOST" --path "$DIR" renew --days 30 \
       --renew-hook "systemctl restart ai-guardian-console"
else
  lego --accept-tos --email "${ACME_EMAIL:-}" --dns acme-dns --domains "$HOST" --path "$DIR" run
  systemctl restart ai-guardian-console
fi
chmod -R go-rwx "$DIR"
