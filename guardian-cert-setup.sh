#!/bin/sh
# One-time setup of the console's Let's Encrypt certificate (DNS-01 validation through acme-dns.io).
# 1st run: registers an acme-dns account and prints the two DNS records to create at your DNS provider.
# 2nd run (after creating them): checks the records, gets the certificate and turns on daily renewal.
set -e
. /etc/default/ai-guardian 2>/dev/null || true
HOST="${GUARDIAN_HOSTNAME:?Set the hostname first: ./install.sh --hostname guardian.example.com --email you@example.com}"
: "${ACME_EMAIL:?Set the e-mail first: ./install.sh --hostname $HOST --email you@example.com}"
DIR=/opt/ai-guardian/console/acme
STORE="$DIR/acme-dns.json"
mkdir -p "$DIR"; chmod 700 /opt/ai-guardian/console "$DIR"
IP=$(hostname -I | awk '{print $1}')

if [ ! -f "$STORE" ]; then
  echo "Registering an acme-dns account (free, used only to answer Let's Encrypt's DNS check)..."
  curl -fsS -X POST https://auth.acme-dns.io/register | HOST="$HOST" python3 -c '
import json, os, sys
a = json.load(sys.stdin)
a["server_url"] = "https://auth.acme-dns.io"
json.dump({os.environ["HOST"]: a}, open(sys.argv[1], "w"), indent=1)' "$STORE"
  chmod 600 "$STORE"
fi
TARGET=$(python3 -c 'import json,sys; print(next(iter(json.load(open(sys.argv[1])).values()))["fulldomain"])' "$STORE")
ZONE=${HOST#*.}; LABEL=${HOST%%.*}

cname_now=$(/opt/ai-guardian/venv/bin/python -c '
import sys, dns.resolver
r = dns.resolver.Resolver(); r.nameservers = ["1.1.1.1"]
try: print(r.resolve("_acme-challenge." + sys.argv[1], "CNAME")[0].target.to_text().rstrip("."))
except Exception: print("")' "$HOST")
a_now=$(/opt/ai-guardian/venv/bin/python -c '
import sys, dns.resolver
r = dns.resolver.Resolver(); r.nameservers = ["1.1.1.1"]
try: print(r.resolve(sys.argv[1], "A")[0].to_text())
except Exception: print("")' "$HOST")

if [ "$cname_now" != "$TARGET" ]; then
  cat <<MSG

Create these two records in the DNS of $ZONE (at your DNS provider, e.g. GoDaddy → My Products → DNS):

  Type   Name                        Value                                        TTL
  CNAME  _acme-challenge.$LABEL      $TARGET   1 hour
  A      $LABEL                      $IP                                    1 hour

The A record points the name at this container's address on your network. It is a private address, so
nobody on the internet can reach the console through it; it only saves your devices from needing a hosts entry.
The CNAME lets Let's Encrypt check that you own the name, without opening anything to the internet.

Then run this script again. (DNS changes can take a few minutes to appear.)
Currently seen: CNAME=${cname_now:-none}  A=${a_now:-none}
MSG
  exit 0
fi
[ "$a_now" = "$IP" ] || echo "Warning: $HOST resolves to ${a_now:-nothing}, not $IP. The certificate will work, but browsers need the name to reach $IP."
echo "DNS records found. Requesting the certificate (this takes up to 3 minutes)..."
GUARDIAN_HOSTNAME="$HOST" ACME_EMAIL="$ACME_EMAIL" /opt/ai-guardian/guardian-cert.sh
systemctl enable -q --now guardian-cert.timer
echo "Done. Open https://$HOST:8443 (renewal is checked daily)."
