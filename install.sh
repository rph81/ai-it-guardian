#!/bin/sh
# Installs or updates AI IT Guardian in /opt/ai-guardian on Debian 13. Run as root from the folder that holds this file.
#
#   ./install.sh --hostname guardian.example.com --email you@example.com
#
# --hostname  the name you'll open the console at (passkeys need a real name; it doesn't have to be public)
# --email     the e-mail Let's Encrypt sends expiry warnings to
# Running it again updates the code and keeps your settings, vault, runs and certificate.
set -e
HOST= EMAIL=
while [ $# -gt 0 ]; do
  case "$1" in
    --hostname) HOST="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "Run as root." >&2; exit 1; }
SRC=$(cd "$(dirname "$0")" && pwd)
DEST=/opt/ai-guardian
CONF=/etc/default/ai-guardian

echo "==> Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nmap arp-scan miniupnpc openssl python3 python3-venv ca-certificates curl lego >/dev/null

echo "==> Copying Guardian to $DEST"
mkdir -p "$DEST"
cp -r "$SRC/guardian" "$DEST/"
cp "$SRC/run.py" "$SRC/console.py" "$SRC/gateway.py" "$SRC/requirements.txt" "$SRC/.env.example" \
   "$SRC/acme-dns-hook.py" "$SRC/guardian-cert.sh" "$SRC/guardian-cert-setup.sh" "$DEST/"
chmod 755 "$DEST/run.py" "$DEST/acme-dns-hook.py" "$DEST/guardian-cert.sh" "$DEST/guardian-cert-setup.sh"
find "$DEST/guardian" -name __pycache__ -prune -exec rm -rf {} +

echo "==> Python environment"
[ -x "$DEST/venv/bin/python" ] || python3 -m venv "$DEST/venv"
"$DEST/venv/bin/pip" install -q --upgrade pip
"$DEST/venv/bin/pip" install -q -r "$DEST/requirements.txt"
[ -f "$DEST/.env" ] || cp "$DEST/.env.example" "$DEST/.env"
chmod 600 "$DEST/.env"

echo "==> Settings in $CONF"
touch "$CONF"; chmod 644 "$CONF"
set_conf() { grep -q "^$1=" "$CONF" && sed -i "s|^$1=.*|$1=$2|" "$CONF" || echo "$1=$2" >> "$CONF"; }
[ -n "$HOST" ] && set_conf GUARDIAN_HOSTNAME "$HOST"
[ -n "$EMAIL" ] && set_conf ACME_EMAIL "$EMAIL"
grep -q "^GUARDIAN_HOSTNAME=" "$CONF" || echo "Note: no --hostname given yet; the console uses a self-signed certificate until you set one." >&2

echo "==> Collector gateway user and data"
id guardian-gw >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin guardian-gw
install -d -m 700 -o guardian-gw -g guardian-gw "$DEST/gateway"
[ -f "$DEST/gateway/gateway.db" ] && chown guardian-gw:guardian-gw "$DEST/gateway"/gateway.db*

echo "==> Services"
cp "$SRC/ai-guardian-gateway.service" "$SRC/ai-guardian-console.service" "$SRC/guardian-cert.service" "$SRC/guardian-cert.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable -q ai-guardian-console
systemctl restart ai-guardian-console
systemctl enable -q ai-guardian-gateway
systemctl restart ai-guardian-gateway
[ -f "$DEST/console/acme/acme-dns.json" ] && systemctl enable -q --now guardian-cert.timer

sleep 3
IP=$(hostname -I | awk '{print $1}')
echo
echo "Installed. Console service: $(systemctl is-active ai-guardian-console) · collector gateway: $(systemctl is-active ai-guardian-gateway) (port 8444)"
if [ -f "$DEST/console/setup-code" ]; then
  echo "First-time setup code: $(cat "$DEST/console/setup-code")"
fi
if [ -f "$DEST/console/acme/acme-dns.json" ]; then
  echo "Open: https://$(sed -n 's/^GUARDIAN_HOSTNAME=//p' "$CONF"):8443"
else
  echo "Next: get a trusted certificate with  $DEST/guardian-cert-setup.sh   (see INSTALL.md, step 6)"
  echo "Until then the console answers at https://$IP:8443 with a self-signed certificate."
fi
