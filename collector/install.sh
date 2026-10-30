#!/bin/sh
# Installs the Guardian site collector as a Linux app (Debian / Ubuntu). Run as root from this folder.
set -eu
DEST=/opt/guardian-collector
id guardian-collector >/dev/null 2>&1 || useradd --system --home-dir /var/lib/guardian-collector --shell /usr/sbin/nologin guardian-collector
apt-get install -y -q python3 python3-venv >/dev/null
install -d -m 755 "$DEST"
install -m 644 guardian_collector.py "$DEST/guardian_collector.py"
[ -x "$DEST/venv/bin/python" ] || python3 -m venv "$DEST/venv"
"$DEST/venv/bin/pip" install -q "cryptography>=42"
install -d -m 700 -o guardian-collector -g guardian-collector /var/lib/guardian-collector
install -m 644 guardian-collector.service /etc/systemd/system/guardian-collector.service
cat > /usr/local/bin/guardian-collector <<'W'
#!/bin/sh
export GUARDIAN_COLLECTOR_DATA=/var/lib/guardian-collector
exec /opt/guardian-collector/venv/bin/python /opt/guardian-collector/guardian_collector.py "$@"
W
chmod 755 /usr/local/bin/guardian-collector
systemctl daemon-reload
echo "Installed. Next: sudo guardian-collector enroll <server> <code> --pin <pin> --scope <subnets>; sudo systemctl enable --now guardian-collector"
