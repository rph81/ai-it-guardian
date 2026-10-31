#!/bin/sh
# Installs the Guardian site collector as a Linux app (Debian / Ubuntu). Run as root from the repository's collector/ folder.
set -eu
DEST=/opt/guardian-collector
id guardian-collector >/dev/null 2>&1 || useradd --system --home-dir /var/lib/guardian-collector --shell /usr/sbin/nologin guardian-collector
apt-get install -y -q python3 python3-venv nmap openssh-client >/dev/null
install -d -m 755 "$DEST" "$DEST/guardian"
install -m 644 guardian_collector.py launch.py "$DEST/"
for f in __init__ jobs access connectors codescan release; do install -m 644 "../guardian/$f.py" "$DEST/guardian/$f.py"; done
[ -x "$DEST/venv/bin/python" ] || python3 -m venv "$DEST/venv"
"$DEST/venv/bin/pip" install -q "cryptography>=42" "ldap3>=2.9" "pywinrm>=0.4.3"
install -d -m 700 -o guardian-collector -g guardian-collector /var/lib/guardian-collector
install -m 644 guardian-collector.service guardian-collector-page.service /etc/systemd/system/
cat > /usr/local/bin/guardian-collector <<'W'
#!/bin/sh
export GUARDIAN_COLLECTOR_DATA=/var/lib/guardian-collector
if [ "$(id -u)" = 0 ]; then exec runuser -u guardian-collector -- /opt/guardian-collector/venv/bin/python /opt/guardian-collector/launch.py "$@"; fi
exec /opt/guardian-collector/venv/bin/python /opt/guardian-collector/launch.py "$@"
W
chmod 755 /usr/local/bin/guardian-collector
systemctl daemon-reload
echo "Installed. Next: sudo guardian-collector enroll <server> <code> --pin <pin> --scope <subnets>; sudo systemctl enable --now guardian-collector"
echo "Optional status page: sudo guardian-collector page-password; sudo systemctl enable --now guardian-collector-page"
