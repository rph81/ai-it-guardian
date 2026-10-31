#!/bin/sh
# Builds guardian-collector_<version>_all.deb from the repository (run on Debian/Ubuntu with dpkg-deb). Output in collector/dist/.
set -eu
cd "$(dirname "$0")/../.."
V=$(sed -n 's/^VERSION = "\(.*\)"/\1/p' collector/guardian_collector.py)
R=$(mktemp -d); P="$R/guardian-collector_${V}_all"
install -d "$P/DEBIAN" "$P/opt/guardian-collector/guardian" "$P/lib/systemd/system" "$P/usr/local/bin"
install -m 644 collector/guardian_collector.py collector/launch.py "$P/opt/guardian-collector/"
for f in __init__ jobs access connectors codescan release; do install -m 644 "guardian/$f.py" "$P/opt/guardian-collector/guardian/"; done
install -m 644 collector/guardian-collector.service collector/guardian-collector-page.service "$P/lib/systemd/system/"
sed -n '/^cat > \/usr\/local\/bin\/guardian-collector/,/^W$/p' collector/install.sh | sed '1d;$d' > "$P/usr/local/bin/guardian-collector"
chmod 755 "$P/usr/local/bin/guardian-collector"
cat > "$P/DEBIAN/control" <<C
Package: guardian-collector
Version: $V
Architecture: all
Maintainer: AI IT Guardian
Depends: python3 (>= 3.11), python3-venv, nmap, openssh-client
Description: Guardian site collector
 Connects out to the Guardian collector gateway and runs signed, read-only assessment jobs inside the customer's scope.
C
cat > "$P/DEBIAN/postinst" <<'C'
#!/bin/sh
set -e
id guardian-collector >/dev/null 2>&1 || useradd --system --home-dir /var/lib/guardian-collector --shell /usr/sbin/nologin guardian-collector
install -d -m 700 -o guardian-collector -g guardian-collector /var/lib/guardian-collector
[ -x /opt/guardian-collector/venv/bin/python ] || python3 -m venv /opt/guardian-collector/venv
/opt/guardian-collector/venv/bin/pip install -q "cryptography>=42" "ldap3>=2.9" "pywinrm>=0.4.3"
systemctl daemon-reload || true
echo "Next: sudo guardian-collector enroll <server> <code> --pin <pin> --scope <subnets>; sudo systemctl enable --now guardian-collector"
C
chmod 755 "$P/DEBIAN/postinst"
mkdir -p collector/dist
dpkg-deb --root-owner-group --build "$P" "collector/dist/guardian-collector_${V}_all.deb"
rm -rf "$R"
echo "collector/dist/guardian-collector_${V}_all.deb"
