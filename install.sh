#!/bin/sh
# Installs AI IT Guardian into /opt/ai-guardian on a Debian 13 host/container. Run as root.
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nmap arp-scan miniupnpc openssl python3 python3-venv ca-certificates
mkdir -p /opt/ai-guardian
cp -r guardian run.py requirements.txt .env.example /opt/ai-guardian/
cd /opt/ai-guardian
python3 -m venv venv
./venv/bin/pip install -q -r requirements.txt
[ -f .env ] || { cp .env.example .env; chmod 600 .env; }
echo "Installed. Put your API key in /opt/ai-guardian/.env, then:"
echo "  /opt/ai-guardian/venv/bin/python /opt/ai-guardian/run.py"
