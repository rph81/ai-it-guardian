#!/bin/sh
# First sign-in on the appliance console: asks for Guardian's server, code, pin and subnets, enrolls, starts the service.
set -eu
echo "Guardian site collector: enrollment (values from the Install dialog in Guardian)"
printf "Server (https://host:port): "; read -r URL
printf "One-time code: "; read -r CODE
printf "Pin (sha256:...): "; read -r PIN
printf "Customer subnets (e.g. 10.20.0.0/22,10.20.8.0/24): "; read -r SCOPE
guardian-collector enroll "$URL" "$CODE" --pin "$PIN" --scope "$SCOPE"
systemctl enable --now guardian-collector
printf "Enable the status page on this network? [y/N] "; read -r P
if [ "$P" = y ]; then guardian-collector page-password && systemctl enable --now guardian-collector-page; fi
guardian-collector status
