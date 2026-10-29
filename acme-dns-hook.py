#!/usr/bin/env python3
"""lego 'exec' DNS hook for acme-dns: lego calls  <script> present|cleanup <fqdn> <value>."""
import json, os, sys, urllib.request
action, fqdn, value = sys.argv[1], sys.argv[2], sys.argv[3]
if action != "present":
    sys.exit(0)                      # acme-dns keeps the last two TXT values; nothing to clean up
name = fqdn.rstrip(".").removeprefix("_acme-challenge.")
accounts = json.load(open(os.environ.get("ACME_DNS_STORAGE_PATH", "/opt/ai-guardian/console/acme/acme-dns.json")))
# lego passes either the domain or, after following the CNAME, the acme-dns name itself
acct = accounts.get(name) or next(a for a in accounts.values() if a["fulldomain"].rstrip(".") == name)
req = urllib.request.Request(acct.get("server_url", "https://auth.acme-dns.io") + "/update", method="POST",
                             data=json.dumps({"subdomain": acct["subdomain"], "txt": value}).encode(),
                             headers={"X-Api-User": acct["username"], "X-Api-Key": acct["password"], "Content-Type": "application/json"})
with urllib.request.urlopen(req, timeout=20) as r:
    print("acme-dns updated", r.status)
