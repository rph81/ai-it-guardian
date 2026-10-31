"""Local demo console for screenshots: signed in as a demo admin, vault unlocked, fictional data only."""
import os, pathlib, sys, time, types
ROOT, DEMO = sys.argv[1], pathlib.Path(sys.argv[2])
sys.path.insert(0, ROOT)
sys.modules["guardian.comppdf"] = types.ModuleType("guardian.comppdf")      # PDF export isn't needed for screenshots
os.environ["GUARDIAN_HOSTNAME"] = "localhost"; os.environ["GUARDIAN_GATEWAY_DATA"] = str(DEMO / "gateway")
import console
from guardian.vault import Vault, new_keypair
(DEMO / "state").mkdir(parents=True, exist_ok=True)
console.STATE = DEMO / "state"; console.RUNS = DEMO / "runs"; console.EVIDENCE_DIR = console.STATE / "evidence"; console.JOB_KEY = console.STATE / "job.key"
v = Vault(console.STATE / "guardian.db"); console.vault = v
priv, pub = new_keypair(); uid = v.create_user("admin@demo.example", "Demo Admin", "admin")
v.update_user(uid, public_key=pub, status="active"); v.initialize(uid, priv); v.unlock_with_private_key(uid, priv, "demo", "Demo Admin")
console.sessions["demo"] = {"uid": uid, "stage": "active", "created": time.time(), "last": time.time(), "fresh_at": time.time()}
console.current = lambda request, stage="active": ("demo", console.sessions["demo"])
st = console.sites_db(); sid = st.add_site("Zürich office", "Muster AG"); st.create_code(sid, "admin@demo.example")
ev = console.evidence_store(); pdf = b"%PDF-1.4\n% sample\n"
ev.add("Security-awareness-training-2026.pdf", pdf, "Demo Admin", ["iso27001:6.3", "cis_ig1:14.1"], "2026-12-31")
ev.add("Backup-restore-test-Q3.pdf", pdf, "Demo Admin", ["iso27001:8.13", "cis_ig1:11.1"], "2026-11-15")
ev.set_override("iso27001", "5.1", "met", "Information security policy v3 approved by management, March 2026.", "Demo Admin")
v.put("anthropic_key_expires", "2027-10-31")
v.put("ticketing", {"system": "jira", "on": True, "auto": True, "threshold": "p2", "resolve_on_verify": True,
                    "settings": {"jira": {"site": "https://demo-office.atlassian.net", "email": "it@demo.example", "project_key": "IT", "issuetype": "Task"}}})
v.put("ticketing_secrets", {"jira": "demo"})
# a second customer, with an assessment built from an imported scanner report, its own ticketing and a limited user
bsid = st.add_site("Head office", "Beispiel GmbH")
v.put("site_settings", {sid: {"scope": "10.20.0.0/22, 10.20.8.0/24", "ticketing": {"mode": "msp", "map": {"project_key": "MUST"}, "threshold": "p1", "resolve": ""}},
                        bsid: {"scope": "10.30.0.0/24", "ticketing": {"mode": "own", "map": {}, "threshold": "", "resolve": "yes",
                               "own": {"system": "servicenow", "on": True, "settings": {"servicenow": {"instance": "https://beispiel-demo.service-now.com", "username": "guardian-api"}}}}}})
v.put("site_ticket_secrets", {bsid: {"system": "servicenow", "secret": "demo"}})
ss = v.get("site_settings")
ss[sid]["vdp"] = {"on": True, "token": "DemoDisclosureLink-0000000000", "contact": "security@muster.example", "policy": ""}
v.put("site_settings", ss)
v.put("vdp_reports", {sid: [{"id": "a1b2c3d4e5f6", "t": time.time() - 7200, "title": "Customer portal shows other customers' invoices",
      "description": "Changing the number in /invoices/1043 to /invoices/1042 shows another company's invoice while signed in as a normal customer.",
      "affected": "https://portal.muster.example/invoices/1043", "contact": "researcher@mail.example", "status": "new"}]})
from guardian import decoys as dmod
dk = dmod.new("login", "passwords.txt on the IT share", sid, "admin@demo.example")
dk["hits"] = [{"t": time.time() - 3600, "ip": "10.20.1.57", "ua": "Mozilla/5.0 (Windows NT 10.0)", "what": "sign-in with the planted password", "severity": "high", "detail": "user 'svc_backup'"},
              {"t": time.time() - 3700, "ip": "10.20.1.57", "ua": "Mozilla/5.0 (Windows NT 10.0)", "what": "fake admin portal visited", "severity": "medium", "detail": ""}]
v.put("decoys", [dk, dmod.new("docx", "Backup folder on the NAS", sid, "admin@demo.example")])
v.put("siem", {"only_new": True, "sentinel": {"on": True, "tenant_id": "00000000-0000-0000-0000-000000000000", "client_id": "11111111-1111-1111-1111-111111111111",
      "endpoint": "https://guardian-dce.westeurope-1.ingest.monitor.azure.com", "dcr_id": "dcr-0123456789abcdef", "stream": "Custom-GuardianFindings"},
      "splunk": {"on": False, "url": "", "index": ""}, "syslog": {"on": False, "host": "", "port": 6514, "proto": "tls"}})
v.put("siem_secrets", {"sentinel": "demo"})
import hashlib as _h
v.put("mcp_tokens", [{"id": "ab12cd34", "name": "Claude Desktop (IT team)", "hash": _h.sha256(b"demo").hexdigest(), "created": time.time() - 86400,
      "last_used": time.time() - 600, "sites": None, "by": "admin@demo.example"}])
import json as _j
console.WEBSCAN_DIR = console.STATE / "webscans"; console.WEBSCAN_DIR.mkdir(parents=True, exist_ok=True)
(console.STATE / "webscans" / "20261031-101500-ab12.json").write_text(_j.dumps({"id": "20261031-101500-ab12", "target": "https://portal.muster.example/",
    "site": sid, "by": "Demo Admin", "started": time.time() - 5000, "status": "done", "signed_in": True, "auth_header": "Cookie", "pages": 87, "requests": 131,
    "counts": {"high": 2, "medium": 2, "low": 1}, "findings": [
      {"title": "Pages for signed-in users also load without signing in", "severity": "high", "urls": ["https://portal.muster.example/invoices/export"], "evidence": "The same page came back without the test account's sign-in.", "recommendation": "Check access control on the server for every page and API, not only in the menu.", "count": 1},
      {"title": "Any website can read signed-in users' data (CORS)", "severity": "high", "urls": ["https://portal.muster.example/"], "evidence": "Origin https://guardian-cors-check.invalid is reflected with Access-Control-Allow-Credentials: true.", "recommendation": "Allow only your own origins in CORS.", "count": 1},
      {"title": "Missing security header: Content-Security-Policy", "severity": "medium", "urls": ["https://portal.muster.example/"], "evidence": "No Content-Security-Policy header on HTML responses.", "recommendation": "Add a Content-Security-Policy that limits scripts to your own origin.", "count": 87},
      {"title": "Cookie session without SameSite", "severity": "medium", "urls": ["https://portal.muster.example/"], "evidence": "Set-Cookie: session=… lacks SameSite.", "recommendation": "Set SameSite=Lax.", "count": 1},
      {"title": "Server software version disclosed", "severity": "low", "urls": ["https://portal.muster.example/"], "evidence": "server: nginx/1.18.0", "recommendation": "Hide version numbers.", "count": 87}]}))
(console.STATE / "webscans" / "20261031-093000-cd56.json").write_text(_j.dumps({"id": "20261031-093000-cd56", "kind": "image", "target": "registry-1.docker.io/library/node:16",
    "site": sid, "by": "Demo Admin", "started": time.time() - 9000, "status": "done", "signed_in": False, "os": "Debian GNU/Linux 11 (bullseye)", "packages": 412, "layers": 7, "mb": 331.2,
    "counts": {"high": 2, "medium": 1}, "findings": [
      {"title": "openssl 1.1.1n-0+deb11u5 has 9 known vulnerabilities", "severity": "high", "urls": [], "evidence": "Debian:11 package libssl1.1: CVE-2023-0286, CVE-2023-0464, …", "recommendation": "Rebuild on an updated base image.", "count": 1},
      {"title": "Image is more than a year old", "severity": "low", "urls": [], "evidence": "Built 2023-09-08", "recommendation": "Rebuild regularly.", "count": 1},
      {"title": "Container runs as root", "severity": "medium", "urls": [], "evidence": "Image config User: (not set)", "recommendation": "Use a non-root USER.", "count": 1}]}))
tech = v.create_user("tech@demo.example", "Demo Technician", "operator"); v.update_user(tech, status="active")
v.put("user_sites", {tech: [sid, bsid]})
from guardian import importers
from guardian.graph import Graph
rd = console.RUNS / "20261029-140000"
if not rd.exists():
    rd.mkdir(); (rd / "site").write_text(bsid)
    g = Graph(str(rd)); g.data["started"] = "2026-10-29T14:00:00"; g.data["site"] = {"name": "Beispiel GmbH · Head office", "id": bsid, "network": "10.30.0.0/24"}
    csv = (b"ip,title,severity,cve,description,solution\n"
           b"10.30.0.5,Remote Desktop exposed to the internet without NLA,critical,,RDP on 3389 reachable from the internet,Require NLA and put RDP behind the VPN\n"
           b"10.30.0.9,SMBv1 enabled on the file server,high,CVE-2017-0144,SMBv1 negotiated,Disable SMBv1\n"
           b"10.30.0.12,Telnet enabled on the core switch,high,,Telnet on port 23,Use SSH and disable Telnet\n"
           b"10.30.0.20,TLS certificate expired on the intranet,medium,,Expired 2026-09-01,Renew the certificate\n")
    fmt, rows = importers.parse("demo.csv", csv)
    console._merge_import(g, rows, fmt)
    g.data["imports"] = [{"t": time.time(), "by": "Demo Admin", "file": "beispiel-nessus-export.csv", "format": "CSV", "added": len(rows), "merged": 0}]
    g.save()
import uvicorn
uvicorn.run(console.app, host="127.0.0.1", port=8765, log_level="warning")
