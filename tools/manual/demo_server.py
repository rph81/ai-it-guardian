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
