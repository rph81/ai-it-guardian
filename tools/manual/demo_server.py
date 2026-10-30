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
import uvicorn
uvicorn.run(console.app, host="127.0.0.1", port=8765, log_level="warning")
