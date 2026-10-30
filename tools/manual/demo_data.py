"""Sample run for the manual: a fictional small office. Nothing here is real."""
import json, os, sys, time
ROOT, RUNS = sys.argv[1], sys.argv[2]
sys.path.insert(0, ROOT)
from guardian.graph import Graph
from guardian import report
run = "20261030-091500"; d = os.path.join(RUNS, run); os.makedirs(d, exist_ok=True)
g = Graph(d); g.data["started"] = "2026-10-30T09:15:00"
g.data["site"] = {"network": "192.168.50.0/24", "gateway": "192.168.50.1", "collector_ip": "192.168.50.10", "name": "Demo office"}
A = [("192.168.50.1", "router", "Ubiquiti", "UniFi Dream Machine", "UniFi OS 4.0.6", [(22, "ssh"), (443, "https")], "high"),
     ("192.168.50.5", "nas", "Synology", "DS920+", "DSM 7.1.1", [(5000, "http"), (5001, "https"), (445, "microsoft-ds")], "high"),
     ("192.168.50.6", "hypervisor", "Proxmox", "Proxmox VE", "Proxmox VE 8.2", [(22, "ssh"), (8006, "https")], "high"),
     ("192.168.50.20", "server", "Microsoft", "Windows Server 2019", "Windows Server 2019", [(445, "microsoft-ds"), (3389, "ms-wbt-server")], "high"),
     ("192.168.50.21", "server", "Debian", "Web server", "Debian 12", [(22, "ssh"), (80, "http"), (443, "https")], "medium"),
     ("192.168.50.30", "printer", "HP", "LaserJet M404", "002.2149A", [(80, "http"), (161, "snmp"), (9100, "jetdirect")], "low"),
     ("192.168.50.40", "camera", "Hikvision", "DS-2CD2143", "V5.5.0", [(80, "http"), (554, "rtsp")], "medium"),
     ("192.168.50.41", "camera", "Hikvision", "DS-2CD2143", "V5.5.0", [(80, "http"), (554, "rtsp")], "medium"),
     ("192.168.50.60", "workstation", "Dell", "OptiPlex 7090", "Windows 11 23H2", [(135, "msrpc"), (445, "microsoft-ds")], "low"),
     ("192.168.50.61", "workstation", "Lenovo", "ThinkPad T14", "Windows 10 22H2", [(135, "msrpc"), (445, "microsoft-ds")], "low"),
     ("192.168.50.70", "iot", "Philips", "Hue Bridge", "1.65", [(80, "http"), (443, "https")], "low"),
     ("192.168.50.80", "access point", "Ubiquiti", "U6-Lite", "6.6.55", [(22, "ssh")], "medium")]
for ip, typ, vendor, model, os_, ports, crit in A:
    g.merge_asset(ip, "scan", device_type=typ, vendor=vendor, model=model, os=os_, hostname=f"{typ.replace(' ', '-')}-{ip.split('.')[-1]}", mac_vendor=vendor, criticality=crit)
    g.set_ports(ip, [{"proto": "tcp", "port": p, "state": "open", "service": s} for p, s in ports])
g.data["wan"] = {"public_ip": "203.0.113.24", "internetdb": {"ports": [443, 5001], "vulns": [], "hostnames": ["office.example.net"]},
                 "upnp_port_mappings": ["0 TCP 5001->192.168.50.5:5001 'Synology QuickConnect'"]}
F = [("RDP open on the internet-facing Windows server without NLA", "critical", "192.168.50.20", "patch", 1, True, 0.94),
     ("NAS admin page reachable from the internet (UPnP forward 5001)", "high", "wan", "wan", 1, False, 0.12),
     ("Windows Server 2019 missing security updates for 84 days", "high", "192.168.50.20", "patch", 1, True, 0.61),
     ("SMBv1 enabled on the file server", "high", "192.168.50.20", "patch", 2, False, 0.07),
     ("2 of 4 Global Administrators without MFA", "high", "site", "m365", 2, False, None),
     ("Legacy authentication still allowed", "medium", "site", "m365", 2, False, None),
     ("Camera firmware with known authentication bypass", "high", "192.168.50.40", "firmware", 2, True, 0.97),
     ("Default SNMP community 'public' on the printer", "medium", "192.168.50.30", "network", 3, False, None),
     ("12 package updates pending on the web server", "medium", "192.168.50.21", "patch", 3, False, 0.03),
     ("Windows 10 22H2 workstation past end of support", "medium", "192.168.50.61", "os", 3, False, None),
     ("DSM version behind latest release", "medium", "192.168.50.5", "patch", 3, False, None),
     ("Self-signed certificate on the Proxmox admin page", "low", "192.168.50.6", "web", 4, False, None),
     ("Old Dropbear SSH on the access point", "low", "192.168.50.80", "network", 4, False, None),
     ("SPF present, DMARC policy set to none", "low", "site", "wan", 4, False, None)]
for title, sev, asset, layer, prio, kev, epss in F:
    g.add_finding({"title": title, "severity": sev, "asset": asset, "layer": layer, "status": "open", "first_seen": "2026-10-30",
                   "evidence": "Observed by the agent (sample data).", "recommendation": "See the fix in the report (sample data)."})
    g.data["findings"][-1]["risk"] = {k: v for k, v in {"priority": prio, "reason": ("Actively exploited (CISA KEV). " if kev else "") + ("Business-critical device." if prio <= 2 else "Limited exposure; fix in the normal cycle."),
        "exposure": "internet" if prio == 1 else "internal", "kev": kev or None, "epss": epss, "due_days": {1: 7, 2: 30, 3: 90, 4: 180}[prio], "by": "risk"}.items() if v is not None}
g.data["attack_paths"] = [{"id": "AP01", "title": "From the internet to the file server", "target": "File server data", "likelihood": "high",
    "steps": [{"text": "Brute force on RDP without NLA", "finding": "F001"}, {"text": "Missing patches allow privilege escalation", "finding": "F003"}, {"text": "SMBv1 reaches the NAS", "finding": "F004"}],
    "choke_points": [{"text": "Put RDP behind a VPN and require NLA", "finding": "F001"}], "summary": "One exposed service plus missing patches give an attacker the file server."}]
g.data["compliance"] = {"cis_ig1": {"1.1": {"status": "met", "findings": [], "note": "12 devices identified."}, "4.4": {"status": "partial", "findings": ["F004"], "note": "SMBv1 open."},
                        "6.5": {"status": "gap", "findings": ["F005"], "note": "2 admins without MFA."}, "7.3": {"status": "gap", "findings": ["F003", "F009"], "note": "Patching stalled."}},
                        "iso27001": {"8.8": {"status": "gap", "findings": ["F001", "F003", "F007"], "note": "Known exploited vulnerabilities open."}, "8.5": {"status": "gap", "findings": ["F005"], "note": "MFA not enforced."}}}
for name, cost in [("orchestrator", .21), ("discovery", .32), ("network", .58), ("os", .49), ("web", .37), ("firmware", .41), ("wan", .29), ("m365", .44), ("patch", .62), ("risk", .36), ("paths", .27), ("compliance", .39), ("report", .15)]:
    g.agent(name, status="done", activity="Finished", rounds=6, cost=cost, checks={"probe": 4})
g.data["cost_total"] = 4.9
g.data["summary"] = {"score": 58, "grade": "C", "headline": "Two internet-facing weaknesses and stalled patching put the file server at risk",
    "executive_summary": "RDP on the file server is reachable from the internet without Network Level Authentication and the server is 84 days behind on updates, one of them actively exploited. Fixing three items this week removes most of the risk.",
    "top_actions": [{"action": "Put RDP behind a VPN and turn on NLA", "why": "Closes the internet entry point", "effort": "hours", "finding_ids": ["F001"]},
                    {"action": "Install the latest Windows Server update", "why": "Removes an actively exploited flaw", "effort": "hours", "finding_ids": ["F003"]},
                    {"action": "Remove the UPnP forward to the NAS", "why": "NAS login no longer on the internet", "effort": "minutes", "finding_ids": ["F002"]}],
    "layer_scores": [{"layer": "network", "score": 62, "summary": "Flat network"}, {"layer": "patch", "score": 41, "summary": "Patching stalled"}]}
t0 = time.time() - 1800
with open(os.path.join(d, "events.jsonl"), "w") as fh:
    for i, (k, a, b, t) in enumerate([("start", "orchestrator", "orchestrator", "started"), ("order", "orchestrator", "network", "Network: 12 devices"),
                                      ("find", "patch", "orchestrator", "RDP open without NLA (critical)"), ("note", "network", "firmware", "Cameras on V5.5.0: check CVE-2021-36260"),
                                      ("done", "risk", "orchestrator", "14 findings ranked")]):
        fh.write(json.dumps({"n": i + 1, "t": t0 + i * 120, "kind": k, "from": a, "to": b, "text": t, "total": 1 + i * .8}) + "\n")
g.save(); report.render(g, os.path.join(d, "report.html"))
d2 = os.path.join(RUNS, "20261023-091500"); os.makedirs(d2, exist_ok=True)
g2 = Graph(d2); g2.data.update({k: g.data[k] for k in ("site", "assets", "wan")}); g2.data["started"] = "2026-10-23T09:15:00"; g2.save()
print("demo run", run)
