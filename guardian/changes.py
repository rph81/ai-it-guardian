"""What changed since the previous run: devices, open ports, internet exposure and findings.

Scan changes compare this run's scan with the previous scan of the site (any run). Finding changes compare with the
previous AI assessment, using the links the Risk analyst made (link_previous); they are only exact once it has run.
"""
import json
import os

from .graph import is_open


def _runs_before(run_dir):
    here = os.path.basename(os.path.normpath(run_dir))
    parent = os.path.dirname(os.path.normpath(run_dir))
    for name in sorted(os.listdir(parent), reverse=True):
        path = os.path.join(parent, name, "graph.json")
        if name < here and os.path.exists(path):
            try:
                with open(path) as f:
                    yield name, json.load(f)
            except (OSError, ValueError):
                continue


def _label(ip, a):
    name = a.get("hostname") or " ".join(x for x in (a.get("vendor"), a.get("model")) if x) or a.get("mac_vendor")
    return f"{ip} ({name})" if name else ip


def _open_ports(a):
    return {(p["proto"], p["port"]): p for p in a.get("ports", []) if p.get("state", "open") == "open"}


def scan_changes(graph):
    prev = next(_runs_before(graph.run_dir), None)
    if not prev:
        return None
    name, old = prev
    cur_assets, old_assets = graph.data.get("assets") or {}, old.get("assets") or {}
    out = {"against": name, "new_devices": [], "gone_devices": [], "new_ports": [], "closed_ports": [],
           "new_internet_ports": [], "new_forwards": [], "new_internet_cves": []}
    for ip, a in cur_assets.items():
        if ip not in old_assets:
            out["new_devices"].append(_label(ip, a))
            continue
        before, now = _open_ports(old_assets[ip]), _open_ports(a)
        for k in sorted(set(now) - set(before)):
            p = now[k]
            out["new_ports"].append(f"{_label(ip, a)} {k[1]}/{k[0]} {p.get('service') or ''} {p.get('product') or ''}".strip())
        for k in sorted(set(before) - set(now)):
            out["closed_ports"].append(f"{_label(ip, a)} {k[1]}/{k[0]}")
    for ip, a in old_assets.items():
        if ip not in cur_assets:
            out["gone_devices"].append(_label(ip, a))
    wan, owan = graph.data.get("wan") or {}, old.get("wan") or {}
    idb, oidb = wan.get("internetdb") or {}, owan.get("internetdb") or {}
    out["new_internet_ports"] = sorted(set(idb.get("ports") or []) - set(oidb.get("ports") or []))
    out["new_internet_cves"] = sorted(set(idb.get("vulns") or []) - set(oidb.get("vulns") or []))
    # upnpc -l lines: " 0 TCP  8443->192.168.1.92:8443  'desc' '' 0"; drop the index so a reordered list still matches
    key = lambda line: " ".join(str(line).split()[1:3])
    old_fw = {key(m) for m in owan.get("upnp_port_mappings") or []}
    out["new_forwards"] = [key(m) for m in wan.get("upnp_port_mappings") or [] if key(m) not in old_fw]
    return out


def finding_changes(graph):
    prev = graph.data.get("previous")
    if not prev:
        return None
    linked = {f["previous"]["id"] for f in graph.data.get("findings", []) if f.get("previous")}
    new = [f for f in graph.data.get("findings", []) if is_open(f) and not f.get("previous")]
    gone = [p for p in prev.get("findings", []) if p["id"] not in linked]
    pr = lambda f: (f.get("risk") or {}).get("priority")
    return {"against": prev["run"],
            "new": [{"id": f["id"], "title": f["title"], "asset": f.get("asset"), "severity": f.get("severity"), "priority": pr(f)} for f in new],
            "not_seen_again": [{"id": p["id"], "title": p["title"], "asset": p.get("asset")} for p in gone],
            "still_open": len(linked)}


def record(graph, findings=False):
    """Store the changes in the run; called after the scan and again after the AI assessment."""
    ch = graph.data.setdefault("changes", {})
    if findings:
        ch["findings"] = finding_changes(graph)
    else:
        ch["scan"] = scan_changes(graph)
    graph.save()
    return ch
