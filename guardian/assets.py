"""One lasting asset list per site, merged across runs and sources (CAASM-style).

Each run contributes what its scan found (IP, MAC, hostname, type, OS) and the device lists the agents read through
connectors (Active Directory computers, Intune, NinjaOne and other RMMs, Jamf / Kandji, vCenter VMs, Kubernetes nodes,
Google Cloud VMs). Records are matched on MAC address, then host name, then IP (scan only), so the same laptop seen by the
scan, AD and Intune becomes one asset with three sources. Kept beside the vault as plain JSON, like the runs themselves.
"""
import hashlib
import json
import os
import re
import time
from pathlib import Path

KEEP_RUNS = 10


def norm(name):
    """Host name for matching: lower case, no domain, no trailing $ (AD computer accounts)."""
    n = str(name or "").strip().lower().rstrip("$")
    n = n.split(".")[0] if not re.fullmatch(r"[\d.]+", n) else n
    return re.sub(r"[^a-z0-9-]", "", n)


def observations(g):
    """What one run saw: [{"name", "ip", "mac", "type", "os", "vendor", "model", "source"}]."""
    out = []
    for ip, a in (g.get("assets") or {}).items():
        if not re.fullmatch(r"[\d.]+|[0-9a-fA-F:]+", ip or ""):
            continue
        os_ = " ".join(x for x in (a.get("os"), a.get("os_version")) if x) or a.get("os_guess")
        out.append({"name": a.get("hostname") or "", "ip": ip, "mac": (a.get("mac") or "").lower(), "type": a.get("device_type"),
                    "os": os_, "vendor": a.get("vendor") or a.get("mac_vendor"), "model": a.get("model"),
                    "firmware": a.get("firmware_version"), "source": "scan"})
    for source, items in (g.get("inventory") or {}).items():
        for i in items:
            if i.get("name"):
                out.append({"name": i["name"], "ip": i.get("ip"), "mac": (i.get("mac") or "").lower(), "type": i.get("type"),
                            "os": i.get("os"), "source": source, "last_seen": i.get("last_seen")})
    return out


class Store:
    def __init__(self, path):
        self.path = Path(path)
        try:
            self.d = json.loads(self.path.read_text())
        except (OSError, ValueError):
            self.d = {"assets": {}, "runs": []}

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.d))
        os.replace(tmp, self.path)

    def _find(self, o):
        for aid, a in self.d["assets"].items():
            if o["mac"] and o["mac"] in a["macs"]:
                return aid
        n = norm(o["name"])
        if n and not re.fullmatch(r"[\d.]+", n):
            for aid, a in self.d["assets"].items():
                if n in a["names"]:
                    return aid
        if o["source"] == "scan" and o.get("ip"):
            for aid, a in self.d["assets"].items():
                if o["ip"] in a["ips"] and not a["macs"] and not (n and a["names"] and n not in a["names"]):
                    return aid
        return None

    def merge_run(self, run_id, g, when=None):
        """Merge one run (idempotent per run ID). Returns the number of assets touched."""
        if run_id in self.d["runs"]:
            return 0
        when = when or (g.get("started") or time.strftime("%Y-%m-%dT%H:%M:%S"))[:19]
        touched = set()
        for o in observations(g):
            aid = self._find(o)
            if not aid:
                aid = "A" + hashlib.sha1(f"{o['mac']}|{norm(o['name'])}|{o.get('ip')}|{o['source']}".encode()).hexdigest()[:10]
                self.d["assets"][aid] = {"id": aid, "name": o["name"] or o.get("ip"), "names": [], "ips": [], "macs": [], "type": None,
                                         "os": None, "vendor": None, "model": None, "firmware": None, "sources": {},
                                         "first_seen": when, "last_seen": when, "runs": [], "open": {}}
            a = self.d["assets"][aid]
            n = norm(o["name"])
            if n and n not in a["names"]:
                a["names"].append(n)
            for k, lst in (("ip", "ips"), ("mac", "macs")):
                if o.get(k) and o[k] not in a[lst]:
                    a[lst] = (a[lst] + [o[k]])[-6:]
            if o["name"] and (not a["name"] or re.fullmatch(r"[\d.]+", str(a["name"]))):
                a["name"] = o["name"]
            for k in ("type", "os", "vendor", "model", "firmware"):
                if o.get(k):
                    a[k] = o[k]
            a["sources"][o["source"]] = o.get("last_seen") or when
            a["last_seen"] = max(a["last_seen"], when)
            if run_id not in a["runs"]:
                a["runs"] = (a["runs"] + [run_id])[-KEEP_RUNS:]
            touched.add(aid)
        self.d["runs"] = (self.d["runs"] + [run_id])[-500:]
        self.d["updated"] = when
        return len(touched)

    def set_open(self, run_id, findings_by_key):
        """Open findings per asset from the latest run: {asset key (IP or name text): {priority: count}}."""
        for a in self.d["assets"].values():
            if run_id not in a["runs"]:
                continue
            counts = {}
            for key, pc in findings_by_key.items():
                k = key.lower()
                if k in a["ips"] or any(n and (k == n or k.endswith("/" + n) or norm(k) == n) for n in a["names"]):
                    for p, c in pc.items():
                        counts[str(p)] = counts.get(str(p), 0) + c
            a["open"] = counts

    def view(self, now=None):
        now = now or time.strftime("%Y-%m-%dT%H:%M:%S")
        rows = sorted(self.d["assets"].values(), key=lambda a: (-sum(v for k, v in a["open"].items() if k in ("1", "2")), str(a["name"]).lower()))
        def age(t):
            try:
                return (time.mktime(time.strptime(now[:19], "%Y-%m-%dT%H:%M:%S")) - time.mktime(time.strptime(t[:19], "%Y-%m-%dT%H:%M:%S"))) / 86400
            except (ValueError, TypeError):
                return 0
        for a in rows:
            a["new"] = age(a["first_seen"]) <= 7
            a["stale"] = age(a["last_seen"]) >= 30
        counts = {"all": len(rows), "new": sum(a["new"] for a in rows), "stale": sum(a["stale"] for a in rows),
                  "p12": sum(1 for a in rows if a["open"].get("1") or a["open"].get("2")),
                  "single": sum(1 for a in rows if len(a["sources"]) == 1)}
        return {"assets": rows, "counts": counts, "updated": self.d.get("updated")}
