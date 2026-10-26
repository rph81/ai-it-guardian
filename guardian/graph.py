"""Asset graph: one JSON document per assessment run, shared by every agent."""
import json
import os
import threading
import time

SEVERITIES = ["critical", "high", "medium", "low", "info"]


class Graph:
    def __init__(self, run_dir):
        self.run_dir = run_dir
        self.path = os.path.join(run_dir, "graph.json")
        self.lock = threading.Lock()
        if os.path.exists(self.path):
            with open(self.path) as f:
                self.data = json.load(f)
        else:
            self.data = {
                "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "site": {},
                "assets": {},
                "wan": {},
                "findings": [],
                "agent_log": [],
            }

    # -- assets -------------------------------------------------------------
    def asset(self, ip):
        return self.data["assets"].setdefault(ip, {"ip": ip, "ports": [], "sources": []})

    def merge_asset(self, ip, source, **fields):
        with self.lock:
            a = self.asset(ip)
            if source not in a["sources"]:
                a["sources"].append(source)
            for k, v in fields.items():
                if v in (None, "", [], {}):
                    continue
                if isinstance(v, dict) and isinstance(a.get(k), dict):
                    a[k].update(v)
                else:
                    a[k] = v

    def set_ports(self, ip, ports):
        with self.lock:
            a = self.asset(ip)
            known = {(p["proto"], p["port"]): p for p in a["ports"]}
            for p in ports:
                known.setdefault((p["proto"], p["port"]), {}).update(p)
            a["ports"] = sorted(known.values(), key=lambda p: (p["proto"], p["port"]))

    # -- findings -----------------------------------------------------------
    def add_finding(self, finding):
        with self.lock:
            finding["id"] = "F%03d" % (len(self.data["findings"]) + 1)
            self.data["findings"].append(finding)
            return finding["id"]

    def log(self, agent, message):
        with self.lock:
            self.data["agent_log"].append(
                {"t": time.strftime("%H:%M:%S"), "agent": agent, "msg": message})
        print(f"[{agent}] {message}", flush=True)

    def save(self):
        with self.lock:
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.data, f, indent=1, default=str)
            os.replace(tmp, self.path)

    # -- compact views handed to agents -------------------------------------
    def summary(self, ips=None):
        rows = []
        for ip, a in sorted(self.data["assets"].items(), key=lambda kv: tuple(map(int, kv[0].split(".")))):
            if ips and ip not in ips:
                continue
            open_ports = [f'{p["port"]}/{p["proto"]} {p.get("service", "")} {p.get("product", "")} {p.get("version", "")}'.strip()
                          for p in a["ports"] if p.get("state", "open").startswith("open")]
            rows.append({
                "ip": ip,
                "mac_vendor": a.get("mac_vendor"),
                "hostname": a.get("hostname"),
                "device_type": a.get("device_type"),
                "role": a.get("role"),
                "vendor": a.get("vendor"),
                "model": a.get("model"),
                "os": a.get("os") or a.get("os_guess"),
                "firmware_version": a.get("firmware_version"),
                "open_ports": open_ports,
            })
        return rows
