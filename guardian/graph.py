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
        self.events_path = os.path.join(run_dir, "events.jsonl")
        self.lock = threading.RLock()
        self.seq = 0
        if os.path.exists(self.events_path):
            with open(self.events_path) as f:
                self.seq = sum(1 for _ in f)
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

    # -- live events for the console's agent map (append-only, one JSON object per line) --------
    def event(self, kind, frm, to=None, text="", **extra):
        with self.lock:
            self.seq += 1
            ev = {"n": self.seq, "t": round(time.time(), 2), "kind": kind, "from": frm, "to": to or frm,
                  "text": text[:600], "total": round(self.data.get("cost_total", 0), 4), **extra}
            with open(self.events_path, "a") as f:
                f.write(json.dumps(ev, default=str) + "\n")
        return ev

    def reset_events(self):
        with self.lock:
            if os.path.exists(self.events_path):
                os.remove(self.events_path)
            self.seq = 0

    def agent(self, name, **fields):
        """Update (and return) the live state of one agent: status, activity, rounds, usage, cost."""
        with self.lock:
            a = self.data.setdefault("agents", {}).setdefault(name, {
                "status": "waiting", "activity": "", "rounds": 0, "checks": {}, "cost": 0.0,
                "usage": {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "searches": 0}})
            a.update(fields)
            return a

    def count_check(self, name, tool):
        with self.lock:
            c = self.agent(name)["checks"]
            c[tool] = c.get(tool, 0) + 1

    def count_round(self, name):
        with self.lock:
            a = self.agent(name)
            a["rounds"] += 1

    def add_usage(self, name, usage, cost):
        with self.lock:
            a = self.agent(name)
            for k, v in usage.items():
                a["usage"][k] = a["usage"].get(k, 0) + v
            a["cost"] = round(a["cost"] + cost, 6)
            self.data["cost_total"] = round(self.data.get("cost_total", 0) + cost, 6)

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
                          for p in a["ports"] if p.get("state", "open") == "open"]
            # nmap says "open|filtered" when a UDP port never answered: unknown, not open
            silent_udp = [f'{p["port"]}/udp' for p in a["ports"] if p.get("state") == "open|filtered"]
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
                **({"udp_no_reply": silent_udp} if silent_udp else {}),
            })
        return rows
