"""Tools the agents can call. Every tool is read-only and scope-checked.

Agents never get a shell. Active probes are limited to an allowlist of nmap
NSE scripts from the "safe"/"discovery" categories, and HTTP is GET/HEAD only
to in-scope LAN addresses.
"""
import json
import os
import re
import subprocess
import threading
import time
import urllib.parse
import urllib.request

from . import access, netutil
from .collector import parse_nmap_xml
from .controls import FRAMEWORKS, STATUSES
from .graph import SEVERITIES, is_open

# check name -> nmap NSE script (all non-intrusive)
PROBES = {
    "tls_ciphers": "ssl-enum-ciphers",
    "tls_cert": "ssl-cert",
    "http_headers": "http-headers",
    "http_methods": "http-methods",
    "http_title": "http-title",
    "http_robots": "http-robots.txt",
    "http_server_header": "http-server-header",
    "ssh_algorithms": "ssh2-enum-algos",
    "ssh_auth_methods": "ssh-auth-methods",
    "ssh_hostkey": "ssh-hostkey",
    "smb_protocols": "smb-protocols",
    "smb_signing": "smb2-security-mode",
    "rdp_encryption": "rdp-enum-encryption",
    "ntp_info": "ntp-info",
    "dns_recursion": "dns-recursion",
    "upnp_info": "upnp-info",
    "snmp_info": "snmp-info",
    "vnc_info": "vnc-info",
    "rtsp_methods": "rtsp-methods",
    "banner": "banner",
}

FIELDS = ["device_type", "role", "vendor", "model", "os", "os_version", "firmware_version", "notes"]

_kev = None
_kev_lock = threading.Lock()
_nvd_lock = threading.Lock()
_nvd_last = [0.0]


def _get_json(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "ai-guardian-assessment/0.1"})
    if "nvd.nist.gov" in url and os.environ.get("NVD_API_KEY"):
        req.add_header("apiKey", os.environ["NVD_API_KEY"])
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read())


def _kev_set():
    global _kev
    with _kev_lock:
        if _kev is None:
            try:
                data = _get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", 60)
                _kev = {v["cveID"]: v for v in data["vulnerabilities"]}
            except Exception:
                _kev = {}
        return _kev


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
PRIORITY_DAYS = {1: 7, 2: 30, 3: 90, 4: 180}          # due-date targets per priority


def cves_in(*texts):
    return sorted({m.upper() for t in texts if t for m in CVE_RE.findall(t if isinstance(t, str) else " ".join(map(str, t)))})


class Toolbox:
    def __init__(self, graph, agent_name, allowed_ips=None):
        self.g = graph
        self.agent = agent_name
        self.network = graph.data["site"]["network"]
        self.allowed_ips = set(allowed_ips) if allowed_ips else None

    # -- schemas --------------------------------------------------------------
    def schemas(self, names):
        all_tools = {
            "inventory": {
                "description": "Compact list of every discovered asset (or a subset) with open ports and what is known about it.",
                "input_schema": {"type": "object", "properties": {
                    "ips": {"type": "array", "items": {"type": "string"}, "description": "Optional subset of IPs."}},
                    "additionalProperties": False}},
            "asset_details": {
                "description": "Full raw record for one asset: ports, service versions, nmap script output, HTTP/TLS banners, UPnP description, broadcast data.",
                "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}},
                                 "required": ["ip"], "additionalProperties": False}},
            "probe": {
                "description": "Run non-intrusive nmap NSE checks against specific ports of one LAN host. Checks: " + ", ".join(PROBES),
                "input_schema": {"type": "object", "properties": {
                    "ip": {"type": "string"},
                    "ports": {"type": "array", "items": {"type": "integer"}, "maxItems": 20},
                    "udp": {"type": "boolean", "description": "Probe UDP instead of TCP."},
                    "checks": {"type": "array", "items": {"type": "string", "enum": list(PROBES)}, "minItems": 1}},
                    "required": ["ip", "ports", "checks"], "additionalProperties": False}},
            "http_get": {
                "description": "HTTP GET or HEAD a URL on a LAN host. No credentials, no redirects followed. Returns status, headers, title and a text excerpt.",
                "input_schema": {"type": "object", "properties": {
                    "url": {"type": "string"}, "method": {"type": "string", "enum": ["GET", "HEAD"]}},
                    "required": ["url"], "additionalProperties": False}},
            "tls_inspect": {
                "description": "Negotiated TLS version/cipher and certificate details (issuer, expiry, key size, self-signed) for a LAN host:port.",
                "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}, "port": {"type": "integer"}},
                                 "required": ["ip", "port"], "additionalProperties": False}},
            "cve_lookup": {
                "description": "Look up known CVEs in NVD. Prefer a CPE 2.3 string with version (cpe:2.3:a:vendor:product:version); otherwise keywords like 'openssh 8.2'. Results include CVSS and whether CISA lists the CVE as actively exploited (KEV).",
                "input_schema": {"type": "object", "properties": {
                    "cpe": {"type": "string"}, "keywords": {"type": "string"}},
                    "additionalProperties": False}},
            "eol_lookup": {
                "description": "End-of-life / support status for a product from endoflife.date (slug such as 'debian', 'windows', 'openssh', 'nginx', 'proxmox-ve', 'synology-dsm', 'ios', 'macos').",
                "input_schema": {"type": "object", "properties": {"product": {"type": "string"}},
                                 "required": ["product"], "additionalProperties": False}},
            "wan_info": {
                "description": "Public IP, what Shodan InternetDB sees from the internet (ports, CPEs, CVEs), and UPnP port mappings on the router.",
                "input_schema": {"type": "object", "properties": {}, "additionalProperties": False}},
            "annotate_asset": {
                "description": "Record what you determined about an asset (identity, role, OS, firmware). Fields: " + ", ".join(FIELDS),
                "input_schema": {"type": "object", "properties": {
                    "ip": {"type": "string"},
                    "fields": {"type": "object", "properties": {f: {"type": "string"} for f in FIELDS},
                               "additionalProperties": False}},
                    "required": ["ip", "fields"], "additionalProperties": False}},
            "record_finding": {
                "description": "Record one security or hygiene finding. One finding per distinct issue per asset (or per site for site-wide issues).",
                "input_schema": {"type": "object", "properties": {
                    "asset": {"type": "string", "description": "IP, or 'site' / 'wan' for site-wide issues."},
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": SEVERITIES},
                    "confidence": {"type": "string", "enum": ["confirmed", "likely", "possible"]},
                    "evidence": {"type": "string", "description": "What you observed, quoting tool output."},
                    "impact": {"type": "string", "description": "Plain-language business impact."},
                    "recommendation": {"type": "string", "description": "Concrete fix steps."},
                    "references": {"type": "array", "items": {"type": "string"}}},
                    "required": ["asset", "title", "severity", "confidence", "evidence", "impact", "recommendation"],
                    "additionalProperties": False}},
            "update_finding": {
                "description": "Update an existing finding after a re-check: mark it resolved when the issue is confirmed gone, or add new evidence / change severity. Quote what you observed.",
                "input_schema": {"type": "object", "properties": {
                    "id": {"type": "string", "description": "Finding ID, e.g. F007."},
                    "status": {"type": "string", "enum": ["open", "resolved"]},
                    "severity": {"type": "string", "enum": SEVERITIES},
                    "evidence": {"type": "string", "description": "What the re-check observed."}},
                    "required": ["id", "status", "evidence"], "additionalProperties": False}},
            # -- connector tools (Active Directory, Patch & configuration): sign in read-only through a connector ----------
            "list_connectors": {
                "description": "The connectors set up for this site that your layer can use: id, type, name and the hosts or domain they cover.",
                "input_schema": {"type": "object", "properties": {}, "additionalProperties": False}},
            "ad_query": {
                "description": "Run one fixed, read-only LDAP query against Active Directory through a connector. Queries: "
                               + ", ".join(access.AD_QUERIES) + ". 'days' sets the age for stale_users / stale_computers (default 90).",
                "input_schema": {"type": "object", "properties": {
                    "connector": {"type": "string"}, "query": {"type": "string", "enum": list(access.AD_QUERIES)},
                    "days": {"type": "integer", "minimum": 30, "maximum": 365}},
                    "required": ["connector", "query"], "additionalProperties": False}},
            "linux_check": {
                "description": "Run one fixed, read-only check on a Linux server over SSH (as the connector's normal user, no sudo). Checks: "
                               + ", ".join(access.LINUX_CHECKS) + ".",
                "input_schema": {"type": "object", "properties": {
                    "connector": {"type": "string"}, "host": {"type": "string"},
                    "check": {"type": "string", "enum": list(access.LINUX_CHECKS)}},
                    "required": ["connector", "host", "check"], "additionalProperties": False}},
            "linux_vulnerable_packages": {
                "description": "Check every installed package on a Debian, Ubuntu LTS or Alpine server against the OSV database; returns the packages with advisories.",
                "input_schema": {"type": "object", "properties": {"connector": {"type": "string"}, "host": {"type": "string"}},
                                 "required": ["connector", "host"], "additionalProperties": False}},
            "synology_info": {
                "description": "Read DSM version, model and update status from a Synology NAS through its read-only connector.",
                "input_schema": {"type": "object", "properties": {"connector": {"type": "string"}},
                                 "required": ["connector"], "additionalProperties": False}},
            "proxmox_get": {
                "description": "Read one Proxmox VE or Backup Server API path through a read-only token (GET only, fixed list of paths: "
                               "version, nodes and their status, pending apt updates, subscription, certificates, firewall options, "
                               "cluster resources and backup jobs, users, storage, guests and their config; for PBS also datastores, verify, sync and prune jobs).",
                "input_schema": {"type": "object", "properties": {"connector": {"type": "string"}, "path": {"type": "string"}},
                                 "required": ["connector", "path"], "additionalProperties": False}},
            "graph_get": {
                "description": "Read one Microsoft Graph path through the Microsoft 365 connector (GET only, fixed list of paths: organization, "
                               "domains, licences, users, groups, directory roles and assignments, Conditional Access, security defaults, "
                               "authorization and authentication-method policies, MFA registration report, sign-in and audit logs, apps, "
                               "service principals and consents, Secure Score, security alerts and incidents, Intune managed devices, "
                               "compliance policies and configurations, devices). query may set $select, $filter, $top, $expand, $orderby, "
                               "$count, $search. beta=true uses the beta API.",
                "input_schema": {"type": "object", "properties": {
                    "connector": {"type": "string"}, "path": {"type": "string"},
                    "query": {"type": "object", "additionalProperties": {"type": "string"}},
                    "beta": {"type": "boolean"}, "max_pages": {"type": "integer", "minimum": 1, "maximum": 10}},
                    "required": ["connector", "path"], "additionalProperties": False}},
            "windows_check": {
                "description": "Run one fixed, read-only PowerShell check on a Windows machine over WinRM (normal user, not an administrator). Checks: "
                               + ", ".join(access.WINDOWS_CHECKS) + ".",
                "input_schema": {"type": "object", "properties": {
                    "connector": {"type": "string"}, "host": {"type": "string"},
                    "check": {"type": "string", "enum": list(access.WINDOWS_CHECKS)}},
                    "required": ["connector", "host", "check"], "additionalProperties": False}},
            # -- analyst tools: they read the run's findings and enrich them; nothing touches the network except the
            # EPSS and KEV feeds -------------------------------------------------------------------------------------
            "list_findings": {
                "description": "Compact list of findings in this run (open ones by default), with the CVEs they mention, any priority already set and what is known about the device.",
                "input_schema": {"type": "object", "properties": {
                    "layer": {"type": "string"}, "include_closed": {"type": "boolean"}}, "additionalProperties": False}},
            "finding_details": {
                "description": "Everything recorded for one finding, including its full evidence and history.",
                "input_schema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"], "additionalProperties": False}},
            "epss_lookup": {
                "description": "FIRST.org EPSS: probability that each CVE is exploited in the wild in the next 30 days, and its percentile.",
                "input_schema": {"type": "object", "properties": {
                    "cves": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 100}},
                    "required": ["cves"], "additionalProperties": False}},
            "kev_details": {
                "description": "CISA Known Exploited Vulnerabilities entries for these CVEs: date added, known ransomware use, required action.",
                "input_schema": {"type": "object", "properties": {
                    "cves": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 200}},
                    "required": ["cves"], "additionalProperties": False}},
            "set_priority": {
                "description": "Set a finding's fix priority: 1 = fix now (target 7 days), 2 = fix soon (30 days), 3 = planned (90 days), 4 = when convenient (180 days). Give the reason in plain words.",
                "input_schema": {"type": "object", "properties": {
                    "id": {"type": "string"}, "priority": {"type": "integer", "enum": [1, 2, 3, 4]},
                    "reason": {"type": "string"},
                    "exposure": {"type": "string", "enum": ["internet", "lan", "internal-only", "account"]},
                    "kev": {"type": "boolean"}, "ransomware": {"type": "boolean"},
                    "epss": {"type": "number", "description": "Highest EPSS of the finding's CVEs, 0-1."},
                    "cves": {"type": "array", "items": {"type": "string"}}},
                    "required": ["id", "priority", "reason", "exposure"], "additionalProperties": False}},
            "merge_findings": {
                "description": "Mark findings as duplicates of another one (the same issue reported by several agents). The kept finding stays open.",
                "input_schema": {"type": "object", "properties": {
                    "keep": {"type": "string"}, "duplicates": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                    "reason": {"type": "string"}}, "required": ["keep", "duplicates", "reason"], "additionalProperties": False}},
            "set_criticality": {
                "description": "Record how important a device is to the business (high = the business stops or data is lost without it).",
                "input_schema": {"type": "object", "properties": {
                    "ip": {"type": "string"}, "level": {"type": "string", "enum": ["high", "medium", "low"]},
                    "reason": {"type": "string"}}, "required": ["ip", "level", "reason"], "additionalProperties": False}},
            "previous_findings": {
                "description": "Open findings from the previous assessment of this site, so the same issue keeps its owner and due date.",
                "input_schema": {"type": "object", "properties": {}, "additionalProperties": False}},
            "link_previous": {
                "description": "Say that a finding in this run is the same issue as a finding from the previous assessment.",
                "input_schema": {"type": "object", "properties": {
                    "id": {"type": "string"}, "previous_id": {"type": "string"}}, "required": ["id", "previous_id"], "additionalProperties": False}},
            "record_path": {
                "description": "Record one realistic attack path: how an attacker could get from an entry point to something the business can't lose, step by step, each step tied to a finding where there is one.",
                "input_schema": {"type": "object", "properties": {
                    "title": {"type": "string"}, "target": {"type": "string", "description": "What the attacker reaches, e.g. 'file server with accounting data'."},
                    "likelihood": {"type": "string", "enum": ["high", "medium", "low"]},
                    "steps": {"type": "array", "minItems": 2, "maxItems": 8, "items": {"type": "object", "properties": {
                        "stage": {"type": "string", "enum": ["entry", "foothold", "move", "escalate", "target"]},
                        "asset": {"type": "string"}, "text": {"type": "string"}, "finding": {"type": "string"}},
                        "required": ["stage", "text"], "additionalProperties": False}},
                    "choke_points": {"type": "array", "items": {"type": "object", "properties": {
                        "finding": {"type": "string"}, "fix": {"type": "string"}},
                        "required": ["fix"], "additionalProperties": False}},
                    "summary": {"type": "string"}},
                    "required": ["title", "target", "likelihood", "steps", "summary"], "additionalProperties": False}},
            "control_catalog": {
                "description": "The controls of one framework: " + ", ".join(f"{k} ({v['title']})" for k, v in FRAMEWORKS.items()) + ".",
                "input_schema": {"type": "object", "properties": {"framework": {"type": "string", "enum": list(FRAMEWORKS)}},
                                 "required": ["framework"], "additionalProperties": False}},
            "set_controls": {
                "description": "Record the status of several controls of one framework. met / partial / gap need evidence (finding IDs or what was observed); use not_assessed when Guardian can't see it.",
                "input_schema": {"type": "object", "properties": {
                    "framework": {"type": "string", "enum": list(FRAMEWORKS)},
                    "items": {"type": "array", "minItems": 1, "maxItems": 100, "items": {"type": "object", "properties": {
                        "id": {"type": "string"}, "status": {"type": "string", "enum": list(STATUSES)},
                        "findings": {"type": "array", "items": {"type": "string"}}, "note": {"type": "string"}},
                        "required": ["id", "status", "note"], "additionalProperties": False}}},
                    "required": ["framework", "items"], "additionalProperties": False}},
        }
        return [{"name": n, **all_tools[n]} for n in names]

    # -- dispatch -------------------------------------------------------------
    def call(self, name, args):
        try:
            return getattr(self, "t_" + name)(**args)
        except TypeError as e:
            return {"error": f"bad arguments: {e}"}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"[:400]}

    def _check_ip(self, ip):
        if not netutil.in_scope(ip, self.network):
            raise ValueError(f"{ip} is outside the assessed network {self.network}")
        if ip == self.g.data["site"].get("collector_ip"):
            raise ValueError("that is the collector itself")

    # -- implementations ------------------------------------------------------
    def t_inventory(self, ips=None):
        return self.g.summary(ips or self.allowed_ips)

    def t_asset_details(self, ip):
        a = self.g.data["assets"].get(ip)
        return a or {"error": "unknown asset"}

    def t_probe(self, ip, ports, checks, udp=False):
        self._check_ip(ip)
        scripts = ",".join(PROBES[c] for c in checks)
        cmd = ["nmap", "-Pn", "-n", "-sU" if udp else "-sT", "-sV", "--version-light",
               "-p", ",".join(str(int(p)) for p in ports), "--script", scripts,
               "--script-timeout", "60s", "-oX", "-", ip]
        self.g.log(self.agent, f"probe {ip}:{ports} {checks}")
        xml_out = subprocess.run(cmd, capture_output=True, text=True, timeout=400).stdout
        parse_nmap_xml(self.g, xml_out, f"probe:{self.agent}")
        a = self.g.data["assets"].get(ip, {})
        return [p for p in a.get("ports", []) if p["port"] in ports]

    def t_http_get(self, url, method="GET"):
        host = urllib.parse.urlparse(url).hostname
        self._check_ip(host)
        return netutil.http_fetch(url, method=method)

    def t_tls_inspect(self, ip, port):
        self._check_ip(ip)
        return netutil.tls_inspect(ip, port)

    def t_cve_lookup(self, cpe=None, keywords=None):
        if not cpe and not keywords:
            return {"error": "give cpe or keywords"}
        q = {"resultsPerPage": 40}
        if cpe:
            q["virtualMatchString"] = cpe
        else:
            q["keywordSearch"] = keywords
        with _nvd_lock:  # NVD allows ~5 requests / 30 s without a key
            wait = (0.8 if os.environ.get("NVD_API_KEY") else 6.5) - (time.time() - _nvd_last[0])
            if wait > 0:
                time.sleep(wait)
            _nvd_last[0] = time.time()
        data = _get_json("https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(q))
        kev = _kev_set()
        out = []
        for item in data.get("vulnerabilities", []):
            c = item["cve"]
            score, sev = None, None
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if c.get("metrics", {}).get(key):
                    d = c["metrics"][key][0]["cvssData"]
                    score, sev = d.get("baseScore"), d.get("baseSeverity") or c["metrics"][key][0].get("baseSeverity")
                    break
            desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
            out.append({"id": c["id"], "cvss": score, "severity": sev, "published": c.get("published", "")[:10],
                        "kev": c["id"] in kev, "summary": desc[:240]})
        out.sort(key=lambda v: (not v["kev"], -(v["cvss"] or 0)))
        return {"total": data.get("totalResults", 0), "top": out[:15]}

    def t_eol_lookup(self, product):
        try:
            cycles = _get_json(f"https://endoflife.date/api/{urllib.parse.quote(product.lower())}.json")
        except Exception as e:
            return {"error": f"no data for '{product}' ({e})"}
        return [{k: c.get(k) for k in ("cycle", "releaseDate", "eol", "support", "latest", "lts", "extendedSupport")}
                for c in cycles[:12]]

    def t_wan_info(self):
        return self.g.data.get("wan", {})

    def t_annotate_asset(self, ip, fields):
        self.g.merge_asset(ip, f"agent:{self.agent}", **{k: v for k, v in fields.items() if k in FIELDS})
        return {"ok": True}

    def t_record_finding(self, **f):
        f["layer"] = self.agent
        f["status"] = "open"
        fid = self.g.add_finding(f)
        self.g.log(self.agent, f'{fid} [{f["severity"]}] {f["asset"]}: {f["title"]}')
        self.g.event("find", self.agent, "orchestrator", f'{f["title"]} ({f["severity"]})', finding=fid, severity=f["severity"])
        return {"ok": True, "id": fid}

    def t_update_finding(self, id, status, evidence, severity=None):
        with self.g.lock:
            f = next((x for x in self.g.data["findings"] if x["id"] == id), None)
            if not f:
                return {"error": f"no finding {id}"}
            f.setdefault("history", []).append({"t": time.strftime("%Y-%m-%dT%H:%M:%S"), "by": self.agent,
                                                "status": status, "evidence": evidence[:2000],
                                                **({"severity": severity} if severity else {})})
            f["status"] = status
            if severity:
                f["severity"] = severity
        self.g.log(self.agent, f"{id} updated: {status}")
        self.g.event("find", self.agent, "orchestrator", f'{id} {"resolved" if status == "resolved" else "updated"}: {f["title"]}',
                     finding=id, severity=f["severity"], status=status)
        return {"ok": True}

    # -- connector tools -------------------------------------------------------------------------------------
    def t_list_connectors(self):
        want = access.CONNECTOR_AGENTS.get(self.agent)
        rows = [c for c in access.summary() if not want or c["type"] in want]
        return rows or {"note": "No connector of this kind was handed to this run (none set up, or the vault was locked when it started)."}

    def t_ad_query(self, connector, query, days=90):
        self.g.log(self.agent, f"ad_query {query}")
        return access.ad_query(connector, query, days)

    def t_linux_check(self, connector, host, check):
        self.g.log(self.agent, f"linux_check {host} {check}")
        return access.linux_check(connector, host, check)

    def t_linux_vulnerable_packages(self, connector, host):
        self.g.log(self.agent, f"linux_vulnerable_packages {host}")
        return access.linux_vulnerable_packages(connector, host)

    def t_graph_get(self, connector, path, query=None, beta=False, max_pages=5):
        self.g.log(self.agent, f"graph_get {path}")
        return access.graph_get(connector, path, query, beta, max_pages)

    def t_windows_check(self, connector, host, check):
        self.g.log(self.agent, f"windows_check {host} {check}")
        return access.windows_check(connector, host, check)

    def t_synology_info(self, connector):
        return access.synology_info(connector)

    def t_proxmox_get(self, connector, path):
        return access.proxmox_get(connector, path)

    # -- analyst tools ---------------------------------------------------------------------------------------
    def _finding(self, fid):
        f = next((x for x in self.g.data["findings"] if x["id"] == fid), None)
        if not f:
            raise ValueError(f"no finding {fid}")
        return f

    def t_list_findings(self, layer=None, include_closed=False):
        assets = self.g.data["assets"]
        out = []
        for f in self.g.data["findings"]:
            if (not include_closed and not is_open(f)) or (layer and f.get("layer") != layer):
                continue
            a = assets.get(f.get("asset"), {})
            out.append({k: v for k, v in {
                "id": f["id"], "layer": f.get("layer"), "asset": f.get("asset"), "title": f.get("title"),
                "severity": f.get("severity"), "confidence": f.get("confidence"), "status": f.get("status"),
                "evidence": (f.get("evidence") or "")[:400],
                "cves": cves_in(f.get("title"), f.get("evidence"), f.get("references")),
                "device": " ".join(x for x in (a.get("vendor"), a.get("model"), a.get("device_type")) if x) or None,
                "role": a.get("role"), "criticality": a.get("criticality"),
                "priority": (f.get("risk") or {}).get("priority")}.items() if v not in (None, [], "")})
        return out

    def t_finding_details(self, id):
        return self._finding(id)

    def t_epss_lookup(self, cves):
        cves = [c.upper() for c in cves if CVE_RE.fullmatch(c.strip())]
        if not cves:
            return {"error": "no valid CVE IDs"}
        data = _get_json("https://api.first.org/data/v1/epss?" + urllib.parse.urlencode({"cve": ",".join(cves[:100])}))
        found = {d["cve"]: {"epss": float(d["epss"]), "percentile": float(d["percentile"]), "date": d.get("date")}
                 for d in data.get("data", [])}
        return {c: found.get(c, "no EPSS score (too new, rejected or not a CVE FIRST tracks)") for c in cves}

    def t_kev_details(self, cves):
        kev = _kev_set()
        if not kev:
            return {"error": "the CISA KEV feed could not be loaded"}
        out = {}
        for c in cves:
            v = kev.get(c.upper())
            out[c.upper()] = {"in_kev": True, "name": v.get("vulnerabilityName"), "added": v.get("dateAdded"),
                              "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
                              "required_action": v.get("requiredAction")} if v else {"in_kev": False}
        return out

    def t_set_priority(self, id, priority, reason, exposure, kev=None, ransomware=None, epss=None, cves=None):
        with self.g.lock:
            f = self._finding(id)
            f["risk"] = {k: v for k, v in {
                "priority": priority, "reason": reason[:600], "exposure": exposure, "kev": kev, "ransomware": ransomware,
                "epss": round(epss, 4) if isinstance(epss, (int, float)) else None,
                "cves": [c.upper() for c in (cves or [])][:20], "due_days": PRIORITY_DAYS[priority],
                "by": self.agent}.items() if v is not None}
        return {"ok": True}

    def t_merge_findings(self, keep, duplicates, reason):
        with self.g.lock:
            self._finding(keep)
            for d in duplicates:
                if d == keep:
                    continue
                f = self._finding(d)
                f.update(status="duplicate", duplicate_of=keep)
                f.setdefault("history", []).append({"t": time.strftime("%Y-%m-%dT%H:%M:%S"), "by": self.agent,
                                                    "status": "duplicate", "evidence": f"Same issue as {keep}: {reason[:400]}"})
        return {"ok": True}

    def t_set_criticality(self, ip, level, reason):
        if ip not in self.g.data["assets"]:
            return {"error": "unknown asset"}
        self.g.merge_asset(ip, f"agent:{self.agent}", criticality=level, criticality_reason=reason[:300])
        return {"ok": True}

    def t_previous_findings(self):
        prev = self.g.data.get("previous") or {}
        if not prev:
            return {"note": "No earlier assessment of this site."}
        return {"run": prev.get("run"), "findings": prev.get("findings", [])}

    def t_link_previous(self, id, previous_id):
        prev = self.g.data.get("previous") or {}
        p = next((x for x in prev.get("findings", []) if x["id"] == previous_id), None)
        if not p:
            return {"error": f"no previous finding {previous_id}"}
        with self.g.lock:
            f = self._finding(id)
            f["previous"] = {"run": prev["run"], "id": previous_id}
            f["first_seen"] = p.get("first_seen") or prev.get("started")
        return {"ok": True, "first_seen": f["first_seen"]}

    def t_record_path(self, title, target, likelihood, steps, summary, choke_points=None):
        known = {f["id"] for f in self.g.data["findings"]}
        bad = [x for x in [s.get("finding") for s in steps] + [c.get("finding") for c in (choke_points or [])] if x and x not in known]
        if bad:
            return {"error": f"unknown finding IDs: {', '.join(bad)}"}
        with self.g.lock:
            paths = self.g.data.setdefault("attack_paths", [])
            pid = "AP%02d" % (len(paths) + 1)
            paths.append({"id": pid, "title": title[:200], "target": target[:200], "likelihood": likelihood,
                          "steps": steps, "choke_points": choke_points or [], "summary": summary[:1200]})
        return {"ok": True, "id": pid}

    def t_control_catalog(self, framework):
        fw = FRAMEWORKS[framework]
        done = (self.g.data.get("compliance") or {}).get(framework, {})
        return {"framework": fw["title"], "controls": [{"id": c, "title": t, **({"status": done[c]["status"]} if c in done else {})}
                                                       for c, t in fw["controls"]]}

    def t_set_controls(self, framework, items):
        ids = {c for c, _ in FRAMEWORKS[framework]["controls"]}
        known = {f["id"] for f in self.g.data["findings"]}
        bad = [i["id"] for i in items if i["id"] not in ids]
        with self.g.lock:
            store = self.g.data.setdefault("compliance", {}).setdefault(framework, {})
            for i in items:
                if i["id"] in ids:
                    store[i["id"]] = {"status": i["status"], "findings": [x for x in i.get("findings", []) if x in known],
                                      "note": i["note"][:600]}
        counts = {s: sum(1 for v in store.values() if v["status"] == s) for s in STATUSES}
        return {"ok": True, "recorded": len(items) - len(bad), **({"unknown_controls": bad} if bad else {}),
                "progress": f"{len(store)} of {len(ids)} controls set", "counts": counts}


def describe(name, args):
    """One line, in plain words, for the live map and the agent cards."""
    a = args or {}
    if name == "probe":
        return f'Probe {a.get("ip")} {"UDP" if a.get("udp") else "TCP"} {",".join(map(str, a.get("ports", [])))}: {", ".join(a.get("checks", []))}'
    if name == "http_get":
        return f'{a.get("method", "GET")} {a.get("url")}'
    if name == "tls_inspect":
        return f'TLS check {a.get("ip")}:{a.get("port")}'
    if name == "cve_lookup":
        return f'CVE lookup: {a.get("cpe") or a.get("keywords")}'
    if name == "eol_lookup":
        return f'End-of-life lookup: {a.get("product")}'
    if name == "wan_info":
        return "Read public-IP data and router port forwards"
    if name == "inventory":
        return "Read the inventory" + (f' ({len(a["ips"])} devices)' if a.get("ips") else "")
    if name == "asset_details":
        return f'Read everything known about {a.get("ip")}'
    if name == "annotate_asset":
        f = a.get("fields", {})
        what = " ".join(x for x in (f.get("vendor"), f.get("model"), f.get("device_type")) if x)
        return f'Identified {a.get("ip")}' + (f": {what}" if what else "")
    if name == "record_finding":
        return f'Recorded a finding: {a.get("title")} ({a.get("severity")})'
    if name == "update_finding":
        return f'Updated {a.get("id")}: ' + ("confirmed fixed" if a.get("status") == "resolved" else "still open, new evidence added")
    if name == "web_search":
        return f'Web search: {a.get("query", "")}'
    if name == "list_connectors":
        return "Read the connectors it can use"
    if name == "ad_query":
        return f'Active Directory: {a.get("query", "").replace("_", " ")}'
    if name == "linux_check":
        return f'{a.get("host")}: {a.get("check", "").replace("_", " ")}'
    if name == "linux_vulnerable_packages":
        return f'{a.get("host")}: packages against OSV'
    if name == "graph_get":
        return f'Microsoft 365: {a.get("path")}'
    if name == "windows_check":
        return f'{a.get("host")}: {a.get("check", "").replace("_", " ")}'
    if name == "synology_info":
        return "Synology: DSM version and updates"
    if name == "proxmox_get":
        return f'Proxmox: {a.get("path")}'
    if name == "list_findings":
        return "Read the findings" + (f' of {a["layer"]}' if a.get("layer") else "")
    if name == "finding_details":
        return f'Read finding {a.get("id")}'
    if name == "epss_lookup":
        return f'EPSS lookup: {len(a.get("cves", []))} CVEs'
    if name == "kev_details":
        return f'CISA KEV lookup: {len(a.get("cves", []))} CVEs'
    if name == "set_priority":
        return f'{a.get("id")} → priority {a.get("priority")}'
    if name == "merge_findings":
        return f'Merged {", ".join(a.get("duplicates", []))} into {a.get("keep")}'
    if name == "set_criticality":
        return f'{a.get("ip")} is {a.get("level")} criticality'
    if name == "previous_findings":
        return "Read the previous assessment's findings"
    if name == "link_previous":
        return f'{a.get("id")} is the same issue as {a.get("previous_id")} last time'
    if name == "record_path":
        return f'Attack path: {a.get("title")}'
    if name == "control_catalog":
        return f'Read the {a.get("framework")} controls'
    if name == "set_controls":
        return f'{a.get("framework")}: set {len(a.get("items", []))} controls'
    return name.replace("_", " ")


# checks that touch the network or the internet (drawn as a pulse on the map); the rest only read the run's data
ACTIVE = {"probe", "http_get", "tls_inspect", "cve_lookup", "eol_lookup", "web_search", "epss_lookup", "kev_details",
          "ad_query", "linux_check", "linux_vulnerable_packages", "synology_info", "proxmox_get",
          "graph_get", "windows_check"}
