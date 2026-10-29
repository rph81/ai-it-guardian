"""Tools the agents can call. Every tool is read-only and scope-checked.

Agents never get a shell. Active probes are limited to an allowlist of nmap
NSE scripts from the "safe"/"discovery" categories, and HTTP is GET/HEAD only
to in-scope LAN addresses.
"""
import json
import os
import subprocess
import threading
import time
import urllib.parse
import urllib.request

from . import netutil
from .collector import parse_nmap_xml
from .graph import SEVERITIES

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
                _kev = {v["cveID"]: v.get("vulnerabilityName") for v in data["vulnerabilities"]}
            except Exception:
                _kev = {}
        return _kev


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
    return name.replace("_", " ")


# checks that touch the network or the internet (drawn as a pulse on the map); the rest only read the run's data
ACTIVE = {"probe", "http_get", "tls_inspect", "cve_lookup", "eol_lookup", "web_search"}
