"""Connectors: read-only accounts that let Guardian look inside systems the scan can only see from outside.

CATALOG describes every connector type (fields, setup steps, what it checks).
suggest() reads the latest scan and proposes connectors for what it found.
Store keeps configured connectors in console/connectors.json with secrets encrypted.
test() signs in with a connector and confirms the account works and can't change anything.
"""
import hashlib
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path

# -- catalog --------------------------------------------------------------------------
F = lambda name, label, kind="text", **kw: {"name": name, "label": label, "kind": kind, **kw}
HOST = F("host", "Address", placeholder="192.168.1.10", mono=True)
VERIFY = F("verify_tls", "Verify the certificate", "checkbox", default=False,
           help="Leave off for self-signed certificates: Guardian then pins the certificate it sees on the first test.")

CATALOG = {
    "synology": {
        "label": "Synology DSM", "icon": "DSM", "color": "#0ea5e9", "category": "Infrastructure & storage",
        "status": "available", "multi": True,
        "summary": "Synology NAS", "checks": "DSM version and update channel, 2-factor, admin accounts, open shares, snapshots, firewall, auto-block.",
        "steps": ["On the NAS: Control Panel > User & Group > Create a user called guardian-ro.",
                  "Don't add it to administrators. Give it no share access and deny all applications except DSM.",
                  "Paste its name and password below. The test warns you if the account has admin rights."],
        "fields": [HOST, F("port", "Port", "number", default=5001, mono=True), F("username", "Username", default="guardian-ro", mono=True),
                   F("password", "Password", "password", secret=True), VERIFY],
    },
    "proxmox_ve": {
        "label": "Proxmox VE", "icon": "PVE", "color": "#e57000", "category": "Infrastructure & storage",
        "status": "available", "multi": True,
        "summary": "Proxmox hypervisor", "checks": "Host and guest versions, VMs and containers, backup jobs, exposed consoles, API tokens.",
        "steps": ["Datacenter > Permissions > Users > Add: user guardian, realm pve (no password needed).",
                  "Datacenter > Permissions > API Tokens > Add: user guardian@pve, token ID read, privilege separation off.",
                  "Datacenter > Permissions > Add > User Permission: path /, user guardian@pve, role PVEAuditor (read-only).",
                  "Paste the token ID and secret below."],
        "fields": [HOST, F("port", "Port", "number", default=8006, mono=True),
                   F("token_id", "Token ID", default="guardian@pve!read", mono=True),
                   F("token_secret", "Token secret", "password", secret=True), VERIFY],
    },
    "proxmox_bs": {
        "label": "Proxmox Backup Server", "icon": "PBS", "color": "#e57000", "category": "Infrastructure & storage",
        "status": "available", "multi": True,
        "summary": "Proxmox backups", "checks": "Last successful backup per machine, verify jobs, retention, encryption.",
        "steps": ["Configuration > Access Control > User Management > Add: user guardian, realm pbs.",
                  "API Token tab > Add: user guardian@pbs, token name read.",
                  "Permissions tab > Add > API Token Permission: path /, token guardian@pbs!read, role Audit (read-only).",
                  "Paste the token ID and secret below."],
        "fields": [HOST, F("port", "Port", "number", default=8007, mono=True),
                   F("token_id", "Token ID", default="guardian@pbs!read", mono=True),
                   F("token_secret", "Token secret", "password", secret=True), VERIFY],
    },
    "home_assistant": {
        "label": "Home Assistant", "icon": "HA", "color": "#18bcf2", "category": "Infrastructure & storage",
        "status": "available", "multi": True,
        "summary": "Smart-home hub", "checks": "Version, users, integrations with cloud access, remote access settings.",
        "steps": ["Settings > People > Add person guardian, allow login, and leave 'Administrator' off.",
                  "Sign in as guardian, open your profile > Security > Long-lived access tokens > Create token.",
                  "Paste the token below. Home Assistant tokens have the user's rights, which is why the user must not be an administrator."],
        "fields": [F("url", "Address", placeholder="http://192.168.1.89", mono=True),
                   F("token", "Access token", "password", secret=True), VERIFY],
    },
    "linux_ssh": {
        "label": "Linux servers (SSH)", "icon": "SSH", "color": "#475569", "category": "Endpoints & network",
        "status": "available", "multi": True,
        "summary": "Linux hosts", "checks": "Used by the Patch & configuration agent: pending security updates, vulnerable packages (OSV), reboot needed, SSH, firewall, users, hardening. One key covers several hosts.",
        "steps": ["On each server: adduser --disabled-password guardian (no sudo, no extra groups).",
                  "Put Guardian's public key (below) in /home/guardian/.ssh/authorized_keys.",
                  "List the servers below, one per line. The test warns you if the account can use sudo."],
        "fields": [F("hosts", "Servers (one per line)", "textarea", mono=True, placeholder="192.168.1.57\n192.168.1.80"),
                   F("username", "Username", default="guardian", mono=True), F("port", "Port", "number", default=22, mono=True)],
        "uses_guardian_key": True,
    },
    "snmp": {
        "label": "Switches & firewalls (SNMPv3)", "icon": "SNMP", "color": "#7c3aed", "category": "Endpoints & network",
        "status": "available", "multi": True,
        "summary": "Network devices", "checks": "Firmware versions, port configuration, which devices sit on which port.",
        "steps": ["On the switch: enable SNMPv3 and create a read-only user (authPriv, SHA + AES).",
                  "Don't enable SNMPv1/v2c, or use a non-default community if the device only supports those.",
                  "List the devices below, one per line, with the user's details."],
        "fields": [F("hosts", "Devices (one per line)", "textarea", mono=True),
                   F("username", "SNMPv3 user", mono=True),
                   F("auth_protocol", "Authentication", "select", options=["SHA", "SHA-256", "MD5"], default="SHA"),
                   F("auth_password", "Authentication password", "password", secret=True),
                   F("priv_protocol", "Encryption", "select", options=["AES", "DES"], default="AES"),
                   F("priv_password", "Encryption password", "password", secret=True)],
    },
    "active_directory": {
        "label": "Active Directory", "icon": "AD", "color": "#2563eb", "category": "Identity & productivity",
        "status": "available", "multi": True, "always": True,
        "summary": "Windows domain", "checks": "Used by the Active Directory agent: admin accounts, Kerberoastable and AS-REP roastable accounts, delegation, password and lockout policy, krbtgt age, stale accounts, LAPS, trusts.",
        "steps": ["Create a normal domain user, e.g. svc-guardian. Domain Users membership is enough to read the directory.",
                  "Set its password not to expire, or note the date: Guardian shows when it's due.",
                  "Use LDAPS (port 636) so the password is encrypted on the network."],
        "fields": [F("domain", "Domain", placeholder="corp.example.local", mono=True),
                   F("host", "Domain controller", placeholder="dc1.corp.example.local", mono=True),
                   F("port", "Port", "number", default=636, mono=True),
                   F("username", "Username", placeholder="svc-guardian", mono=True),
                   F("password", "Password", "password", secret=True), VERIFY],
    },
    "email_domain": {
        "label": "Email domain (DNS)", "icon": "@", "color": "#0f766e", "category": "Identity & productivity",
        "status": "available", "multi": True, "always": True,
        "summary": "Mail spoofing protection", "checks": "SPF, DKIM, DMARC and MX records: protection against spoofed e-mail.",
        "steps": ["No account needed: these are public DNS records.",
                  "Enter the domain you send e-mail from."],
        "fields": [F("domain", "Domain", placeholder="example.com", mono=True),
                   F("dkim_selectors", "DKIM selectors (optional)", placeholder="selector1, google", mono=True)],
    },
    "m365": {
        "label": "Microsoft 365 / Entra ID", "icon": "M365", "color": "#0078d4", "category": "Identity & productivity",
        "status": "available", "multi": True, "always": True,
        "summary": "Cloud identity, mail and devices",
        "checks": "Used by the Microsoft 365 & Entra ID agent (MFA, admins, Conditional Access, legacy sign-in, guests, app "
                  "consents, mail forwarding, Secure Score) and the Device fleet agent (Intune compliance, encryption, "
                  "updates, Defender alerts).",
        "steps": ["Entra admin center › App registrations › New registration: name Guardian, single tenant, no redirect URI.",
                  "API permissions › Add › Microsoft Graph › Application permissions, all read-only: Organization.Read.All, "
                  "Directory.Read.All, Policy.Read.All, RoleManagement.Read.Directory, User.Read.All, Application.Read.All, "
                  "AuditLog.Read.All, Reports.Read.All, SecurityEvents.Read.All, SecurityAlert.Read.All, MailboxSettings.Read, "
                  "DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All. Then Grant admin consent.",
                  "Certificates & secrets › New client secret (e.g. 12 months). Copy the value now: it's shown once.",
                  "Paste the tenant ID, the application (client) ID and the secret below. The test warns you if the app "
                  "has any permission that can change things."],
        "fields": [F("tenant_id", "Tenant ID", placeholder="00000000-0000-0000-0000-000000000000", mono=True),
                   F("client_id", "Application (client) ID", mono=True),
                   F("client_secret", "Client secret", "password", secret=True)],
    },
    "azure": {
        "label": "Microsoft Azure", "icon": "AZ", "color": "#0089d6", "category": "Cloud",
        "status": "available", "multi": True, "always": True,
        "summary": "Cloud subscriptions",
        "checks": "Used by the Azure agent: Defender for Cloud score, plans and recommendations, internet exposure, network "
                  "security groups, storage, databases, Key Vault, VMs and disks, role assignments, logging, backup, policy.",
        "steps": ["Entra admin center › App registrations › New registration: name Guardian-Azure-Reader, single tenant, no "
                  "redirect URI. Use a separate app from the Microsoft 365 one, with no Microsoft Graph permissions.",
                  "Certificates & secrets › New client secret (e.g. 12 months). Copy the value now: it's shown once.",
                  "Azure portal › Subscriptions (or a management group above them) › Access control (IAM) › Add role "
                  "assignment: Reader, then again Security Reader, both for Guardian-Azure-Reader. Nothing else.",
                  "Paste the tenant ID, the application (client) ID and the secret below. Optionally limit Guardian to some "
                  "subscription IDs. The test lists the subscriptions it can see and warns if the app has any other role."],
        "fields": [F("tenant_id", "Tenant ID", placeholder="00000000-0000-0000-0000-000000000000", mono=True),
                   F("client_id", "Application (client) ID", mono=True),
                   F("client_secret", "Client secret", "password", secret=True),
                   F("subscriptions", "Only these subscription IDs (optional, space-separated)", mono=True)],
    },
    "ninjaone": {
        "label": "NinjaOne (RMM)", "icon": "N1", "color": "#2b6cb0", "category": "Endpoints & network",
        "status": "available", "multi": False, "always": True,
        "summary": "Patch and device status from your RMM",
        "checks": "Used by the Patch & configuration agent: managed devices (also off the office network), pending and "
                  "failed OS and software patches, antivirus status, device health. Read-only; patch jobs use separate "
                  "credentials on the Fix page.",
        "steps": ["NinjaOne › Administration › Apps › API › Client app IDs › Add: application platform 'API Services "
                  "(machine-to-machine)', name Guardian-Read, scope Monitoring only, grant type Client credentials.",
                  "Copy the client ID and the client secret (shown once).",
                  "Region: app (US), eu, oc, ca or us2: the start of your NinjaOne address, e.g. eu.ninjarmm.com → eu."],
        "fields": [F("region", "Region", placeholder="eu", mono=True, default="eu"),
                   F("client_id", "Client ID", mono=True),
                   F("client_secret", "Client secret", "password", secret=True)],
    },
    "google_workspace": {"label": "Google Workspace", "icon": "GW", "color": "#34a853", "category": "Identity & productivity",
                         "status": "planned", "always": True, "summary": "Cloud identity", "checks": "2-step verification, admins, sharing settings, third-party apps."},
    "vmware": {"label": "VMware vSphere / ESXi", "icon": "VM", "color": "#5b7f3a", "category": "Infrastructure & storage",
               "status": "planned", "summary": "Hypervisor", "checks": "Host versions, VM inventory, exposed services."},
    "docker": {"label": "Docker / Kubernetes", "icon": "D", "color": "#1d63ed", "category": "Infrastructure & storage",
               "status": "planned", "summary": "Containers", "checks": "Exposed APIs, outdated images, containers running as root."},
    "windows": {
        "label": "Windows (WinRM)", "icon": "WIN", "color": "#0284c7", "category": "Endpoints & network",
        "status": "available", "multi": True,
        "summary": "Windows PCs and servers",
        "checks": "Used by the Patch & configuration agent: OS build and installed updates, pending reboot, Defender, "
                  "firewall, BitLocker, local admins, SMB, RDP, UAC and LSA settings, installed software.",
        "steps": ["Create a normal domain or local user, e.g. svc-guardian (not an administrator).",
                  "Add it to the local group 'Remote Management Users' on each machine (a Group Policy can do this for many).",
                  "Make sure WinRM over HTTPS (port 5986) is on: winrm quickconfig -transport:https, or by Group Policy.",
                  "List the machines below. Some checks (BitLocker) need more rights and are reported as 'not readable'."],
        "fields": [F("hosts", "Machines (one per line)", "textarea", mono=True, placeholder="192.168.1.20\nsrv-files.corp.local"),
                   F("username", "Username", placeholder="CORP\\svc-guardian", mono=True),
                   F("password", "Password", "password", secret=True),
                   F("port", "Port", "number", default=5986, mono=True), VERIFY],
    },
    "firewall": {"label": "Firewall API (pfSense, OPNsense, FortiGate, UniFi)", "icon": "FW", "color": "#dc2626",
                 "category": "Endpoints & network", "status": "planned", "summary": "Firewalls", "checks": "Rules, firmware, VPN settings."},
}


def public_catalog():
    return {k: {kk: vv for kk, vv in v.items()} for k, v in CATALOG.items()}


# -- suggestions ------------------------------------------------------------------------
def _ports(asset):
    return [p for p in asset.get("ports", []) if p.get("state") == "open"]


def _titles(asset):
    out = []
    for p in _ports(asset):
        h = p.get("http") if isinstance(p.get("http"), dict) else {}
        t = p.get("tls") if isinstance(p.get("tls"), dict) else {}
        out.append((p["port"], (h.get("title") or ""), (t.get("subject") or ""), t))
    return out


def _name(asset, fallback):
    up = asset.get("upnp") or {}
    n = (up.get("friendlyName") or "").split("(")[0].strip()
    return n or asset.get("hostname") or fallback


def _domains(graph):
    """Organisation domains: seen in certificates on at least two devices, or in the public hostnames.
    A domain on one device only is usually the vendor's built-in certificate (e.g. tplinkrepeater.net)."""
    skip = ("synology.me", "datazug.ch", "local", "lan", "home.arpa", "example.com")
    hosts, names = {}, {}
    for ip, a in graph.get("assets", {}).items():
        for _, _, subject, _ in _titles(a):
            m = re.search(r"CN=([A-Za-z0-9.-]+\.[A-Za-z]{2,})", subject)
            if m:
                d = ".".join(m.group(1).lower().split(".")[-2:])
                hosts.setdefault(d, set()).add(ip)
                names.setdefault(d, set()).add(m.group(1).lower())
    public = {".".join(h.lower().split(".")[-2:]) for h in (graph.get("wan", {}).get("internetdb") or {}).get("hostnames", [])}
    return {d: names[d] for d in names
            if not any(d.endswith(s) for s in skip) and (len(hosts[d]) >= 2 or d in public)}


def suggest(graph, store):
    """Connector suggestions for the latest scan, minus configured and dismissed ones."""
    assets = graph.get("assets", {}) if graph else {}
    configured_hosts = store.configured_targets()
    new_macs = store.new_devices(graph) if graph else set()
    out = []

    def add(key, ctype, title, hosts, why, prefill, macs=()):
        if key in store.dismissed:
            return
        if all(h in configured_hosts.get(ctype, set()) for h in hosts):
            return
        out.append({"key": key, "type": ctype, "title": title, "hosts": hosts, "why": why, "prefill": prefill,
                    "new": any(m in new_macs for m in macs),
                    "findings": sum(1 for f in graph.get("findings", []) if f.get("asset") in hosts)})

    linux, switches = [], []
    for ip, a in sorted(assets.items(), key=lambda kv: tuple(map(int, kv[0].split(".")))):
        mac = a.get("mac", "")
        vendor = f'{a.get("mac_vendor", "")} {(a.get("upnp") or {}).get("manufacturer", "")} {a.get("vendor", "")}'.lower()
        titles = _titles(a)
        ports = {p["port"] for p in _ports(a) if p["proto"] == "tcp"}
        model = (a.get("upnp") or {}).get("modelName") or a.get("model") or ""
        if "synology" in vendor and ports & {5000, 5001}:
            port = 5001 if 5001 in ports else 5000
            add(f"synology:{mac}", "synology", f"Synology DSM · {_name(a, ip)}", [ip],
                f"{model or 'Synology NAS'} at {ip}", {"name": _name(a, ip), "host": ip, "port": port}, [mac])
        elif any("Proxmox Virtual Environment" in t or "PVE Cluster Node" in s for _, t, s, _ in titles):
            add(f"proxmox_ve:{mac}", "proxmox_ve", f"Proxmox VE · {ip}", [ip], f"Proxmox VE web interface on {ip}:8006",
                {"name": "Proxmox VE", "host": ip, "port": 8006}, [mac])
        elif any("Proxmox Backup Server" in t or "Proxmox Backup Server" in s for _, t, s, _ in titles):
            add(f"proxmox_bs:{mac}", "proxmox_bs", f"Proxmox Backup Server · {ip}", [ip], f"Backup server web interface on {ip}:8007",
                {"name": "Proxmox Backup Server", "host": ip, "port": 8007}, [mac])
        if any(t == "Home Assistant" for _, t, _, _ in titles):
            port, scheme = next(((p, "https" if tls else "http") for p, t, _, tls in titles if t == "Home Assistant"), (80, "http"))
            add(f"home_assistant:{mac}", "home_assistant", f"Home Assistant · {ip}", [ip], f"Home Assistant on {ip}:{port}",
                {"name": "Home Assistant", "url": f"{scheme}://{ip}" + ("" if port in (80, 443) else f":{port}")}, [mac])
        ssh = next((p for p in _ports(a) if p["port"] == 22 and p["proto"] == "tcp"), None)
        if ssh and re.search(r"debian|ubuntu|rhel|centos|fedora|alpine", f'{ssh.get("version", "")} {ssh.get("extrainfo", "")}', re.I):
            linux.append((ip, mac))
        if a.get("device_type") == "switch" or re.search(r"switch", " ".join(t for _, t, _, _ in titles) + model + (a.get("os_guess") or ""), re.I):
            switches.append((ip, mac))
    if linux:
        hosts = [ip for ip, _ in linux]
        add("linux_ssh:site", "linux_ssh", "Linux servers (SSH)", hosts, f"{len(hosts)} hosts running Debian-family Linux",
            {"name": "Linux servers", "hosts": "\n".join(hosts)}, [m for _, m in linux])
    if switches:
        hosts = [ip for ip, _ in switches]
        add("snmp:site", "snmp", "Network switches (SNMP)", hosts, f"{len(hosts)} managed switch{'es' if len(hosts) > 1 else ''}",
            {"name": "Switches", "hosts": "\n".join(hosts)}, [m for _, m in switches])
    for d, names in sorted(_domains(graph or {}).items()):
        add(f"email_domain:{d}", "email_domain", f"Email domain · {d}", [d],
            f"Your devices use {d} ({', '.join(sorted(names)[:3])}). Check that nobody can send e-mail pretending to be it.",
            {"name": d, "domain": d})
    return out


def no_connector_count(graph, suggestions):
    covered = {h for s in suggestions for h in s["hosts"]}
    return sum(1 for ip in (graph or {}).get("assets", {}) if ip not in covered)


# -- storage ------------------------------------------------------------------------------
class Store:
    """Connectors are encrypted records in the vault (readable only while it is unlocked).
    Suggestion bookkeeping (dismissed suggestions, device inventory) is plain metadata."""

    def __init__(self, vault, state_dir):
        self.v = vault
        self.dir = Path(state_dir)

    @property
    def dismissed(self):
        return self.v.get("dismissed", [])

    def set_dismissed(self, items):
        self.v.put("dismissed", items)

    def connectors(self):
        return self.v.load_records("connector") if self.v.unlocked else []

    def get(self, cid):
        return next((c for c in self.connectors() if c["id"] == cid), None)

    def save_connector(self, c):
        self.v.save_record(c["id"], "connector", c)

    def delete(self, cid):
        self.v.delete_record(cid)

    def public(self, c):
        """A connector as the browser may see it: secrets replaced by a 'set' flag."""
        spec = CATALOG[c["type"]]
        out = {k: v for k, v in c.items() if k not in ("secrets", "pin")}
        out["secrets_set"] = {f["name"]: bool(c.get("secrets", {}).get(f["name"])) for f in spec["fields"] if f.get("secret")}
        return out

    @staticmethod
    def fields_with_secrets(c):
        return {**c["fields"], **c.get("secrets", {})}

    def configured_targets(self):
        out = {}
        for c in self.connectors():
            f = c["fields"]
            hosts = set(filter(None, (f.get("hosts") or "").split())) | {f.get("host"), f.get("domain")}
            if f.get("url"):
                hosts.add(urllib.parse.urlparse(f["url"]).hostname)
            out.setdefault(c["type"], set()).update(h for h in hosts if h)
        return out

    # device inventory: remembers every MAC seen, so a device first seen in the latest scan is "new"
    def update_inventory(self, run_id, graph):
        runs = self.v.get("inventory_runs", [])
        if not graph or run_id in runs:
            return
        inv = self.v.get("inventory", {})
        first = not runs
        for ip, a in graph.get("assets", {}).items():
            mac = a.get("mac")
            if mac and mac not in inv:
                inv[mac] = {"first_seen": run_id, "ip": ip, "baseline": first}
        self.v.put("inventory", inv)
        self.v.put("inventory_runs", runs + [run_id])

    def new_devices(self, graph):
        runs = self.v.get("inventory_runs", [])
        last = runs[-1] if runs else None
        return {m for m, v in self.v.get("inventory", {}).items() if v["first_seen"] == last and not v.get("baseline")}


# -- connection tests -------------------------------------------------------------------
class Result(Exception):
    def __init__(self, level, message, details=None):
        super().__init__(message)
        self.level, self.message, self.details = level, message, details or []


def _fingerprint(host, port):
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((host, int(port)), timeout=8) as s, ctx.wrap_socket(s, server_hostname=host) as t:
        return hashlib.sha256(t.getpeercert(binary_form=True)).hexdigest()


def _tls_context(host, port, verify, pin):
    """Verified context, or an unverified one bound to a pinned certificate fingerprint. Returns (ctx, pin)."""
    if verify:
        return ssl.create_default_context(), pin
    seen = _fingerprint(host, port)
    if pin and pin != seen:
        raise Result("error", "The device's certificate has changed since it was first trusted. "
                              "If you replaced it, remove and re-add this connector.")
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    return ctx, seen


def _http(url, ctx=None, headers=None, data=None, timeout=12):
    req = urllib.request.Request(url, headers={"User-Agent": "ai-guardian", **(headers or {})},
                                 data=urllib.parse.urlencode(data).encode() if data else None)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode() or "null")
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(body)
        except ValueError:
            return e.code, body[:200]
    except (urllib.error.URLError, socket.timeout, ConnectionError) as e:
        raise Result("error", f"Can't reach it: {getattr(e, 'reason', e)}")


def _done(level, message, details=None, pin=None):
    return level, message, details or [], pin


def _test_synology(f, pin):
    host, port = f["host"], int(f.get("port") or 5001)
    scheme = "https" if port in (5001, 443) else "http"
    if scheme == "http":
        ctx, pin = None, None
    else:
        ctx, pin = _tls_context(host, port, f.get("verify_tls"), pin)
    base = f"{scheme}://{host}:{port}/webapi/entry.cgi"
    st, r = _http(base, ctx, data={"api": "SYNO.API.Auth", "version": "6", "method": "login", "account": f["username"],
                                   "passwd": f["password"], "session": "guardian", "format": "sid"})
    if not isinstance(r, dict) or not r.get("success"):
        code = (r or {}).get("error", {}).get("code") if isinstance(r, dict) else st
        hint = {400: "wrong username or password", 401: "account disabled", 403: "2-factor is on for this account; turn it off for guardian-ro",
                407: "this address is blocked by auto-block"}.get(code, f"error {code}")
        raise Result("error", f"Sign-in failed: {hint}")
    sid = r["data"]["sid"]
    details, level = [], "ok"
    try:
        _, info = _http(f"{base}?api=SYNO.DSM.Info&version=2&method=getinfo&_sid={sid}", ctx)
        d = (info or {}).get("data", {}) if isinstance(info, dict) else {}
        version = d.get("version_string") or d.get("version") or "unknown"
        details.append(f"DSM {version} on {d.get('model', 'unknown model')}")
        # an admin-only API: if it answers, the account has admin rights
        _, adm = _http(f"{base}?api=SYNO.Core.System&version=1&method=info&_sid={sid}", ctx)
        if isinstance(adm, dict) and adm.get("success"):
            level = "warn"
            details.append("This account has administrator rights. Use a normal user so Guardian can only read.")
        else:
            details.append("Account is not an administrator")
    finally:
        _http(f"{base}?api=SYNO.API.Auth&version=6&method=logout&session=guardian&_sid={sid}", ctx)
    if scheme == "http":
        level = "warn" if level == "ok" else level
        details.append("Connected over plain HTTP: use port 5001 so the password is encrypted.")
    return _done(level, "Connected" if level == "ok" else "Connected, with a warning", details, pin=pin)


WRITE_PRIVS = re.compile(r"\.(Allocate|Modify|PowerMgmt|Console|Config|Migrate|Snapshot|Backup|Clone|Prune|Remove|Delete)", re.I)


def _test_proxmox(f, pin, kind):
    host, port = f["host"], int(f.get("port") or (8006 if kind == "ve" else 8007))
    ctx, pin = _tls_context(host, port, f.get("verify_tls"), pin)
    prefix = "PVEAPIToken" if kind == "ve" else "PBSAPIToken"
    sep = "=" if kind == "ve" else ":"
    auth = {"Authorization": f'{prefix}={f["token_id"]}{sep}{f["token_secret"]}'}
    base = f"https://{host}:{port}/api2/json"
    st, v = _http(f"{base}/version", ctx, auth)
    if st != 200:
        raise Result("error", "The token was refused: check the token ID and secret." if st == 401 else f"Error {st}: {str(v)[:120]}")
    ver = (v or {}).get("data", {})
    name = "Proxmox VE" if kind == "ve" else "Proxmox Backup Server"
    details = [f"{name} {ver.get('version', '')}{('-' + ver['release']) if kind == 'pbs' and ver.get('release') else ''}".strip()]
    _, perms = _http(f"{base}/access/permissions", ctx, auth)
    privs = set()
    for path, p in ((perms or {}).get("data") or {}).items() if isinstance(perms, dict) else []:
        privs |= {k for k, on in (p or {}).items() if on}
    writes = sorted(p for p in privs if WRITE_PRIVS.search(p))
    if writes:
        details.append("The token can change things: " + ", ".join(writes[:6]) + ("…" if len(writes) > 6 else "")
                       + ". Give it only the read-only role " + ("PVEAuditor." if kind == "ve" else "Audit."))
        return _done("warn", "Connected, with a warning", details, pin=pin)
    details.append(f"Token is read-only ({len(privs)} read permissions)")
    return _done("ok", "Connected", details, pin=pin)


def _test_home_assistant(f, pin):
    url = f["url"].rstrip("/")
    u = urllib.parse.urlparse(url)
    ctx = None
    if u.scheme == "https":
        ctx, pin = _tls_context(u.hostname, u.port or 443, f.get("verify_tls"), pin)
    auth = {"Authorization": f'Bearer {f["token"]}'}
    st, cfg = _http(f"{url}/api/config", ctx, auth)
    if st == 401:
        raise Result("error", "The token was refused.")
    if st != 200 or not isinstance(cfg, dict):
        raise Result("error", f"Unexpected answer ({st}). Check the address.")
    details = [f"Home Assistant {cfg.get('version', '')}, location '{cfg.get('location_name', '')}'"]
    level = "ok"
    if u.scheme == "http":
        level = "warn"
        details.append("Connected over plain HTTP: the token crosses the network unencrypted.")
    details.append("Make sure the guardian user is not an administrator: Home Assistant can't report this to Guardian.")
    return _done(level, "Connected" if level == "ok" else "Connected, with a warning", details, pin=pin)


def guardian_ssh_key(vault):
    """Guardian's own SSH key. The private half is a vault record; only the public half is plain metadata."""
    pub = vault.get("ssh_public_key")
    if pub:
        return pub
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode() + " ai-guardian"
    vault.save_record("ssh-key", "secret", {"private": private})
    vault.put("ssh_public_key", pub)
    return pub


class ssh_key_file:
    """The private key written to a RAM-backed file for the duration of one ssh call, then removed."""

    def __init__(self, vault):
        self.vault = vault

    def __enter__(self):
        import tempfile
        rec = next((r for r in self.vault.load_records("secret") if "private" in r), None)
        if not rec:
            raise Result("error", "Guardian's SSH key is missing: open the Linux connector to create it.")
        tmpdir = "/dev/shm" if os.path.isdir("/dev/shm") else None
        fd, self.path = tempfile.mkstemp(prefix="guardian-", dir=tmpdir)
        os.write(fd, rec["private"].encode())
        os.close(fd)
        os.chmod(self.path, 0o600)
        return self.path

    def __exit__(self, *exc):
        try:
            with open(self.path, "r+b") as f:
                f.write(b"\0" * os.path.getsize(self.path))
        finally:
            os.unlink(self.path)


def _test_linux_ssh(f, state_dir, key):
    (Path(state_dir) / "ssh").mkdir(mode=0o700, exist_ok=True)
    known = Path(state_dir) / "ssh" / "known_hosts"
    hosts = [h for h in (f.get("hosts") or "").split() if h]
    if not hosts:
        raise Result("error", "Add at least one server.")
    details, worst = [], "ok"
    for h in hosts:
        cmd = ["ssh", "-i", str(key), "-p", str(int(f.get("port") or 22)), "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
               "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={known}",
               f'{f.get("username") or "guardian"}@{h}',
               'echo "uid=$(id -u)"; . /etc/os-release 2>/dev/null; echo "os=$PRETTY_NAME"; sudo -n true 2>/dev/null && echo sudo=yes || echo sudo=no']
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        except subprocess.TimeoutExpired:
            details.append(f"{h}: timed out")
            worst = "error"
            continue
        if r.returncode != 0:
            err = (r.stderr.strip().splitlines() or ["unknown error"])[-1]
            if "Permission denied" in err:
                err = "key not accepted (is Guardian's public key in authorized_keys?)"
            elif "REMOTE HOST IDENTIFICATION HAS CHANGED" in r.stderr:
                err = "the server's host key changed since it was first trusted"
            details.append(f"{h}: {err}")
            worst = "error"
            continue
        out = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
        msg = f"{h}: {out.get('os', 'connected')}"
        if out.get("uid") == "0" or out.get("sudo") == "yes":
            msg += " · this account is root or has passwordless sudo; use a normal user"
            worst = "warn" if worst == "ok" else worst
        details.append(msg)
    ok = sum(1 for d in details if ": " in d and "key not accepted" not in d and "timed out" not in d and "changed" not in d)
    msg = {"ok": f"Connected to {len(hosts)} server{'s' if len(hosts) > 1 else ''}",
           "warn": "Connected, with a warning", "error": f"{ok} of {len(hosts)} servers connected"}[worst]
    return _done(worst, msg, details)


def _test_snmp(f):
    hosts = [h for h in (f.get("hosts") or "").split() if h]
    if not hosts:
        raise Result("error", "Add at least one device.")
    details, worst = [], "ok"
    for h in hosts:
        cmd = ["snmpget", "-v3", "-l", "authPriv", "-u", f["username"], "-a", f.get("auth_protocol") or "SHA",
               "-A", f["auth_password"], "-x", f.get("priv_protocol") or "AES", "-X", f["priv_password"],
               "-t", "4", "-r", "1", "-Oqv", h, "1.3.6.1.2.1.1.1.0"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except FileNotFoundError:
            raise Result("error", "The SNMP tools aren't installed in the container (apt install snmp).")
        except subprocess.TimeoutExpired:
            r = None
        if r and r.returncode == 0 and r.stdout.strip():
            details.append(f"{h}: {r.stdout.strip().strip(chr(34))[:120]}")
        else:
            details.append(f"{h}: no answer (SNMPv3 not enabled, or wrong user/passwords)")
            worst = "error"
    return _done(worst, "Connected" if worst == "ok" else "Some devices didn't answer", details)


def _test_ad(f, pin):
    try:
        import ldap3
    except ImportError:
        raise Result("error", "The LDAP library isn't installed in the container.")
    host, port = f["host"], int(f.get("port") or 636)
    use_ssl = port == 636
    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED if f.get("verify_tls") else ssl.CERT_NONE)
    if use_ssl and not f.get("verify_tls"):
        _, pin = _tls_context(host, port, False, pin)
    server = ldap3.Server(host, port=port, use_ssl=use_ssl, tls=tls, get_info=ldap3.DSA, connect_timeout=8)
    user = f["username"] if "@" in f["username"] or "\\" in f["username"] else f'{f["username"]}@{f["domain"]}'
    conn = ldap3.Connection(server, user=user, password=f["password"], receive_timeout=10)
    try:
        if not use_ssl:
            conn.open()
            conn.start_tls()
        if not conn.bind():
            raise Result("error", f"Sign-in failed: {conn.result.get('description', 'invalid credentials')}")
        info = server.info
        nc = (info.other.get("defaultNamingContext") or [""])[0] if info else ""
        level = (info.other.get("domainFunctionality") or ["?"])[0] if info else "?"
        conn.search(nc, f"(sAMAccountName={ldap3.utils.conv.escape_filter_chars(f['username'].split('@')[0].split(chr(92))[-1])})",
                    attributes=["memberOf"])
        groups = [str(g) for e in conn.entries for g in e.memberOf] if conn.entries else []
        details = [f"Domain {nc}, functional level {level}"]
        if any(re.search(r"CN=(Domain Admins|Enterprise Admins|Administrators|Account Operators)", g, re.I) for g in groups):
            return _done("warn", "Connected, with a warning", details + ["This account is in an admin group. Use a normal domain user."], pin=pin)
        return _done("ok", "Connected", details + ["Account is not in an admin group"], pin=pin)
    except ldap3.core.exceptions.LDAPException as e:
        raise Result("error", f"Can't connect: {e}")
    finally:
        conn.unbind()


def _test_email(f):
    try:
        import dns.resolver
    except ImportError:
        raise Result("error", "The DNS library isn't installed in the container.")
    d = f["domain"].strip().lower()
    res = dns.resolver.Resolver()
    res.lifetime = 6

    def txt(name):
        try:
            return [b"".join(r.strings).decode(errors="replace") for r in res.resolve(name, "TXT")]
        except Exception:                                   # noqa: BLE001 - absent record
            return []
    try:
        mx = sorted(str(r.exchange).rstrip(".") for r in res.resolve(d, "MX"))
    except Exception:                                       # noqa: BLE001
        mx = []
    spf = [t for t in txt(d) if t.lower().startswith("v=spf1")]
    dmarc = [t for t in txt(f"_dmarc.{d}") if t.lower().startswith("v=dmarc1")]
    dkim = []
    for sel in [s.strip() for s in (f.get("dkim_selectors") or "").replace(",", " ").split() if s.strip()]:
        if any("p=" in t for t in txt(f"{sel}._domainkey.{d}")):
            dkim.append(sel)
    details = [f"MX: {', '.join(mx) if mx else 'none (this domain does not receive e-mail)'}",
               f"SPF: {spf[0] if spf else 'missing'}",
               f"DMARC: {dmarc[0] if dmarc else 'missing'}"]
    if f.get("dkim_selectors"):
        details.append(f"DKIM: {', '.join(dkim) + ' found' if dkim else 'no key found for the selectors given'}")
    weak = not spf or not dmarc or (dmarc and re.search(r"p=none", dmarc[0], re.I))
    return _done("warn" if weak else "ok", "Records read" + (": protection is incomplete" if weak else ""), details)


WRITE_GRAPH = re.compile(r"(ReadWrite|\.Write|\.Send|\.Manage|FullControl|\.Create|\.Delete)", re.I)


def graph_token(f, scope="https://graph.microsoft.com/.default"):
    """Client-credentials token for Microsoft Graph (or another Microsoft API scope). Returns (token, roles)."""
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", f.get("tenant_id") or "") or not re.fullmatch(r"[0-9a-fA-F-]{36}", f.get("client_id") or ""):
        raise Result("error", "Tenant ID and client ID are GUIDs like 00000000-0000-0000-0000-000000000000.")
    st, r = _http(f"https://login.microsoftonline.com/{f['tenant_id']}/oauth2/v2.0/token", ssl.create_default_context(),
                  data={"grant_type": "client_credentials", "client_id": f["client_id"], "client_secret": f["client_secret"],
                        "scope": scope})
    if st != 200 or not isinstance(r, dict) or "access_token" not in r:
        msg = (r or {}).get("error_description", "") if isinstance(r, dict) else str(r)
        raise Result("error", "Sign-in refused: " + (msg.split("\r\n")[0][:200] or f"error {st}"))
    import base64
    payload = r["access_token"].split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return r["access_token"], sorted(claims.get("roles") or [])


AZURE_SCOPE = "https://management.azure.com/.default"
AZURE_READ_ROLES = {"Reader", "Security Reader"}
GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def azure_token(f):
    """Token for Azure Resource Manager. Returns (token, object id of the app's service principal)."""
    import base64
    token, _ = graph_token(f, AZURE_SCOPE)
    payload = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return token, claims.get("oid", "")


def azure_subscription_filter(f):
    subs = [x.lower() for x in (f.get("subscriptions") or "").replace(",", " ").split() if x]
    bad = [x for x in subs if not GUID.match(x)]
    if bad:
        raise Result("error", "Subscription IDs are GUIDs: " + ", ".join(bad[:3]))
    return set(subs)


def _test_ninjaone(f):
    from . import fixes
    try:
        host, tok = fixes.ninja_token(f, "monitoring")
    except fixes.Failed as e:
        raise Result("error", str(e))
    st, orgs = _http(f"https://{host}/v2/organizations", ssl.create_default_context(), {"Authorization": f"Bearer {tok}"})
    st2, devs = _http(f"https://{host}/v2/devices?pageSize=1000", ssl.create_default_context(), {"Authorization": f"Bearer {tok}"})
    if st != 200:
        raise Result("error", f"Signed in, but reading organizations failed ({st})")
    details = [f"{len(orgs or [])} organization(s), {len(devs or []) if st2 == 200 else '?'} device(s) visible"]
    return _done("ok", "Connected (monitoring scope)", details)


def _test_azure(f):
    only = azure_subscription_filter(f)
    token, oid = azure_token(f)
    ctx = ssl.create_default_context()
    h = {"Authorization": f"Bearer {token}"}
    st, d = _http("https://management.azure.com/subscriptions?api-version=2022-12-01", ctx, h)
    if st != 200 or not isinstance(d, dict):
        raise Result("error", f"Signed in, but listing subscriptions failed ({st})")
    subs = [x for x in d.get("value", []) if not only or x.get("subscriptionId", "").lower() in only]
    if not subs:
        return _done("warn", "Signed in, but no subscriptions are visible",
                     ["Give the app Reader and Security Reader on your subscriptions (Access control › Add role assignment)."])
    details = [f"{len(subs)} subscription(s): " + ", ".join(f"{x.get('displayName')} ({x.get('state')})" for x in subs[:10])]
    roles, worst = set(), "ok"
    for sub in subs[:20]:
        sid = sub["subscriptionId"]
        st, ra = _http(f"https://management.azure.com/subscriptions/{sid}/providers/Microsoft.Authorization/roleAssignments"
                       f"?api-version=2022-04-01&$filter=assignedTo('{oid}')", ctx, h)
        for a in (ra or {}).get("value", []) if st == 200 and isinstance(ra, dict) else []:
            rid = (a.get("properties") or {}).get("roleDefinitionId", "")
            st2, rd = _http(f"https://management.azure.com{rid}?api-version=2022-04-01", ctx, h)
            if st2 == 200 and isinstance(rd, dict):
                roles.add((rd.get("properties") or {}).get("roleName", rid.rsplit("/", 1)[-1]))
    details.append("Roles: " + (", ".join(sorted(roles)) if roles else "none found (Reader and Security Reader are needed)"))
    extra = sorted(roles - AZURE_READ_ROLES)
    if extra:
        return _done("warn", "Connected, with a warning", details + ["Remove these roles: Guardian only needs Reader and "
                                                                    "Security Reader: " + ", ".join(extra)])
    if "Security Reader" not in roles:
        worst = "warn"
        details.append("Security Reader is missing: Defender for Cloud results will be incomplete.")
    return _done(worst, "Connected" if worst == "ok" else "Connected, with a warning", details + (["All roles are read-only"] if worst == "ok" else []))


def _test_m365(f):
    token, roles = graph_token(f)
    st, org = _http("https://graph.microsoft.com/v1.0/organization?$select=displayName,verifiedDomains", ssl.create_default_context(),
                    {"Authorization": f"Bearer {token}"})
    name = ((org or {}).get("value") or [{}])[0].get("displayName", "your tenant") if isinstance(org, dict) else "your tenant"
    details = [f"Signed in to {name}", f"{len(roles)} application permissions: " + (", ".join(roles) if roles else "none (grant admin consent)")]
    writes = [r for r in roles if WRITE_GRAPH.search(r)]
    if writes:
        return _done("warn", "Connected, with a warning", details + ["These permissions can change things; remove them: " + ", ".join(writes)])
    if not roles:
        return _done("warn", "Connected, but no permissions", details)
    return _done("ok", "Connected", details + ["All permissions are read-only"])


def _test_windows(f):
    try:
        import winrm
    except ImportError:
        raise Result("error", "The WinRM library isn't installed in the container (pip install pywinrm).")
    hosts = [h for h in (f.get("hosts") or "").split() if h]
    if not hosts:
        raise Result("error", "Add at least one machine.")
    details, worst = [], "ok"
    for h in hosts:
        try:
            s = winrm.Session(f"https://{h}:{int(f.get('port') or 5986)}/wsman", auth=(f["username"], f["password"]), transport="ntlm",
                              server_cert_validation="validate" if f.get("verify_tls") else "ignore", operation_timeout_sec=20, read_timeout_sec=30)
            r = s.run_ps("$o=Get-CimInstance Win32_OperatingSystem; \"$($o.Caption) $($o.Version)\"; "
                         "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')")
            out = r.std_out.decode(errors="replace").split()
            if r.status_code != 0:
                details.append(f"{h}: {r.std_err.decode(errors='replace')[:160]}")
                worst = "error"
                continue
            admin = out[-1].lower() == "true" if out else False
            msg = f"{h}: {' '.join(out[:-1])}"
            if admin:
                msg += " · this account is an administrator; use a member of Remote Management Users instead"
                worst = "warn" if worst == "ok" else worst
            details.append(msg)
        except Exception as e:                                       # noqa: BLE001 - reported per machine
            details.append(f"{h}: {str(e)[:160]}")
            worst = "error"
    return _done(worst, {"ok": "Connected", "warn": "Connected, with a warning", "error": "Some machines didn't answer"}[worst], details)


def test(ctype, fields, pin=None, state_dir=None, vault=None):
    """Run a connection test. Returns (level, message, details, pin)."""
    tests = {
        "synology": lambda: _test_synology(fields, pin),
        "proxmox_ve": lambda: _test_proxmox(fields, pin, "ve"),
        "proxmox_bs": lambda: _test_proxmox(fields, pin, "pbs"),
        "home_assistant": lambda: _test_home_assistant(fields, pin),
        "linux_ssh": lambda: _with_ssh_key(vault, lambda key: _test_linux_ssh(fields, state_dir, key)),
        "snmp": lambda: _test_snmp(fields),
        "active_directory": lambda: _test_ad(fields, pin),
        "email_domain": lambda: _test_email(fields),
        "m365": lambda: _test_m365(fields),
        "azure": lambda: _test_azure(fields),
        "ninjaone": lambda: _test_ninjaone(fields),
        "windows": lambda: _test_windows(fields),
    }
    if ctype not in tests:
        return "error", "This connector can't be tested yet.", [], pin
    try:
        level, message, details, new_pin = tests[ctype]()
        return level, message, details, new_pin if new_pin is not None else pin
    except Result as r:
        return r.level, r.message, r.details, pin
    except KeyError as e:
        return "error", f"Missing field: {e.args[0]}", [], pin
    except (OSError, ssl.SSLError) as e:
        return "error", f"Can't connect: {e}", [], pin


def _with_ssh_key(vault, fn):
    with ssh_key_file(vault) as key:
        return fn(key)


def validate(ctype, fields):
    spec = CATALOG.get(ctype)
    if not spec or spec["status"] != "available":
        raise ValueError("This connector type isn't available yet")
    out = {}
    for fd in spec["fields"]:
        v = fields.get(fd["name"], fd.get("default"))
        if fd["kind"] == "checkbox":
            v = bool(v)
        elif fd["kind"] == "number":
            v = int(v) if str(v or "").strip() else fd.get("default")
            if v is not None and not 1 <= v <= 65535:
                raise ValueError(f"{fd['label']} must be a port number")
        elif fd["kind"] == "select":
            v = v if v in fd["options"] else fd.get("default")
        else:
            v = (v or "").strip() if isinstance(v, str) else v
            if v and fd["kind"] != "textarea" and re.search(r"[\r\n]", v):
                raise ValueError(f"{fd['label']} can't contain line breaks")
            if v and len(v) > 4000:
                raise ValueError(f"{fd['label']} is too long")
        out[fd["name"]] = v
    for name in ("host",):
        if out.get(name) and not re.match(r"^[A-Za-z0-9.\-:\[\]]+$", out[name]):
            raise ValueError("The address can only contain letters, digits, dots, dashes and colons")
    if out.get("hosts"):
        hs = out["hosts"].split()
        if any(not re.match(r"^[A-Za-z0-9.\-:\[\]]+$", h) for h in hs):
            raise ValueError("Each server must be an address or host name")
        out["hosts"] = "\n".join(hs)
    if out.get("url") and not re.match(r"^https?://[A-Za-z0-9.\-:\[\]]+(:\d+)?/?$", out["url"]):
        raise ValueError("The address must look like http://192.168.1.89 or https://ha.example.com:8123")
    for g in ("tenant_id", "client_id"):
        if out.get(g) and not re.fullmatch(r"[0-9a-fA-F-]{36}", out[g]):
            raise ValueError(f"{g.replace('_', ' ').capitalize()} must be a GUID")
    if out.get("domain") and not re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", out["domain"]):
        raise ValueError("Enter a domain like example.com")
    return out


def new_id():
    return "c" + secrets.token_hex(5)
