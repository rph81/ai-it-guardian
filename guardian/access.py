"""Read-only access to systems through the connectors, for the Active Directory and Patch & configuration agents.

The console decrypts the connectors (vault unlocked) and hands them to the run through a pipe: they live only in this
process's memory and are never written to disk, logs or the environment. Agents never see a secret; they call fixed,
named checks, and the code here does the signing in. Every check only reads.
"""
import atexit
import json
import os
import re
import ssl
import subprocess
import tempfile
import time
import urllib.parse
import urllib.error
import urllib.request

from . import connectors as conn

_CONNECTORS = []        # [{"id", "type", "name", "fields": {...incl. secrets}, "pin"}]
_SSH = {"private": None, "path": None}
_STATE_DIR = None
TYPES = {"active_directory", "linux_ssh", "synology", "proxmox_ve", "proxmox_bs", "m365", "windows", "azure", "ninjaone"}
CONNECTOR_AGENTS = {"ad": ["active_directory"], "patch": ["linux_ssh", "synology", "proxmox_ve", "proxmox_bs", "windows", "ninjaone"],
                    "m365": ["m365"], "devices": ["m365"], "azure": ["azure"]}


def load(data, state_dir):
    """Called once by run.py with what the console sent on stdin."""
    global _STATE_DIR
    _STATE_DIR = state_dir
    _CONNECTORS[:] = [c for c in data.get("connectors", []) if c.get("type") in TYPES]
    _SSH["private"] = data.get("ssh_private_key")


def summary():
    """What the agents (and graph.json) may know: types, names and hosts, never secrets."""
    out = []
    for c in _CONNECTORS:
        f = c["fields"]
        hosts = [h for h in (f.get("hosts") or "").split() if h] or [x for x in (f.get("host"), f.get("domain")) if x]
        out.append({"id": c["id"], "type": c["type"], "name": c.get("name") or c["type"], "hosts": hosts})
    return out


def available(agent):
    return any(c["type"] in CONNECTOR_AGENTS.get(agent, []) for c in _CONNECTORS)


def _get(cid, types):
    c = next((c for c in _CONNECTORS if c["id"] == cid and c["type"] in types), None)
    if not c:
        raise ValueError(f"no connector {cid} of type {', '.join(sorted(types))}")
    return c


# -- SSH (Linux servers) ----------------------------------------------------------------------------------
def _key_path():
    if not _SSH["private"]:
        raise ValueError("Guardian's SSH key wasn't handed to this run (vault locked?)")
    if not _SSH["path"]:
        fd, path = tempfile.mkstemp(prefix="guardian-run-", dir="/dev/shm" if os.path.isdir("/dev/shm") else None)
        os.write(fd, _SSH["private"].encode())
        os.close(fd)
        os.chmod(path, 0o600)
        _SSH["path"] = path
    return _SSH["path"]


@atexit.register
def _wipe():
    p = _SSH.get("path")
    if p and os.path.exists(p):
        with open(p, "r+b") as f:
            f.write(b"\0" * os.path.getsize(p))
        os.unlink(p)


# Fixed, read-only commands. The agent picks a name; it can't pass its own command or arguments.
LINUX_CHECKS = {
    "os_release": "cat /etc/os-release; echo; echo kernel=$(uname -r); echo arch=$(uname -m); echo boot=$(uptime -s 2>/dev/null)",
    "pending_updates": ("if command -v apt >/dev/null 2>&1; then echo manager=apt; "
                        "echo lists_age_days=$(( ( $(date +%s) - $(stat -c %Y /var/lib/apt/lists 2>/dev/null || echo 0) ) / 86400 )); "
                        "apt list --upgradable 2>/dev/null | tail -n +2 | head -400; "
                        "elif command -v dnf >/dev/null 2>&1; then echo manager=dnf; dnf -q --cacheonly updateinfo list --security 2>/dev/null | head -300; "
                        "dnf -q --cacheonly check-update 2>/dev/null | head -400; "
                        "elif command -v apk >/dev/null 2>&1; then echo manager=apk; apk version -l '<' 2>/dev/null | head -400; "
                        "else echo manager=unknown; fi"),
    "reboot_required": ("test -f /var/run/reboot-required && { echo reboot_required=yes; cat /var/run/reboot-required.pkgs 2>/dev/null; } "
                        "|| echo reboot_required=no; echo running=$(uname -r); ls -1 /boot 2>/dev/null | grep -E '^vmlinuz-' | sort -V | tail -3"),
    "auto_updates": ("cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; systemctl is-enabled unattended-upgrades 2>/dev/null; "
                     "systemctl is-enabled dnf-automatic.timer dnf-automatic-install.timer 2>/dev/null; true"),
    "ssh_config": "grep -hvE '^\\s*(#|$)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | head -150",
    "listening": "ss -tulnH 2>/dev/null | head -150",
    "firewall": ("for u in ufw firewalld nftables iptables; do echo \"$u=$(systemctl is-active $u 2>/dev/null)\"; done; "
                 "grep -h '^ENABLED' /etc/ufw/ufw.conf 2>/dev/null; true"),
    "users": ("getent passwd | awk -F: '$3==0 || $3>=1000 {print $1\":\"$3\":\"$7}' | head -200; echo ---; "
              "getent group sudo wheel admin 2>/dev/null"),
    "services": "systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}' | head -200",
    "disk_encryption": "lsblk -o NAME,TYPE,FSTYPE,SIZE,MOUNTPOINT 2>/dev/null | head -60",
    "time_sync": "timedatectl show -p NTPSynchronized -p Timezone 2>/dev/null; true",
    "kernel_hardening": ("sysctl kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict fs.suid_dumpable "
                         "net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects "
                         "net.ipv4.conf.all.rp_filter net.ipv4.tcp_syncookies 2>/dev/null; true"),
    "packages": ("if command -v dpkg-query >/dev/null 2>&1; then echo manager=dpkg; "
                 "dpkg-query -W -f '${source:Package} ${source:Version}\\n' 2>/dev/null | sort -u | head -4000; "
                 "elif command -v rpm >/dev/null 2>&1; then echo manager=rpm; rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\\n' | head -4000; "
                 "elif command -v apk >/dev/null 2>&1; then echo manager=apk; apk info -v 2>/dev/null | head -4000; fi"),
}


def linux_check(cid, host, check):
    c = _get(cid, {"linux_ssh"})
    f = c["fields"]
    if host not in (f.get("hosts") or "").split():
        raise ValueError(f"{host} isn't one of this connector's servers")
    if check not in LINUX_CHECKS:
        raise ValueError("unknown check")
    os.makedirs(os.path.join(_STATE_DIR, "ssh"), mode=0o700, exist_ok=True)
    known = os.path.join(_STATE_DIR, "ssh", "known_hosts")
    cmd = ["ssh", "-i", _key_path(), "-p", str(int(f.get("port") or 22)), "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
           "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known}", "-o", "LogLevel=ERROR",
           f'{f.get("username") or "guardian"}@{host}', LINUX_CHECKS[check]]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        return {"error": "timed out"}
    if r.returncode != 0 and not r.stdout:
        err = (r.stderr.strip().splitlines() or ["unknown error"])[-1]
        if "Host key verification failed" in r.stderr:
            err = "the server's host key isn't trusted yet or has changed (test the connector in Settings first)"
        return {"error": err[:300]}
    out = r.stdout
    return {"host": host, "check": check, "output": out[:24000], **({"truncated": True} if len(out) > 24000 else {})}


OSV_ECOSYSTEM = {"debian": "Debian:{v}", "ubuntu": "Ubuntu:{v}:LTS", "alpine": "Alpine:v{v}"}


def linux_vulnerable_packages(cid, host):
    """Installed packages checked against OSV for the distribution (Debian, Ubuntu LTS, Alpine)."""
    rel = linux_check(cid, host, "os_release")
    if "error" in rel:
        return rel
    info = dict(re.findall(r'^(\w+)="?([^"\n]*)"?$', rel["output"], re.M))
    distro, ver = info.get("ID", "").lower(), info.get("VERSION_ID", "")
    if distro == "alpine":
        ver = ".".join(ver.split(".")[:2])
    if distro not in OSV_ECOSYSTEM or not ver:
        return {"note": f"OSV doesn't cover {info.get('PRETTY_NAME', distro)}; use pending_updates and cve_lookup instead."}
    eco = OSV_ECOSYSTEM[distro].format(v=ver)
    pk = linux_check(cid, host, "packages")
    if "error" in pk:
        return pk
    pkgs = []
    for line in pk["output"].splitlines()[1:]:
        parts = line.split()
        if len(parts) == 2:
            name, version = parts if distro != "alpine" else (parts[0].rsplit("-", 2)[0], "-".join(parts[0].rsplit("-", 2)[1:]))
            pkgs.append((name, version))
    from .codescan import http as osv_http
    hits = []
    for i in range(0, len(pkgs), 1000):
        chunk = pkgs[i:i + 1000]
        res = json.loads(osv_http("https://api.osv.dev/v1/querybatch", {"queries": [
            {"package": {"ecosystem": eco, "name": n}, "version": v} for n, v in chunk]}, limit=32 * 2**20))
        for (n, v), r in zip(chunk, res.get("results") or []):
            ids = [x["id"] for x in r.get("vulns") or []]
            if ids:
                hits.append({"package": n, "version": v, "advisories": ids[:8], "count": len(ids)})
    hits.sort(key=lambda h: -h["count"])
    return {"host": host, "ecosystem": eco, "packages_checked": len(pkgs), "vulnerable_packages": len(hits), "top": hits[:60],
            "note": "Advisory IDs (DSA/DLA/USN/CVE). Use cve_lookup or kev_details on the CVEs that matter; a fix may only "
                    "be available once the package has an update (see pending_updates)."}


# -- Synology DSM (normal, non-admin user) ----------------------------------------------------------------
def synology_info(cid):
    c = _get(cid, {"synology"})
    f = c["fields"]
    host, port = f["host"], int(f.get("port") or 5001)
    scheme = "https" if port in (5001, 443) else "http"
    ctx = conn._tls_context(host, port, f.get("verify_tls"), c.get("pin"))[0] if scheme == "https" else None
    base = f"{scheme}://{host}:{port}/webapi/entry.cgi"
    st, r = conn._http(base, ctx, data={"api": "SYNO.API.Auth", "version": "6", "method": "login", "account": f["username"],
                                        "passwd": f["password"], "session": "guardian", "format": "sid"})
    if not isinstance(r, dict) or not r.get("success"):
        return {"error": "sign-in failed"}
    sid = r["data"]["sid"]
    try:
        out = {}
        for api, method, ver in (("SYNO.DSM.Info", "getinfo", 2), ("SYNO.Core.System", "info", 1),
                                 ("SYNO.Core.Upgrade.Server", "check", 1), ("SYNO.Core.SecurityScan.Status", "system_get", 1)):
            _, d = conn._http(f"{base}?api={api}&version={ver}&method={method}&_sid={sid}", ctx)
            if isinstance(d, dict) and d.get("success"):
                out[api] = d.get("data")
            else:
                out[api] = "not available to this (non-admin) account"
        return {"host": host, "transport": scheme, **out}
    finally:
        conn._http(f"{base}?api=SYNO.API.Auth&version=6&method=logout&session=guardian&_sid={sid}", ctx)


# -- Proxmox VE / Backup Server (read-only token) ---------------------------------------------------------
PVE_PATHS = [r"/version", r"/nodes", r"/nodes/[\w.-]+/status", r"/nodes/[\w.-]+/apt/update", r"/nodes/[\w.-]+/apt/versions",
             r"/nodes/[\w.-]+/subscription", r"/nodes/[\w.-]+/certificates/info", r"/nodes/[\w.-]+/firewall/options",
             r"/cluster/resources", r"/cluster/firewall/options", r"/cluster/backup", r"/cluster/options", r"/access/users",
             r"/access/domains", r"/storage", r"/nodes/[\w.-]+/qemu", r"/nodes/[\w.-]+/lxc", r"/nodes/[\w.-]+/qemu/\d+/config",
             r"/nodes/[\w.-]+/lxc/\d+/config"]
PBS_PATHS = [r"/version", r"/nodes/localhost/status", r"/nodes/localhost/apt/update", r"/nodes/localhost/subscription",
             r"/admin/datastore", r"/admin/datastore/[\w.-]+/status", r"/admin/datastore/[\w.-]+/groups", r"/config/datastore",
             r"/config/verify", r"/config/sync", r"/config/prune", r"/admin/verify", r"/admin/sync", r"/access/users",
             r"/nodes/localhost/certificates/info"]


def proxmox_get(cid, path):
    c = _get(cid, {"proxmox_ve", "proxmox_bs"})
    ve = c["type"] == "proxmox_ve"
    path = "/" + path.strip().lstrip("/").split("?")[0]
    if not any(re.fullmatch(p, path) for p in (PVE_PATHS if ve else PBS_PATHS)):
        return {"error": "path not in the read-only list", "allowed": PVE_PATHS if ve else PBS_PATHS}
    f = c["fields"]
    host, port = f["host"], int(f.get("port") or (8006 if ve else 8007))
    ctx = conn._tls_context(host, port, f.get("verify_tls"), c.get("pin"))[0]
    auth = {"Authorization": (f'PVEAPIToken={f["token_id"]}={f["token_secret"]}' if ve else f'PBSAPIToken={f["token_id"]}:{f["token_secret"]}')}
    st, d = conn._http(f"https://{host}:{port}/api2/json{urllib.parse.quote(path)}", ctx, auth)
    data = d.get("data") if isinstance(d, dict) else d
    body = json.dumps(data, default=str)
    if len(body) > 24000:
        return {"status": st, "data": body[:24000], "truncated": True}
    return {"status": st, "data": data}


# -- Active Directory (normal domain user, LDAPS) ---------------------------------------------------------
UAC = {"disabled": 2, "pwd_not_required": 32, "reversible": 128, "normal": 512, "never_expires": 65536,
       "trusted_for_delegation": 524288, "des_only": 2097152, "no_preauth": 4194304}
PRIV_GROUPS = ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators",
               "Backup Operators", "Server Operators", "Print Operators", "DnsAdmins", "Group Policy Creator Owners"]
ENABLED_USER = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))%s)"


def _bit(name):
    return f"(userAccountControl:1.2.840.113556.1.4.803:={UAC[name]})"


def _filetime(days_ago):
    return str(int((time.time() - days_ago * 86400 + 11644473600) * 10**7))


AD_QUERIES = {
    "domain_policy": ("base", None, ["minPwdLength", "pwdHistoryLength", "maxPwdAge", "minPwdAge", "lockoutThreshold",
                                     "lockoutDuration", "pwdProperties", "ms-DS-MachineAccountQuota", "msDS-Behavior-Version"]),
    "domain_controllers": ("sub", "(&(objectCategory=computer)(primaryGroupID=516))",
                           ["dNSHostName", "operatingSystem", "operatingSystemVersion", "lastLogonTimestamp"]),
    "kerberoastable_users": ("sub", ENABLED_USER % "(servicePrincipalName=*)(!(sAMAccountName=krbtgt))",
                             ["sAMAccountName", "servicePrincipalName", "adminCount", "pwdLastSet", "memberOf"]),
    "asrep_roastable_users": ("sub", ENABLED_USER % _bit("no_preauth"), ["sAMAccountName", "adminCount", "pwdLastSet"]),
    "unconstrained_delegation": ("sub", "(&" + _bit("trusted_for_delegation") + "(!(primaryGroupID=516)))",
                                 ["sAMAccountName", "objectClass", "dNSHostName"]),
    "constrained_delegation": ("sub", "(msDS-AllowedToDelegateTo=*)", ["sAMAccountName", "msDS-AllowedToDelegateTo"]),
    "password_never_expires": ("sub", ENABLED_USER % _bit("never_expires"), ["sAMAccountName", "adminCount", "pwdLastSet"]),
    "password_not_required": ("sub", ENABLED_USER % _bit("pwd_not_required"), ["sAMAccountName", "adminCount"]),
    "reversible_or_des": ("sub", "(|" + _bit("reversible") + _bit("des_only") + ")", ["sAMAccountName", "userAccountControl"]),
    "admin_count_users": ("sub", ENABLED_USER % "(adminCount=1)", ["sAMAccountName", "pwdLastSet", "lastLogonTimestamp", "memberOf"]),
    "stale_users": ("sub", None, ["sAMAccountName", "lastLogonTimestamp", "adminCount"]),
    "stale_computers": ("sub", None, ["sAMAccountName", "operatingSystem", "lastLogonTimestamp"]),
    "computer_os": ("sub", "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                    ["operatingSystem", "operatingSystemVersion"]),
    "laps_coverage": ("sub", "(&(objectCategory=computer)(!(primaryGroupID=516))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                      ["sAMAccountName", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime"]),
    "krbtgt": ("sub", "(sAMAccountName=krbtgt)", ["pwdLastSet"]),
    "builtin_accounts": ("sub", "(|(sAMAccountName=Administrator)(sAMAccountName=Guest))",
                         ["sAMAccountName", "userAccountControl", "lastLogonTimestamp", "pwdLastSet"]),
    "privileged_groups": ("groups", None, ["sAMAccountName"]),
    "trusts": ("sub", "(objectClass=trustedDomain)", ["flatName", "trustPartner", "trustDirection", "trustType", "trustAttributes"]),
    "gpos": ("sub", "(objectClass=groupPolicyContainer)", ["displayName", "whenChanged", "flags"]),
    "sid_history": ("sub", "(sIDHistory=*)", ["sAMAccountName"]),
}


def _norm(v):
    """LDAP values as plain text: bytes are decoded (or shown as hex), lists are normalised item by item."""
    if isinstance(v, list):
        return [_norm(x) for x in v]
    if isinstance(v, (bytes, bytearray)):
        try:
            return bytes(v).decode("utf-8")
        except UnicodeDecodeError:
            return bytes(v).hex()
    return v


def _ftime(v):
    """AD FILETIME / datetime to an ISO date, or None."""
    v = _norm(v)
    if v in (None, "", 0, "0") or (isinstance(v, list) and not v):
        return None
    if hasattr(v, "isoformat"):
        return None if v.year < 1700 else v.date().isoformat()
    try:
        n = int(v)
        return None if n <= 0 else time.strftime("%Y-%m-%d", time.gmtime(n / 10**7 - 11644473600))
    except (TypeError, ValueError):
        return str(v)[:30]


def ad_query(cid, query, days=90):
    import ldap3
    c = _get(cid, {"active_directory"})
    if query not in AD_QUERIES:
        raise ValueError("unknown query")
    f = c["fields"]
    host, port = f["host"], int(f.get("port") or 636)
    use_ssl = port == 636
    if use_ssl and not f.get("verify_tls"):
        conn._tls_context(host, port, False, c.get("pin"))         # refuses if the certificate changed since it was pinned
    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED if f.get("verify_tls") else ssl.CERT_NONE)
    server = ldap3.Server(host, port=port, use_ssl=use_ssl, tls=tls, get_info=ldap3.DSA, connect_timeout=8)
    user = f["username"] if "@" in f["username"] or "\\" in f["username"] else f'{f["username"]}@{f["domain"]}'
    # check_names off: attributes such as the LAPS ones only exist when that schema extension is installed
    lc = ldap3.Connection(server, user=user, password=f["password"], receive_timeout=20, read_only=True, check_names=False)
    if not use_ssl:
        lc.open()
        lc.start_tls()
    if not lc.bind():
        return {"error": "sign-in failed"}
    try:
        nc = (server.info.other.get("defaultNamingContext") or [""])[0]
        scope, flt, attrs = AD_QUERIES[query]
        days = max(30, min(365, int(days)))
        if query == "stale_users":
            flt = ENABLED_USER % f"(lastLogonTimestamp<={_filetime(days)})"
        if query == "stale_computers":
            flt = f"(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<={_filetime(days)}))"
        if scope == "base":
            lc.search(nc, "(objectClass=*)", search_scope=ldap3.BASE, attributes=attrs)
            e = lc.entries[0].entry_attributes_as_dict if lc.entries else {}
            return {"domain": nc, "policy": {k: (_norm(v)[0] if isinstance(v, list) and len(v) == 1 else _norm(v)) for k, v in e.items()},
                    "note": "maxPwdAge / lockoutDuration are negative 100-ns intervals; pwdProperties bit 1 = complexity on."}
        if scope == "groups":
            out = {}
            for g in PRIV_GROUPS:
                lc.search(nc, f"(&(objectClass=group)(cn={ldap3.utils.conv.escape_filter_chars(g)}))", attributes=["distinguishedName"])
                if not lc.entries:
                    continue
                dn = str(lc.entries[0].distinguishedName)
                lc.search(nc, f"(&(objectCategory=person)(memberOf:1.2.840.113556.1.4.1941:={ldap3.utils.conv.escape_filter_chars(dn)}))",
                          attributes=["sAMAccountName", "userAccountControl"], size_limit=200)
                out[g] = [{"user": _norm(x.sAMAccountName.value), "disabled": bool(int(_norm(x.userAccountControl.value) or 0) & 2)}
                          for x in lc.entries]
            return {"domain": nc, "privileged_groups": out}
        try:
            lc.search(nc, flt, attributes=attrs, size_limit=500, paged_size=200)
        except ldap3.core.exceptions.LDAPAttributeError:
            if query != "laps_coverage":
                raise
            lc.search(nc, flt, attributes=["sAMAccountName"], size_limit=500, paged_size=200)
            return {"domain": nc, "computers": len(lc.entries), "with_laps": 0,
                    "note": "The LAPS attributes don't exist in this directory's schema: LAPS isn't installed."}
        rows = []
        for e in lc.entries[:500]:
            d = {}
            for k, v in e.entry_attributes_as_dict.items():
                v = _norm(v)
                if k in ("pwdLastSet", "lastLogonTimestamp", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime", "whenChanged"):
                    d[k] = _ftime(v[0] if isinstance(v, list) and v else v)
                elif k == "memberOf":
                    d[k] = [str(x).split(",")[0].replace("CN=", "") for x in v][:15]
                else:
                    d[k] = v[0] if isinstance(v, list) and len(v) == 1 else (v[:10] if isinstance(v, list) else v)
            rows.append(d)
        result = {"domain": nc, "query": query, "count": len(rows), "rows": rows[:200]}
        if query == "laps_coverage":
            covered = sum(1 for r in rows if r.get("ms-Mcs-AdmPwdExpirationTime") or r.get("msLAPS-PasswordExpirationTime"))
            result = {"domain": nc, "computers": len(rows), "with_laps": covered,
                      "without_laps": [r["sAMAccountName"] for r in rows if not (r.get("ms-Mcs-AdmPwdExpirationTime") or r.get("msLAPS-PasswordExpirationTime"))][:100],
                      "note": "A normal user may not be allowed to read the LAPS attributes; 0 covered can mean 'not readable'."}
        if query == "computer_os":
            counts = {}
            for r in rows:
                k = f'{r.get("operatingSystem") or "unknown"} {r.get("operatingSystemVersion") or ""}'.strip()
                counts[k] = counts.get(k, 0) + 1
            result = {"domain": nc, "computers": len(rows), "by_os": dict(sorted(counts.items(), key=lambda kv: -kv[1]))}
        return result
    finally:
        lc.unbind()


# -- Microsoft Graph (application with read-only permissions) ----------------------------------------------
GRAPH_PATHS = [
    r"/organization", r"/domains", r"/subscribedSkus", r"/users", r"/users/[\w.@-]+", r"/users/[\w.@-]+/memberOf",
    r"/users/[\w.@-]+/mailboxSettings", r"/users/[\w.@-]+/mailFolders/inbox/messageRules", r"/groups",
    r"/directoryRoles", r"/directoryRoles/[\w-]+/members", r"/roleManagement/directory/roleAssignments",
    r"/roleManagement/directory/roleEligibilitySchedules", r"/identity/conditionalAccess/policies",
    r"/identity/conditionalAccess/namedLocations", r"/policies/identitySecurityDefaultsEnforcementPolicy",
    r"/policies/authorizationPolicy", r"/policies/authenticationMethodsPolicy", r"/policies/adminConsentRequestPolicy",
    r"/reports/authenticationMethods/userRegistrationDetails", r"/auditLogs/signIns", r"/auditLogs/directoryAudits",
    r"/applications", r"/servicePrincipals", r"/servicePrincipals/[\w-]+/appRoleAssignments", r"/oauth2PermissionGrants",
    r"/security/secureScores", r"/security/secureScoreControlProfiles", r"/security/alerts_v2", r"/security/incidents",
    r"/deviceManagement/managedDevices", r"/deviceManagement/managedDevices/[\w-]+", r"/deviceManagement/deviceCompliancePolicies",
    r"/deviceManagement/deviceConfigurations", r"/deviceManagement/managedDeviceOverview",
    r"/deviceManagement/windowsAutopilotDeviceIdentities", r"/devices",
]
GRAPH_QUERY = {"$select", "$filter", "$top", "$expand", "$orderby", "$count", "$search"}
_GRAPH_TOKEN = {}


def _graph_token(c):
    t = _GRAPH_TOKEN.get(c["id"])
    if t and t[1] > time.time() + 60:
        return t[0]
    token, _ = conn.graph_token(c["fields"])
    _GRAPH_TOKEN[c["id"]] = (token, time.time() + 3000)
    return token


def graph_get(cid, path, query=None, beta=False, max_pages=5):
    """GET one allow-listed Microsoft Graph path, following up to max_pages of results."""
    c = _get(cid, {"m365"})
    path = "/" + path.strip().lstrip("/").split("?")[0]
    if ".." in path or not any(re.fullmatch(p, path) for p in GRAPH_PATHS):
        return {"error": "path not in the read-only list", "allowed": GRAPH_PATHS}
    q = {k: str(v)[:500] for k, v in (query or {}).items() if k in GRAPH_QUERY}
    url = f"https://graph.microsoft.com/{'beta' if beta else 'v1.0'}{urllib.parse.quote(path)}" + (("?" + urllib.parse.urlencode(q)) if q else "")
    headers = {"Authorization": f"Bearer {_graph_token(c)}", "ConsistencyLevel": "eventual"}
    ctx = ssl.create_default_context()
    rows, pages = [], 0
    while url and pages < max(1, min(10, int(max_pages))):
        st, d = conn._http(url, ctx, headers)
        pages += 1
        if st != 200:
            err = (d or {}).get("error", {}) if isinstance(d, dict) else {}
            hint = " (the app lacks a permission, or the tenant's licence doesn't include this report)" if st in (401, 403) else ""
            return {"status": st, "error": f"{err.get('code', st)}: {str(err.get('message', d))[:300]}{hint}", "rows_so_far": rows[:50]}
        if isinstance(d, dict) and "value" in d:
            rows.extend(d["value"])
            url = d.get("@odata.nextLink")
            if url and not url.startswith("https://graph.microsoft.com/"):
                url = None
        else:
            return {"status": st, "data": d}
    body = json.dumps(rows, default=str)
    out = {"status": 200, "count": len(rows), "more": bool(url), "rows": rows}
    if len(body) > 30000:
        out.update(rows=json.loads(json.dumps(rows[:max(1, int(len(rows) * 30000 / len(body)))], default=str)), truncated=True)
    return out


# -- Microsoft Azure (separate app with Reader + Security Reader) ------------------------------------------
ARM = "https://management.azure.com"
# Resource Graph: fixed queries only. The agent picks a name; it can narrow by resource group, never write KQL.
AZURE_QUERIES = {
    "subscriptions": "resourcecontainers | where type == 'microsoft.resources/subscriptions' | project subscriptionId, name, state=tostring(properties.state)",
    "resource_counts": "resources | summarize count() by type | order by count_ desc | take 100",
    "public_ips": "resources | where type == 'microsoft.network/publicipaddresses' | project name, resourceGroup, subscriptionId, ip=properties.ipAddress, attachedTo=tostring(properties.ipConfiguration.id), natGateway=tostring(properties.natGateway.id), sku=tostring(sku.name)",
    "nsg_open_inbound": "resources | where type == 'microsoft.network/networksecuritygroups' | mv-expand rule=properties.securityRules | extend p=rule.properties | where p.direction == 'Inbound' and p.access == 'Allow' and (tostring(p.sourceAddressPrefix) in ('*', '0.0.0.0/0', 'Internet', 'Any') or tostring(p.sourceAddressPrefixes) has '\"*\"' or tostring(p.sourceAddressPrefixes) has '0.0.0.0/0') | project nsg=name, resourceGroup, subscriptionId, rule=tostring(rule.name), ports=coalesce(tostring(p.destinationPortRange), tostring(p.destinationPortRanges)), protocol=tostring(p.protocol), priority=toint(p.priority), nics=array_length(properties.networkInterfaces), subnets=array_length(properties.subnets)",
    "nsg_coverage": "resources | where type == 'microsoft.network/virtualnetworks' | mv-expand subnet=properties.subnets | project vnet=name, resourceGroup, subscriptionId, subnet=tostring(subnet.name), nsg=tostring(subnet.properties.networkSecurityGroup.id)",
    "flow_logs": "resources | where type == 'microsoft.network/networkwatchers/flowlogs' | project name, target=tostring(properties.targetResourceId), enabled=properties.enabled, retentionDays=properties.retentionPolicy.days",
    "vnets": "resources | where type == 'microsoft.network/virtualnetworks' | project name, resourceGroup, subscriptionId, ddosProtection=properties.enableDdosProtection, addressSpace=properties.addressSpace.addressPrefixes",
    "gateways_and_balancers": "resources | where type in~ ('microsoft.network/applicationgateways', 'microsoft.network/loadbalancers', 'microsoft.network/azurefirewalls', 'microsoft.network/bastionhosts') | project type, name, resourceGroup, subscriptionId, sku=tostring(sku.name), waf=properties.webApplicationFirewallConfiguration.enabled, wafPolicy=tostring(properties.firewallPolicy.id)",
    "vms": "resources | where type == 'microsoft.compute/virtualmachines' | project name, resourceGroup, subscriptionId, location, zones, size=tostring(properties.hardwareProfile.vmSize), os=tostring(properties.storageProfile.osDisk.osType), image=properties.storageProfile.imageReference, power=tostring(properties.extended.instanceView.powerState.code), identity=tostring(identity.type), encryptionAtHost=properties.securityProfile.encryptionAtHost, securityType=tostring(properties.securityProfile.securityType)",
    "vm_extensions": "resources | where type == 'microsoft.compute/virtualmachines/extensions' | project vm=tostring(split(id, '/')[8]), resourceGroup, name, publisher=tostring(properties.publisher), extType=tostring(properties.type), state=tostring(properties.provisioningState)",
    "disks": "resources | where type == 'microsoft.compute/disks' | project name, resourceGroup, subscriptionId, state=tostring(properties.diskState), encryption=tostring(properties.encryption.type), networkAccess=tostring(properties.networkAccessPolicy), publicNetwork=tostring(properties.publicNetworkAccess), attachedTo=tostring(managedBy)",
    "storage_accounts": "resources | where type == 'microsoft.storage/storageaccounts' | project name, resourceGroup, subscriptionId, kind, publicBlobAccess=properties.allowBlobPublicAccess, sharedKeyAccess=properties.allowSharedKeyAccess, httpsOnly=properties.supportsHttpsTrafficOnly, minTls=tostring(properties.minimumTlsVersion), publicNetwork=tostring(properties.publicNetworkAccess), defaultAction=tostring(properties.networkAcls.defaultAction), privateEndpoints=array_length(properties.privateEndpointConnections), infraEncryption=properties.encryption.requireInfrastructureEncryption, crossTenantReplication=properties.allowCrossTenantReplication",
    "sql_servers": "resources | where type == 'microsoft.sql/servers' | project name, resourceGroup, subscriptionId, publicNetwork=tostring(properties.publicNetworkAccess), minTls=tostring(properties.minimalTlsVersion), entraAdmin=tostring(properties.administrators.login), entraOnlyAuth=properties.administrators.azureADOnlyAuthentication",
    "open_source_databases": "resources | where type in~ ('microsoft.dbforpostgresql/flexibleservers', 'microsoft.dbformysql/flexibleservers', 'microsoft.documentdb/databaseaccounts') | project type, name, resourceGroup, subscriptionId, publicNetwork=coalesce(tostring(properties.network.publicNetworkAccess), tostring(properties.publicNetworkAccess)), version=tostring(properties.version), backupDays=properties.backup.backupRetentionDays, geoBackup=tostring(properties.backup.geoRedundantBackup), ha=tostring(properties.highAvailability.mode), ipRules=properties.ipRules",
    "key_vaults": "resources | where type == 'microsoft.keyvault/vaults' | project name, resourceGroup, subscriptionId, softDelete=properties.enableSoftDelete, purgeProtection=properties.enablePurgeProtection, rbacModel=properties.enableRbacAuthorization, publicNetwork=tostring(properties.publicNetworkAccess), defaultAction=tostring(properties.networkAcls.defaultAction), retentionDays=properties.softDeleteRetentionInDays",
    "app_services": "resources | where type == 'microsoft.web/sites' | project name, kind, resourceGroup, subscriptionId, httpsOnly=properties.httpsOnly, publicNetwork=tostring(properties.publicNetworkAccess), clientCert=properties.clientCertEnabled, identity=tostring(identity.type), state=tostring(properties.state)",
    "defender_plans": "securityresources | where type == 'microsoft.security/pricings' | project subscriptionId, plan=name, tier=tostring(properties.pricingTier), subPlan=tostring(properties.subPlan)",
    "secure_score": "securityresources | where type == 'microsoft.security/securescores' | project subscriptionId, current=properties.score.current, max=properties.score.max, percentage=properties.score.percentage",
    "defender_recommendations": "securityresources | where type == 'microsoft.security/assessments' and tostring(properties.status.code) == 'Unhealthy' | summarize resources=count(), examples=make_set(tostring(properties.resourceDetails.Id), 3) by recommendation=tostring(properties.displayName), severity=tostring(properties.metadata.severity) | order by resources desc | take 150",
    "defender_alerts": "securityresources | where type == 'microsoft.security/locations/alerts' and tostring(properties.Status) == 'Active' | project subscriptionId, alert=tostring(properties.AlertDisplayName), severity=tostring(properties.Severity), time=tostring(properties.TimeGeneratedUtc), entity=tostring(properties.CompromisedEntity) | take 150",
    "role_assignments": "authorizationresources | where type == 'microsoft.authorization/roleassignments' | extend roleId=tolower(tostring(properties.roleDefinitionId)) | join kind=leftouter (authorizationresources | where type == 'microsoft.authorization/roledefinitions' | extend roleId=tolower(id), role=tostring(properties.roleName) | project roleId, role) on roleId | project principalId=tostring(properties.principalId), principalType=tostring(properties.principalType), role, scope=tostring(properties.scope) | take 1000",
    "custom_roles": "authorizationresources | where type == 'microsoft.authorization/roledefinitions' and tostring(properties.type) == 'CustomRole' | project role=tostring(properties.roleName), permissions=properties.permissions, scopes=properties.assignableScopes",
    "policy_assignments": "policyresources | where type == 'microsoft.authorization/policyassignments' | project name=tostring(properties.displayName), scope=tostring(properties.scope), enforcement=tostring(properties.enforcementMode)",
    "policy_noncompliance": "policyresources | where type == 'microsoft.policyinsights/policystates' and tostring(properties.complianceState) == 'NonCompliant' | summarize resources=dcount(tostring(properties.resourceId)) by policy=tostring(properties.policyDefinitionName), assignment=tostring(properties.policyAssignmentName) | order by resources desc | take 100",
    "backup_items": "recoveryservicesresources | where type == 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems' | project item=tostring(properties.friendlyName), source=tostring(properties.sourceResourceId), lastBackup=tostring(properties.lastBackupTime), health=tostring(properties.healthStatus), policy=tostring(properties.policyName)",
    "vms_without_backup": "resources | where type == 'microsoft.compute/virtualmachines' | extend vmId=tolower(id) | join kind=leftouter (recoveryservicesresources | where type == 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems' | extend vmId=tolower(tostring(properties.sourceResourceId)), protected=true | project vmId, protected) on vmId | where isnull(protected) | project name, resourceGroup, subscriptionId",
    "recovery_vaults": "resources | where type == 'microsoft.recoveryservices/vaults' | project name, resourceGroup, subscriptionId, softDelete=tostring(properties.securitySettings.softDeleteSettings.softDeleteState), immutability=tostring(properties.securitySettings.immutabilitySettings.state), redundancy=tostring(properties.redundancySettings.standardTierStorageRedundancy), publicNetwork=tostring(properties.publicNetworkAccess)",
    "orphaned_resources": "resources | where (type == 'microsoft.compute/disks' and tostring(properties.diskState) == 'Unattached') or (type == 'microsoft.network/publicipaddresses' and isnull(properties.ipConfiguration) and isnull(properties.natGateway)) or (type == 'microsoft.network/networkinterfaces' and isnull(properties.virtualMachine) and isnull(properties.privateEndpoint)) | project type, name, resourceGroup, subscriptionId",
    "untagged": "resources | where isnull(tags) or array_length(bag_keys(tags)) == 0 | summarize count() by type | order by count_ desc | take 50",
}
# Management API: GET only, fixed paths. {s} subscription, {rg} resource group, {n} name; api-version is set here.
_N = r"[\w.()-]{1,90}"
_SUB = r"/subscriptions/[0-9a-fA-F-]{36}"
AZURE_PATHS = [
    (r"/subscriptions", "2022-12-01"),
    (_SUB + r"/providers/Microsoft\.Security/pricings", "2024-01-01"),
    (_SUB + r"/providers/Microsoft\.Security/secureScores", "2020-01-01"),
    (_SUB + r"/providers/Microsoft\.Security/securityContacts", "2020-01-01-preview"),
    (_SUB + r"/providers/Microsoft\.Security/autoProvisioningSettings", "2017-08-01-preview"),
    (_SUB + r"/providers/Microsoft\.Insights/diagnosticSettings", "2021-05-01-preview"),
    (_SUB + r"/providers/Microsoft\.Insights/activityLogAlerts", "2020-10-01"),
    (_SUB + r"/providers/Microsoft\.Authorization/locks", "2020-05-01"),
    (_SUB + r"/providers/Microsoft\.Authorization/classicAdministrators", "2015-07-01"),
    (_SUB + r"/providers/Microsoft\.Advisor/recommendations", "2023-01-01"),
    (_SUB + rf"/resourceGroups/{_N}/providers/Microsoft\.Sql/servers/{_N}/firewallRules", "2021-11-01"),
    (_SUB + rf"/resourceGroups/{_N}/providers/Microsoft\.Sql/servers/{_N}/auditingSettings", "2021-11-01"),
    (_SUB + rf"/resourceGroups/{_N}/providers/Microsoft\.Sql/servers/{_N}/databases", "2021-11-01"),
    (_SUB + rf"/resourceGroups/{_N}/providers/Microsoft\.Sql/servers/{_N}/databases/{_N}/transparentDataEncryption", "2021-11-01"),
    (_SUB + rf"/resourceGroups/{_N}/providers/Microsoft\.DBforPostgreSQL/flexibleServers/{_N}/firewallRules", "2022-12-01"),
    (_SUB + rf"/resourceGroups/{_N}/providers/Microsoft\.DBforMySQL/flexibleServers/{_N}/firewallRules", "2021-05-01"),
    (_SUB + rf"/resourceGroups/{_N}/providers/Microsoft\.Web/sites/{_N}/config/web", "2023-01-01"),
    (_SUB + rf"/resourceGroups/{_N}/providers/Microsoft\.KeyVault/vaults/{_N}/secrets", "2023-07-01"),
    (_SUB + rf"/resourceGroups/{_N}/providers/Microsoft\.KeyVault/vaults/{_N}/keys", "2023-07-01"),
    (_SUB + rf"/resourceGroups/{_N}/providers/Microsoft\.Storage/storageAccounts/{_N}/blobServices/default", "2023-01-01"),
    (_SUB + rf"/resourceGroups/{_N}/providers/Microsoft\.Network/networkSecurityGroups/{_N}", "2023-09-01"),
    (_SUB + rf"/resourceGroups/{_N}/providers/[A-Za-z]+\.[A-Za-z]+/[A-Za-z]+/{_N}/providers/Microsoft\.Insights/diagnosticSettings", "2021-05-01-preview"),
]
RG = re.compile(r"^[\w.()-]{1,90}$")
_AZ_TOKEN = {}


def _azure(c):
    """(token, subscriptions Guardian may read) for an Azure connector; the token is cached for ~50 minutes."""
    t = _AZ_TOKEN.get(c["id"])
    if not t or t[1] < time.time() + 60:
        token, _ = conn.azure_token(c["fields"])
        only = conn.azure_subscription_filter(c["fields"])
        st, d = conn._http(f"{ARM}/subscriptions?api-version=2022-12-01", ssl.create_default_context(), {"Authorization": f"Bearer {token}"})
        subs = [x["subscriptionId"].lower() for x in (d or {}).get("value", []) if st == 200 and isinstance(d, dict)
                and (not only or x["subscriptionId"].lower() in only)]
        t = (token, time.time() + 3000, subs)
        _AZ_TOKEN[c["id"]] = t
    return t[0], t[2]


def _cap(rows, more, extra=None):
    body = json.dumps(rows, default=str)
    out = {"status": 200, "count": len(rows), "more": more, "rows": rows, **(extra or {})}
    if len(body) > 30000:
        out.update(rows=json.loads(json.dumps(rows[:max(1, int(len(rows) * 30000 / len(body)))], default=str)), truncated=True)
    return out


def azure_query(cid, query, resource_group=None, subscription=None):
    """Run one fixed Azure Resource Graph query (read-only) over the subscriptions this connector may read."""
    c = _get(cid, {"azure"})
    if query not in AZURE_QUERIES:
        return {"error": "unknown query", "allowed": sorted(AZURE_QUERIES)}
    token, subs = _azure(c)
    if subscription:
        if subscription.lower() not in subs:
            return {"error": "that subscription isn't readable by this connector", "subscriptions": subs}
        subs = [subscription.lower()]
    if not subs:
        return {"error": "no readable subscriptions (give the app Reader on them)"}
    kql = AZURE_QUERIES[query]
    if resource_group:
        if not RG.match(resource_group):
            return {"error": "bad resource group name"}
        table, rest = kql.split(" | ", 1)
        kql = f"{table} | where resourceGroup =~ '{resource_group}' | {rest}"
    rows, skip, pages = [], None, 0
    while pages < 5:
        body = {"subscriptions": subs, "query": kql, "options": {"$top": 1000, "resultFormat": "objectArray", **({"$skipToken": skip} if skip else {})}}
        req = urllib.request.Request(f"{ARM}/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01", method="POST",
                                     data=json.dumps(body).encode(), headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                                                              "User-Agent": "ai-guardian"})
        try:
            with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=30) as r:
                d = json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            try:
                err = json.loads(e.read().decode(errors="replace")).get("error", {})
            except ValueError:
                err = {}
            return {"status": e.code, "error": f"{err.get('code', e.code)}: {str(err.get('message', ''))[:300]}", "rows_so_far": rows[:50]}
        except (urllib.error.URLError, OSError) as e:
            return {"error": f"Azure unreachable: {getattr(e, 'reason', e)}"}
        rows.extend(d.get("data") or [])
        skip = d.get("$skipToken")
        pages += 1
        if not skip:
            break
    return _cap(rows, bool(skip), {"subscriptions": len(subs)})


def azure_get(cid, path):
    """GET one allow-listed Azure Resource Manager path (read-only)."""
    c = _get(cid, {"azure"})
    path = "/" + path.strip().lstrip("/").split("?")[0].rstrip("/")
    api = next((v for p, v in AZURE_PATHS if re.fullmatch(p, path)), None)
    if ".." in path or not api:
        return {"error": "path not in the read-only list", "allowed": [p for p, _ in AZURE_PATHS]}
    token, subs = _azure(c)
    m = re.match(r"^/subscriptions/([0-9a-fA-F-]{36})", path)
    if m and m.group(1).lower() not in subs:
        return {"error": "that subscription isn't readable by this connector", "subscriptions": subs}
    url = f"{ARM}{urllib.parse.quote(path)}?api-version={api}"
    ctx, rows, pages = ssl.create_default_context(), [], 0
    while url and pages < 5:
        st, d = conn._http(url, ctx, {"Authorization": f"Bearer {token}"}, timeout=30)
        pages += 1
        if st != 200:
            err = (d or {}).get("error", {}) if isinstance(d, dict) else {}
            hint = " (the app lacks Reader / Security Reader here, or the feature isn't enabled)" if st in (401, 403) else ""
            return {"status": st, "error": f"{err.get('code', st)}: {str(err.get('message', d))[:300]}{hint}"}
        if isinstance(d, dict) and "value" in d:
            rows.extend(d["value"])
            url = d.get("nextLink")
            if url and not url.startswith(ARM + "/"):
                url = None
        else:
            return {"status": st, "data": d}
    if path == "/subscriptions":
        rows = [x for x in rows if x.get("subscriptionId", "").lower() in subs]
    if path.endswith(("/secrets", "/keys")):      # names and expiry only: values never come through the management API
        rows = [{"name": x.get("name"), "attributes": (x.get("properties") or {}).get("attributes")} for x in rows]
    return _cap(rows, bool(url))


# -- NinjaOne (read-only API app, monitoring scope) -------------------------------------------------------------
NINJA_QUERIES = {
    "devices": ("/v2/devices-detailed", {}),
    "os_patches_pending": ("/v2/queries/os-patches", {"status": "PENDING"}),
    "os_patches_failed": ("/v2/queries/os-patches", {"status": "FAILED"}),
    "os_patch_installs_failed": ("/v2/queries/os-patch-installs", {"status": "FAILED"}),
    "software_patches_pending": ("/v2/queries/software-patches", {"status": "PENDING"}),
    "antivirus_status": ("/v2/queries/antivirus-status", {}),
    "device_health": ("/v2/queries/device-health", {}),
}
_NJ = {}


def ninja_query(cid, name):
    """One fixed NinjaOne read; follows the cursor for up to 5 pages of 1000."""
    from . import fixes
    c = _get(cid, {"ninjaone"})
    if name not in NINJA_QUERIES:
        return {"error": "unknown query", "allowed": sorted(NINJA_QUERIES)}
    t = _NJ.get(cid)
    if not t or t[2] < time.time() + 60:
        try:
            host, tok = fixes.ninja_token(c["fields"], "monitoring")
        except fixes.Failed as e:
            return {"error": str(e)}
        t = _NJ[cid] = (host, tok, time.time() + 3000)
    host, tok, _ = t
    path, params = NINJA_QUERIES[name]
    rows, cursor = [], None
    for _ in range(5):
        q = {**params, "pageSize": 1000, **({"cursor": cursor} if cursor else {})}
        st, d = conn._http(f"https://{host}{path}?{urllib.parse.urlencode(q)}", ssl.create_default_context(), {"Authorization": f"Bearer {tok}"}, timeout=30)
        if st != 200:
            return {"status": st, "error": str(d)[:300]}
        if isinstance(d, list):
            rows += d
            break
        rows += (d or {}).get("results", [])
        cursor = ((d or {}).get("cursor") or {}).get("name")
        if not cursor or not (d or {}).get("results"):
            break
    return _cap(rows, bool(cursor), {"query": name})


# -- Windows over WinRM (normal user in Remote Management Users) ------------------------------------------
WINDOWS_CHECKS = {
    "os": "$o=Get-CimInstance Win32_OperatingSystem; $o | Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime,InstallDate | ConvertTo-Json",
    "updates": "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 30 HotFixID,Description,InstalledOn | ConvertTo-Json",
    "update_settings": ("$au='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU'; "
                        "[pscustomobject]@{Policy=(Get-ItemProperty $au -EA SilentlyContinue | Select-Object NoAutoUpdate,AUOptions,ScheduledInstallDay);"
                        "Service=(Get-Service wuauserv).StartType.ToString()} | ConvertTo-Json -Depth 3"),
    "pending_reboot": ("[pscustomobject]@{CBS=(Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending');"
                       "WindowsUpdate=(Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired')} | ConvertTo-Json"),
    "defender": ("Get-MpComputerStatus -EA SilentlyContinue | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,"
                 "BehaviorMonitorEnabled,IsTamperProtected,AntivirusSignatureLastUpdated,QuickScanEndTime,AMRunningMode | ConvertTo-Json"),
    "firewall": "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json",
    "bitlocker": "try { Get-BitLockerVolume -EA Stop | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod | ConvertTo-Json } catch { 'not readable with this account' }",
    "local_admins": "Get-LocalGroupMember -SID S-1-5-32-544 -EA SilentlyContinue | Select-Object Name,ObjectClass,PrincipalSource | ConvertTo-Json",
    "smb": "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EncryptData | ConvertTo-Json",
    "rdp": ("$t='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server'; [pscustomobject]@{"
            "Denied=(Get-ItemProperty $t).fDenyTSConnections; NLA=(Get-ItemProperty \"$t\\WinStations\\RDP-Tcp\").UserAuthentication} | ConvertTo-Json"),
    "security_settings": ("$l='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; [pscustomobject]@{"
                          "UAC=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA;"
                          "LsaRunAsPPL=(Get-ItemProperty $l).RunAsPPL; LmCompatibilityLevel=(Get-ItemProperty $l).LmCompatibilityLevel;"
                          "WDigest=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -EA SilentlyContinue).UseLogonCredential;"
                          "PowerShellV2=((Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -EA SilentlyContinue).State)} | ConvertTo-Json"),
    "installed_software": ("Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
                           "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -EA SilentlyContinue | "
                           "Where-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher | Sort-Object DisplayName -Unique | "
                           "Select-Object -First 300 | ConvertTo-Json"),
    "listening": "Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort -Unique | Sort-Object LocalPort | ConvertTo-Json",
}


def windows_check(cid, host, check):
    c = _get(cid, {"windows"})
    f = c["fields"]
    if host not in (f.get("hosts") or "").split():
        raise ValueError(f"{host} isn't one of this connector's machines")
    if check not in WINDOWS_CHECKS:
        raise ValueError("unknown check")
    import winrm
    s = winrm.Session(f"https://{host}:{int(f.get('port') or 5986)}/wsman", auth=(f["username"], f["password"]), transport="ntlm",
                      server_cert_validation="validate" if f.get("verify_tls") else "ignore", operation_timeout_sec=60, read_timeout_sec=90)
    r = s.run_ps(WINDOWS_CHECKS[check])
    out, err = r.std_out.decode(errors="replace"), r.std_err.decode(errors="replace")
    if r.status_code != 0 and not out.strip():
        return {"error": re.sub(r"<[^>]+>", " ", err)[:400] or f"exit {r.status_code}"}
    return {"host": host, "check": check, "output": out[:24000], **({"truncated": True} if len(out) > 24000 else {})}
