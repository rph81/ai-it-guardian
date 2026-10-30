"""More remediation recipes: Linux updates, Windows hardening and updates (agentless, WinRM), Microsoft 365 (separate
write app) and NinjaOne patch jobs.

Same contract as remediate.py: each recipe is backup -> apply -> verify, with a rollback that undoes the change. They
use only the fix credentials in the vault's "fix-accounts" record (never the read-only connectors the agents use) and
run only after an admin turned remediation on and approved the change with a passkey.
"""
import base64
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from . import connectors as conn

APT_AUTO = "/etc/apt/apt.conf.d/20auto-upgrades"
APT_AUTO_SETTING = 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
SUDOERS_EXTRA = (", /usr/bin/apt-get update, /usr/bin/apt-get -y -o Dpkg\\:\\:Options\\:\\:\\=--force-confold upgrade, "
                 f"/usr/bin/tee {APT_AUTO}, /usr/bin/cat {APT_AUTO}, /usr/bin/rm -f {APT_AUTO}")
WORK = r"C:\ProgramData\Guardian"
GRAPH = "https://graph.microsoft.com/v1.0"
M365_ALLOWED = {"User.Read.All", "User.EnableDisableAccount.All", "MailboxSettings.ReadWrite", "Organization.Read.All",
                "AuditLog.Read.All", "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "Application.Read.All",
                "RoleManagement.Read.Directory", "Directory.Read.All"}
NINJA_HOSTS = {"app": "app.ninjarmm.com", "eu": "eu.ninjarmm.com", "oc": "oc.ninjarmm.com", "ca": "ca.ninjarmm.com",
               "us2": "us2.ninjarmm.com"}
CA_NAME = "Guardian: block legacy authentication"
STALE_DAYS = 90


class Failed(Exception):
    pass


RECIPES = {
    "linux.security_updates": {
        "title": "Install pending package updates", "applies": "Debian / Ubuntu servers", "risk": "medium", "status": "active",
        "backup": "Proxmox snapshot first when the server is a Proxmox guest (set in its fix account); package list saved",
        "rollback": "One click: restore the snapshot. Without a snapshot: manual",
        "needs": "Linux fix account (sudo for apt-get update / upgrade)",
        "breaks": "Updated services restart; a kernel update needs a reboot (Guardian reports it, it doesn't reboot). "
                  "Packages that need new dependencies are held back (apt-get upgrade, not dist-upgrade).",
    },
    "linux.auto_updates": {
        "title": "Turn on automatic security updates", "applies": "Debian / Ubuntu with unattended-upgrades", "risk": "low",
        "status": "active", "backup": "The settings file is saved (or noted as new)", "rollback": "Automatic",
        "needs": "Linux fix account", "breaks": "Security updates install daily by themselves; services may restart.",
    },
    "windows.smb1_off": {
        "title": "Turn off SMBv1", "applies": "Windows servers and PCs (WinRM)", "risk": "low", "status": "active",
        "backup": "Current setting saved", "rollback": "Automatic", "needs": "Windows fix account (local admin)",
        "breaks": "Very old devices (Windows XP, old NAS or scanners using SMBv1) can no longer use this machine's shares.",
    },
    "windows.firewall_on": {
        "title": "Turn on Windows Firewall (all profiles)", "applies": "Windows servers and PCs (WinRM)", "risk": "medium",
        "status": "active", "backup": "Profile states saved",
        "rollback": "Automatic: a dead-man switch on the machine restores the old state in 2 minutes unless Guardian "
                    "can still reach it", "needs": "Windows fix account (local admin)",
        "breaks": "Programs that listen on the network without a firewall rule stop being reachable.",
    },
    "windows.defender_rt_on": {
        "title": "Turn on Defender real-time protection", "applies": "Windows with Microsoft Defender", "risk": "low",
        "status": "active", "backup": "Current setting saved", "rollback": "Automatic", "needs": "Windows fix account",
        "breaks": "Nothing normally. If another antivirus is installed, Defender stays passive and the check fails safely.",
    },
    "windows.updates_install": {
        "title": "Install Windows updates", "applies": "Windows servers and PCs (WinRM, agentless)", "risk": "medium",
        "status": "active", "backup": "List of installed updates saved",
        "rollback": "Manual (Settings › Windows Update › Update history › Uninstall)",
        "needs": "Windows fix account (local admin)",
        "breaks": "Installs all pending security and quality updates through Windows' own update engine. A restart is "
                  "usually needed: Guardian reports it and doesn't restart unless you chose to.",
    },
    "m365.forwarding_off": {
        "title": "Remove mail rules forwarding outside the company", "applies": "Microsoft 365 mailboxes", "risk": "low",
        "status": "active", "backup": "Every rule removed is exported", "rollback": "One click: re-created",
        "needs": "Microsoft 365 fix app (MailboxSettings.ReadWrite)",
        "breaks": "Mail no longer goes to the outside addresses. Check with the users first if forwarding was intended.",
    },
    "m365.disable_stale": {
        "title": "Disable stale accounts (no sign-in for 90+ days)", "applies": "Microsoft 365 / Entra ID", "risk": "medium",
        "status": "active", "backup": "Each account's state is saved", "rollback": "One click: re-enabled",
        "needs": "Microsoft 365 fix app (User.EnableDisableAccount.All, AuditLog.Read.All; Entra ID P1 for sign-in data)",
        "breaks": "Those people can't sign in. Accounts with an admin role, guests and accounts created in the last 90 "
                  "days are left alone; at most 50 per change.",
    },
    "m365.legacy_auth_report": {
        "title": "Block legacy sign-in (Conditional Access, report-only)", "applies": "Microsoft 365 / Entra ID P1",
        "risk": "low", "status": "active", "backup": "Notes that the policy didn't exist", "rollback": "One click: deleted",
        "needs": "Microsoft 365 fix app (Policy.ReadWrite.ConditionalAccess)",
        "breaks": "Nothing yet: report-only shows in the sign-in logs who would be blocked. Switch it to On in Entra "
                  "after a week without surprises.",
    },
    "ninja.os_patches": {
        "title": "Install missing OS patches through NinjaOne", "applies": "Devices managed by NinjaOne", "risk": "medium",
        "status": "active", "backup": "Pending patch list saved", "rollback": "Manual (through NinjaOne)",
        "needs": "NinjaOne connector + NinjaOne patch credentials (management scope)",
        "breaks": "NinjaOne installs the approved patches with its own policy (reboot behaviour follows the device's "
                  "NinjaOne policy).",
    },
}


# -- small HTTP helper for JSON APIs -----------------------------------------------------------------------------
def _req(method, url, token=None, body=None, headers=None, ctx=None, form=None, timeout=30):
    h = {"User-Agent": "ai-guardian", "Accept": "application/json", **(headers or {})}
    data = None
    if token:
        h["Authorization"] = token if " " in token else f"Bearer {token}"
    if body is not None:
        data, h["Content-Type"] = json.dumps(body).encode(), "application/json"
    if form is not None:
        data, h["Content-Type"] = urllib.parse.urlencode(form).encode(), "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, context=ctx or ssl.create_default_context(), timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw.strip() else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw[:300]
    except (urllib.error.URLError, OSError) as e:
        raise Failed(f"Can't reach {urllib.parse.urlsplit(url).hostname}: {getattr(e, 'reason', e)}")


def _ok(st, d, what):
    if st >= 300:
        err = (d or {}).get("error", d) if isinstance(d, dict) else d
        msg = err.get("message", err) if isinstance(err, dict) else err
        raise Failed(f"{what}: {st} {str(msg)[:250]}")
    return d


# -- Proxmox snapshot (optional, for Linux guests) ----------------------------------------------------------------
def _pve(ctx):
    p = (ctx.fix or {}).get("proxmox") or {}
    if not p.get("host"):
        return None
    tls, _ = conn._tls_context(p["host"], int(p.get("port") or 8006), p.get("verify_tls"), p.get("pin"))
    return p, tls, f'PVEAPIToken={p["token_id"]}={p["token_secret"]}', f'https://{p["host"]}:{int(p.get("port") or 8006)}/api2/json'


def _guest(ctx, host):
    g = (ctx.fix_hosts.get(host) or {}).get("guest") or ""
    m = re.fullmatch(r"([\w.-]{1,63})/(qemu|lxc)/(\d{2,9})", g)
    return m.groups() if m else None


def snapshot(ctx, host, label):
    pve, guest = _pve(ctx), _guest(ctx, host)
    if not pve or not guest:
        return None
    p, tls, auth, base = pve
    node, kind, vmid = guest
    name = f"guardian-{label}-{int(time.time())}"[:40]
    st, d = _req("POST", f"{base}/nodes/{node}/{kind}/{vmid}/snapshot", auth, ctx=tls,
                 form={"snapname": name, "description": "Taken by AI IT Guardian before a change"})
    _ok(st, d, "Proxmox snapshot")
    _wait_task(tls, auth, base, node, (d or {}).get("data"))
    return {"node": node, "kind": kind, "vmid": vmid, "name": name}


def _wait_task(tls, auth, base, node, upid, limit=600):
    if not upid:
        return
    end = time.time() + limit
    while time.time() < end:
        st, d = _req("GET", f"{base}/nodes/{node}/tasks/{urllib.parse.quote(upid)}/status", auth, ctx=tls)
        data = (d or {}).get("data") or {}
        if data.get("status") == "stopped":
            if data.get("exitstatus") != "OK":
                raise Failed(f"Proxmox task failed: {data.get('exitstatus')}")
            return
        time.sleep(3)
    raise Failed("Proxmox task didn't finish in time")


def snapshot_rollback(ctx, snap):
    p, tls, auth, base = _pve(ctx)
    st, d = _req("POST", f'{base}/nodes/{snap["node"]}/{snap["kind"]}/{snap["vmid"]}/snapshot/{snap["name"]}/rollback', auth, ctx=tls,
                 form={"start": 1} if snap["kind"] == "qemu" else {})
    _ok(st, d, "Proxmox rollback")
    _wait_task(tls, auth, base, snap["node"], (d or {}).get("data"))


# -- Linux ----------------------------------------------------------------------------------------------------------
def _ssh_ok(ctx, host, cmd, what, stdin=None, timeout=60):
    r = ctx.ssh(host, cmd, stdin=stdin, timeout=timeout)
    if r.returncode != 0:
        raise Failed(f"{what}: {(r.stderr or r.stdout or 'failed').strip()[-300:]}")
    return r.stdout


def _upgradable(ctx, h):
    out = _ssh_ok(ctx, h, "LC_ALL=C apt list --upgradable 2>/dev/null", "List pending updates")
    return [l.split("/", 1)[0] for l in out.splitlines() if "/" in l and "upgradable from" in l]


def upd_backup(ctx, p):
    h = p["host"]
    _ssh_ok(ctx, h, "true", "Key login with the fix account")
    _ssh_ok(ctx, h, "sudo -n /usr/bin/apt-get update", "apt-get update", timeout=300)
    pending = _upgradable(ctx, h)
    if not pending:
        raise Failed("No pending updates: nothing to do.")
    return {"host": h, "pending": pending[:500], "snapshot": snapshot(ctx, h, "apt")}


def upd_apply(ctx, p):
    _ssh_ok(ctx, p["host"], "DEBIAN_FRONTEND=noninteractive sudo -n /usr/bin/apt-get -y -o Dpkg::Options::=--force-confold upgrade", "apt-get upgrade",
            timeout=3600)


def upd_verify(ctx, p):
    h = p["host"]
    _ssh_ok(ctx, h, "true", "Key login after updating")
    left = _upgradable(ctx, h)
    reboot = ctx.ssh(h, "test -f /var/run/reboot-required").returncode == 0
    return (f"Updated; {len(left)} package(s) held back (need dist-upgrade)" if left else "All packages up to date") + \
        (" · a reboot is needed" if reboot else "")


def upd_rollback(ctx, b):
    if not b.get("snapshot"):
        raise Failed("No Proxmox snapshot was taken (no Proxmox fix token or guest set): roll back by hand.")
    snapshot_rollback(ctx, b["snapshot"])


def auto_backup(ctx, p):
    h = p["host"]
    _ssh_ok(ctx, h, "true", "Key login with the fix account")
    _ssh_ok(ctx, h, "dpkg-query -W -f='${Status}' unattended-upgrades | grep -q 'install ok installed'",
            "The unattended-upgrades package isn't installed (apt install unattended-upgrades)")
    old = ctx.ssh(h, f"sudo -n /usr/bin/cat {APT_AUTO}")
    return {"host": h, "existed": old.returncode == 0, "content": old.stdout if old.returncode == 0 else ""}


def auto_apply(ctx, p):
    _ssh_ok(ctx, p["host"], f"sudo -n /usr/bin/tee {APT_AUTO} >/dev/null", "Write setting", stdin=APT_AUTO_SETTING)


def auto_verify(ctx, p):
    out = _ssh_ok(ctx, p["host"], "apt-config dump APT::Periodic", "Read apt settings")
    if 'Unattended-Upgrade "1"' not in out:
        raise Failed("apt doesn't report automatic upgrades as on (another file may override it).")
    return "Automatic security updates are on"


def auto_rollback(ctx, b):
    if b["existed"]:
        _ssh_ok(ctx, b["host"], f"sudo -n /usr/bin/tee {APT_AUTO} >/dev/null", "Restore setting", stdin=b["content"])
    else:
        _ssh_ok(ctx, b["host"], f"sudo -n /usr/bin/rm -f {APT_AUTO}", "Remove setting")


# -- Windows (WinRM, fix account in the local Administrators group) -------------------------------------------------
def winrm(ctx, host):
    acct = ((ctx.fix or {}).get("windows") or {}).get(host)
    if not acct:
        raise Failed("No Windows fix account for this machine")
    if ctx.winrm_factory:
        return ctx.winrm_factory(host, acct)
    import winrm as _w
    return _w.Session(f"https://{host}:{int(acct.get('port') or 5986)}/wsman", auth=(acct["user"], acct["password"]),
                      transport="ntlm", server_cert_validation="validate" if acct.get("verify_tls") else "ignore",
                      operation_timeout_sec=60, read_timeout_sec=90)


def ps(ctx, host, script, what):
    r = winrm(ctx, host).run_ps(script)
    out, err = r.std_out.decode(errors="replace").strip(), r.std_err.decode(errors="replace").strip()
    if r.status_code != 0:
        raise Failed(f"{what}: {(err or out)[-300:]}")
    return out


def smb_backup(ctx, p):
    v = ps(ctx, p["host"], "(Get-SmbServerConfiguration).EnableSMB1Protocol", "Read SMBv1 setting").lower()
    if v == "false":
        raise Failed("SMBv1 is already off: nothing to do.")
    return {"host": p["host"], "smb1": v == "true"}


def smb_apply(ctx, p):
    ps(ctx, p["host"], "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false", "Turn off SMBv1")


def smb_verify(ctx, p):
    if ps(ctx, p["host"], "(Get-SmbServerConfiguration).EnableSMB1Protocol", "Re-read").lower() != "false":
        raise Failed("SMBv1 still reported on")
    return "SMBv1 is off"


def smb_rollback(ctx, b):
    ps(ctx, b["host"], f"Set-SmbServerConfiguration -EnableSMB1Protocol ${'true' if b['smb1'] else 'false'} -Force -Confirm:$false", "Restore SMBv1")


def fw_backup(ctx, p):
    out = ps(ctx, p["host"], "Get-NetFirewallProfile | ForEach-Object { \"$($_.Name)=$($_.Enabled)\" }", "Read firewall profiles")
    state = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
    if state and all(v.lower() == "true" for v in state.values()):
        raise Failed("The firewall is already on for every profile: nothing to do.")
    return {"host": p["host"], "profiles": state, "token": base64.b32encode(__import__("os").urandom(10)).decode().lower()}


def _fw_restore_lines(profiles):
    return "; ".join(f"Set-NetFirewallProfile -Name {n} -Enabled {('True' if v.lower() == 'true' else 'False')}"
                     for n, v in profiles.items() if re.fullmatch(r"[A-Za-z]+", n))


def fw_apply(ctx, p):
    b = ctx.record["backup"]
    keep = f"{WORK}\\keep-{b['token']}"
    # dead-man switch: turn the firewall on, then restore the old state unless Guardian proves it can still connect
    script = (f"New-Item -ItemType Directory -Force -Path '{WORK}' | Out-Null; "
              f"$s = \"Set-NetFirewallProfile -All -Enabled True; Start-Sleep 120; if (-not (Test-Path '{keep}')) {{ {_fw_restore_lines(b['profiles'])} }}\"; "
              f"$a = New-ScheduledTaskAction -Execute powershell.exe -Argument (\"-NoProfile -Command \" + $s); "
              f"Register-ScheduledTask -TaskName 'Guardian-firewall-{b['token']}' -Action $a -User SYSTEM -RunLevel Highest -Force | Out-Null; "
              f"Start-ScheduledTask -TaskName 'Guardian-firewall-{b['token']}'")
    ps(ctx, p["host"], script, "Start the firewall change")
    time.sleep(ctx.wait(20))


def fw_verify(ctx, p):
    b = ctx.record["backup"]
    try:
        ps(ctx, p["host"], f"New-Item -ItemType File -Force -Path '{WORK}\\keep-{b['token']}' | Out-Null", "Confirm access")
    except Exception as e:                                          # noqa: BLE001 - any failure means we lost access
        raise Failed(f"Guardian can't reach the machine with the firewall on ({e}); it restores itself in 2 minutes.")
    out = ps(ctx, p["host"], "Get-NetFirewallProfile | ForEach-Object { \"$($_.Name)=$($_.Enabled)\" }", "Re-read profiles")
    if any(l.split("=", 1)[1].lower() != "true" for l in out.splitlines() if "=" in l):
        raise Failed("Not every profile is on")
    ps(ctx, p["host"], f"Unregister-ScheduledTask -TaskName 'Guardian-firewall-{b['token']}' -Confirm:$false -ErrorAction SilentlyContinue",
       "Clean up")
    return "Firewall on for every profile; Guardian still has access"


def fw_rollback(ctx, b):
    try:
        ps(ctx, b["host"], _fw_restore_lines(b["profiles"]), "Restore firewall profiles")
    except Failed:
        time.sleep(ctx.wait(130))                                   # the switch on the machine restores it itself
        ps(ctx, b["host"], "Get-NetFirewallProfile | Out-Null", "Reach the machine after the automatic restore")


def def_backup(ctx, p):
    v = ps(ctx, p["host"], "(Get-MpPreference).DisableRealtimeMonitoring", "Read Defender setting").lower()
    return {"host": p["host"], "disabled": v == "true"}


def def_apply(ctx, p):
    ps(ctx, p["host"], "Set-MpPreference -DisableRealtimeMonitoring $false", "Turn on real-time protection")


def def_verify(ctx, p):
    if ps(ctx, p["host"], "(Get-MpComputerStatus).RealTimeProtectionEnabled", "Re-read").lower() != "true":
        raise Failed("Real-time protection still off (Tamper Protection, policy or another antivirus may control it)")
    return "Real-time protection is on"


def def_rollback(ctx, b):
    ps(ctx, b["host"], f"Set-MpPreference -DisableRealtimeMonitoring ${'true' if b['disabled'] else 'false'}", "Restore Defender setting")


WU_SCRIPT = r"""
$ErrorActionPreference = 'Stop'; $out = '%OUT%'
try {
  $s = New-Object -ComObject Microsoft.Update.Session
  $r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software' and IsHidden=0")
  $c = New-Object -ComObject Microsoft.Update.UpdateColl
  foreach ($u in $r.Updates) { if (-not $u.EulaAccepted) { $u.AcceptEula() }; [void]$c.Add($u) }
  $titles = @($r.Updates | ForEach-Object { $_.Title })
  if ($c.Count -gt 0) {
    $d = $s.CreateUpdateDownloader(); $d.Updates = $c; [void]$d.Download()
    $i = $s.CreateUpdateInstaller(); $i.Updates = $c; $res = $i.Install()
    $codes = @(0..($c.Count-1) | ForEach-Object { $res.GetUpdateResult($_).ResultCode })
    @{done=$true; titles=$titles; codes=$codes; reboot=$res.RebootRequired} | ConvertTo-Json -Compress | Set-Content $out
  } else { @{done=$true; titles=@(); codes=@(); reboot=$false} | ConvertTo-Json -Compress | Set-Content $out }
} catch { @{done=$true; error=$_.Exception.Message} | ConvertTo-Json -Compress | Set-Content $out }
"""


def wu_backup(ctx, p):
    out = ps(ctx, p["host"], "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 50 -ExpandProperty HotFixID",
             "List installed updates")
    return {"host": p["host"], "installed": out.split()[:50], "token": base64.b32encode(__import__("os").urandom(10)).decode().lower()}


def wu_apply(ctx, p):
    # Windows' update engine refuses to install from a remote session, so it runs once as a scheduled task (SYSTEM).
    b = ctx.record["backup"]
    out = f"{WORK}\\wu-{b['token']}.json"
    script = WU_SCRIPT.replace("%OUT%", out)
    enc = base64.b64encode(script.encode("utf-16-le")).decode()
    ps(ctx, p["host"], f"New-Item -ItemType Directory -Force -Path '{WORK}' | Out-Null; "
                       f"$a = New-ScheduledTaskAction -Execute powershell.exe -Argument '-NoProfile -EncodedCommand {enc}'; "
                       f"Register-ScheduledTask -TaskName 'Guardian-updates-{b['token']}' -Action $a -User SYSTEM -RunLevel Highest -Force | Out-Null; "
                       f"Start-ScheduledTask -TaskName 'Guardian-updates-{b['token']}'", "Start Windows Update")
    end = time.time() + ctx.wait(3 * 3600)
    while True:
        time.sleep(ctx.wait(30))
        res = ps(ctx, p["host"], f"if (Test-Path '{out}') {{ Get-Content '{out}' -Raw }}", "Read progress")
        if res:
            b["result"] = json.loads(res)
            ps(ctx, p["host"], f"Unregister-ScheduledTask -TaskName 'Guardian-updates-{b['token']}' -Confirm:$false; Remove-Item '{out}'",
               "Clean up")
            if b["result"].get("error"):
                raise Failed("Windows Update: " + b["result"]["error"][:250])
            if p.get("reboot") and b["result"].get("reboot"):
                ps(ctx, p["host"], 'shutdown.exe /r /t 900 /c "AI IT Guardian: restarting in 15 minutes to finish updates"', "Schedule restart")
            return
        if time.time() > end:
            raise Failed("Windows Update didn't finish within 3 hours")


def wu_verify(ctx, p):
    r = ctx.record["backup"].get("result") or {}
    titles, codes = r.get("titles") or [], r.get("codes") or []
    if not titles:
        return "No pending updates were found"
    ok = sum(1 for c in codes if c in (2, 3))                      # 2 succeeded, 3 succeeded with errors
    if ok == 0:
        raise Failed(f"None of the {len(titles)} updates installed (result codes {codes[:10]})")
    msg = f"{ok} of {len(titles)} updates installed"
    if r.get("reboot"):
        msg += " · restart " + ("scheduled in 15 minutes" if p.get("reboot") else "needed")
    return msg


def wu_rollback(ctx, b):
    raise Failed("Windows updates aren't rolled back automatically: uninstall a specific update in Settings › "
                 "Windows Update › Update history if it causes trouble.")


# -- Microsoft 365 (separate fix app) -----------------------------------------------------------------------------
def m365_token(ctx):
    f = (ctx.fix or {}).get("m365") or {}
    if not f.get("client_id"):
        raise Failed("No Microsoft 365 fix app is set up")
    if ctx.m365_token:
        return ctx.m365_token
    token, roles = conn.graph_token(f)
    extra = sorted(set(roles) - M365_ALLOWED)
    if extra:
        raise Failed("The fix app has permissions Guardian doesn't use; remove them first: " + ", ".join(extra))
    ctx.m365_token = token
    return token


def _g(ctx, method, path, body=None):
    path = path.replace(" ", "%20")
    st, d = _req(method, GRAPH + path if path.startswith("/") else path, m365_token(ctx), body)
    return st, d


def _pages(ctx, path, limit=20):
    rows, url = [], GRAPH + path.replace(" ", "%20")
    for _ in range(limit):
        st, d = _g(ctx, "GET", url)
        _ok(st, d, "Microsoft Graph")
        rows += d.get("value", [])
        url = d.get("@odata.nextLink")
        if not url or not url.startswith(GRAPH):
            break
    return rows


def _external(rule, domains):
    acts = rule.get("actions") or {}
    addrs = [a.get("emailAddress", {}).get("address", "") for k in ("forwardTo", "redirectTo", "forwardAsAttachmentTo")
             for a in acts.get(k) or []]
    return [a for a in addrs if a and a.split("@")[-1].lower() not in domains]


def fwd_backup(ctx, p):
    org = _pages(ctx, "/organization?$select=verifiedDomains")
    domains = {d["name"].lower() for o in org for d in o.get("verifiedDomains", [])}
    found = []
    for u in _pages(ctx, "/users?$select=id,userPrincipalName,accountEnabled,userType&$filter=userType eq 'Member'&$top=999"):
        st, d = _g(ctx, "GET", f"/users/{u['id']}/mailFolders/inbox/messageRules")
        if st != 200:
            continue                                           # no mailbox
        for rule in d.get("value", []):
            ext = _external(rule, domains)
            if ext:
                found.append({"user": u["id"], "upn": u["userPrincipalName"], "rule": rule, "to": ext})
    if not found:
        raise Failed("No rules forward mail outside the company: nothing to do.")
    return {"rules": found[:200]}


def fwd_apply(ctx, p):
    for f in ctx.record["backup"]["rules"]:
        st, d = _g(ctx, "DELETE", f"/users/{f['user']}/mailFolders/inbox/messageRules/{f['rule']['id']}")
        _ok(st, d, f"Delete rule of {f['upn']}")


def fwd_verify(ctx, p):
    left = []
    for f in ctx.record["backup"]["rules"]:
        st, d = _g(ctx, "GET", f"/users/{f['user']}/mailFolders/inbox/messageRules/{f['rule']['id']}")
        if st == 200:
            left.append(f["upn"])
    if left:
        raise Failed("Rules still present for " + ", ".join(left[:5]))
    return f"{len(ctx.record['backup']['rules'])} forwarding rule(s) removed: " + ", ".join(sorted({f['upn'] for f in ctx.record['backup']['rules']})[:10])


RULE_FIELDS = ("displayName", "sequence", "isEnabled", "conditions", "actions", "exceptions")


def fwd_rollback(ctx, b):
    for f in b["rules"]:
        body = {k: v for k, v in f["rule"].items() if k in RULE_FIELDS and v is not None}
        st, d = _g(ctx, "POST", f"/users/{f['user']}/mailFolders/inbox/messageRules", body)
        _ok(st, d, f"Re-create rule of {f['upn']}")


def stale_backup(ctx, p):
    cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - STALE_DAYS * 86400))
    admins = {m["id"] for r in _pages(ctx, "/directoryRoles?$select=id") for m in _pages(ctx, f"/directoryRoles/{r['id']}/members?$select=id")}
    users = _pages(ctx, "/users?$select=id,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity&$top=999")
    stale = []
    for u in users:
        last = ((u.get("signInActivity") or {}).get("lastSignInDateTime")) or ""
        if (u.get("accountEnabled") and u.get("userType") == "Member" and u["id"] not in admins
                and (u.get("createdDateTime") or "9") < cutoff and last and last < cutoff):
            stale.append({"id": u["id"], "upn": u["userPrincipalName"], "last": last})
    if not users or not any("signInActivity" in u for u in users):
        raise Failed("Sign-in data isn't available (needs Entra ID P1 and AuditLog.Read.All)")
    if not stale:
        raise Failed("No enabled account is older than 90 days without a sign-in: nothing to do.")
    return {"accounts": stale[:50], "more": max(0, len(stale) - 50)}


def stale_apply(ctx, p):
    for a in ctx.record["backup"]["accounts"]:
        _ok(*_g(ctx, "PATCH", f"/users/{a['id']}", {"accountEnabled": False}), f"Disable {a['upn']}")


def stale_verify(ctx, p):
    still = [a["upn"] for a in ctx.record["backup"]["accounts"]
             if (_g(ctx, "GET", f"/users/{a['id']}?$select=accountEnabled")[1] or {}).get("accountEnabled")]
    if still:
        raise Failed("Still enabled: " + ", ".join(still[:5]))
    b = ctx.record["backup"]
    return f"{len(b['accounts'])} account(s) disabled" + (f"; {b['more']} more remain for a next change" if b["more"] else "")


def stale_rollback(ctx, b):
    for a in b["accounts"]:
        _ok(*_g(ctx, "PATCH", f"/users/{a['id']}", {"accountEnabled": True}), f"Re-enable {a['upn']}")


def ca_backup(ctx, p):
    pol = _pages(ctx, "/identity/conditionalAccess/policies?$select=id,displayName,state")
    if any(x.get("displayName") == CA_NAME for x in pol):
        raise Failed("Guardian's policy already exists: change it in Entra.")
    return {"existed": False}


def ca_apply(ctx, p):
    body = {"displayName": CA_NAME, "state": "enabledForReportingButNotEnforced",
            "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]},
                           "clientAppTypes": ["exchangeActiveSync", "other"]},
            "grantControls": {"operator": "OR", "builtInControls": ["block"]}}
    st, d = _g(ctx, "POST", "/identity/conditionalAccess/policies", body)
    _ok(st, d, "Create Conditional Access policy")
    ctx.record["backup"]["policy"] = d.get("id")


def ca_verify(ctx, p):
    pid = ctx.record["backup"].get("policy")
    st, d = _g(ctx, "GET", f"/identity/conditionalAccess/policies/{pid}")
    _ok(st, d, "Read policy")
    if d.get("state") != "enabledForReportingButNotEnforced":
        raise Failed("The policy isn't in report-only mode")
    return "Policy created in report-only mode: check Entra › Sign-in logs › Report-only after a week, then switch it to On"


def ca_rollback(ctx, b):
    if b.get("policy"):
        st, d = _g(ctx, "DELETE", f"/identity/conditionalAccess/policies/{b['policy']}")
        if st not in (204, 404):
            _ok(st, d, "Delete policy")


# -- NinjaOne -------------------------------------------------------------------------------------------------------
def ninja_token(f, scope):
    host = NINJA_HOSTS.get(f.get("region") or "app")
    if not host:
        raise Failed("Unknown NinjaOne region")
    st, d = _req("POST", f"https://{host}/ws/oauth/token", form={"grant_type": "client_credentials", "client_id": f["client_id"],
                                                                 "client_secret": f["client_secret"], "scope": scope})
    if st != 200 or not isinstance(d, dict) or "access_token" not in d:
        raise Failed("NinjaOne refused the credentials" + (f": {d.get('error_description') or d.get('error')}" if isinstance(d, dict) else ""))
    return host, d["access_token"]


def ninja_patch(ctx, p):
    f = (ctx.fix or {}).get("ninja") or {}
    if not f.get("client_id"):
        raise Failed("No NinjaOne patch credentials are set up")
    return ninja_token(f, "management control")


def nj_backup(ctx, p):
    host, tok = ninja_patch(ctx, p)
    st, d = _req("GET", f"https://{host}/v2/device/{int(p['device'])}/os-patches?status=PENDING", tok)
    _ok(st, d, "Read pending patches")
    rows = d if isinstance(d, list) else (d or {}).get("results", [])
    if not rows:
        raise Failed("NinjaOne lists no pending OS patches for this device: nothing to do.")
    return {"device": p["device"], "pending": [{"name": r.get("name"), "kb": r.get("kbNumber"), "severity": r.get("severity")} for r in rows][:200]}


def nj_apply(ctx, p):
    host, tok = ninja_patch(ctx, p)
    st, d = _req("POST", f"https://{host}/v2/device/{int(p['device'])}/patch/os/apply", tok)
    _ok(st, d, "Ask NinjaOne to apply OS patches")


def nj_verify(ctx, p):
    return (f"NinjaOne accepted the job for {len(ctx.record['backup']['pending'])} pending patch(es); it installs them with "
            "the device's policy. Re-check the finding afterwards to confirm.")


def nj_rollback(ctx, b):
    raise Failed("Patches installed by NinjaOne are rolled back in NinjaOne (or Windows Update history).")


STEPS = {
    "linux.security_updates": (upd_backup, upd_apply, upd_verify, upd_rollback),
    "linux.auto_updates": (auto_backup, auto_apply, auto_verify, auto_rollback),
    "windows.smb1_off": (smb_backup, smb_apply, smb_verify, smb_rollback),
    "windows.firewall_on": (fw_backup, fw_apply, fw_verify, fw_rollback),
    "windows.defender_rt_on": (def_backup, def_apply, def_verify, def_rollback),
    "windows.updates_install": (wu_backup, wu_apply, wu_verify, wu_rollback),
    "m365.forwarding_off": (fwd_backup, fwd_apply, fwd_verify, fwd_rollback),
    "m365.disable_stale": (stale_backup, stale_apply, stale_verify, stale_rollback),
    "m365.legacy_auth_report": (ca_backup, ca_apply, ca_verify, ca_rollback),
    "ninja.os_patches": (nj_backup, nj_apply, nj_verify, nj_rollback),
}


# -- proposals: which of these fit the latest run's findings ------------------------------------------------------
IP = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
MATCH = [
    ("linux.security_updates", "linux", re.compile(r"(pending|missing|outstanding|available)\s+(security\s+)?(package\s+)?updates|updates?\s+(are\s+)?(pending|waiting|available|outstanding)|upgradable|vulnerable packages|outdated packages", re.I)),
    ("linux.auto_updates", "linux", re.compile(r"(unattended|automatic)[- ](security )?(upgrades?|updates?)", re.I)),
    ("windows.smb1_off", "windows", re.compile(r"smb\s?v?1", re.I)),
    ("windows.firewall_on", "windows", re.compile(r"firewall.{0,40}(off|disabled|not enabled)|(off|disabled).{0,20}firewall", re.I)),
    ("windows.defender_rt_on", "windows", re.compile(r"real[- ]?time protection.{0,30}(off|disabled)|defender.{0,40}(off|disabled)", re.I)),
    ("windows.updates_install", "windows", re.compile(r"missing (windows |security |cumulative )?updates|updates? (not installed|missing|behind)|outdated (build|patch)|pending updates", re.I)),
]
M365_MATCH = [
    ("m365.forwarding_off", re.compile(r"forward(ing|s)?.{0,60}(outside|external)|external forward", re.I)),
    ("m365.disable_stale", re.compile(r"stale|inactive|dormant|no sign-?in", re.I)),
    ("m365.legacy_auth_report", re.compile(r"legacy (auth|sign-?in|protocol)|basic auth", re.I)),
]


def proposals(graph, fix, collector_ip=None):
    findings = [f for f in graph.get("findings") or [] if f.get("status") not in ("resolved", "duplicate")]
    linux, windows = (fix or {}).get("hosts") or {}, (fix or {}).get("windows") or {}
    out, seen = [], set()
    for f in findings:
        text = f'{f.get("title", "")} {f.get("evidence", "")}'
        ip = f.get("asset", "")
        for recipe, kind, rx in MATCH:
            if not IP.match(ip) or not rx.search(text) or (recipe, ip) in seen:
                continue
            if kind == "linux" and ip in windows or kind == "windows" and ip in linux:
                continue
            osname = " ".join(str((graph.get("assets") or {}).get(ip, {}).get(k) or "") for k in ("os", "os_guess", "device_type")).lower()
            is_win = "windows" in osname or "windows" in text.lower()
            is_lin = any(w in osname for w in ("linux", "debian", "ubuntu", "proxmox")) or re.search(r"\b(apt|debian|ubuntu|linux)\b", text, re.I)
            if kind == "linux" and is_win and not is_lin or kind == "windows" and is_lin and not is_win:
                continue                                    # a Windows finding never gets a Linux recipe, and the other way round
            seen.add((recipe, ip))
            blocked = "This is Guardian's own host: change it by hand." if ip == collector_ip else None
            if not blocked and kind == "linux" and ip not in linux:
                blocked = "Needs a Linux fix account on this server (add it below)."
            if not blocked and kind == "windows" and ip not in windows:
                blocked = "Needs a Windows fix account on this machine (add it below)."
            title = {"linux.security_updates": "Install pending updates on", "linux.auto_updates": "Turn on automatic security updates on",
                     "windows.smb1_off": "Turn off SMBv1 on", "windows.firewall_on": "Turn on Windows Firewall on",
                     "windows.defender_rt_on": "Turn on Defender real-time protection on",
                     "windows.updates_install": "Install Windows updates on"}[recipe]
            out.append({"id": f"{recipe}:{ip}", "recipe": recipe, "target": ip, "title": f"{title} {ip}",
                        "why": f'{f["id"]}: {f.get("title", "")}', "finding": f["id"], "params": {"host": ip},
                        "ready": blocked is None, "blocked": blocked})
        for recipe, rx in M365_MATCH:
            if f.get("layer") in ("m365", "devices") and rx.search(text) and recipe not in seen:
                seen.add(recipe)
                blocked = None if ((fix or {}).get("m365") or {}).get("client_id") else "Needs the Microsoft 365 fix app (add it below)."
                out.append({"id": recipe, "recipe": recipe, "target": "microsoft365", "title": RECIPES[recipe]["title"],
                            "why": f'{f["id"]}: {f.get("title", "")}', "finding": f["id"], "params": {},
                            "ready": blocked is None, "blocked": blocked})
    ninja = (fix or {}).get("ninja") or {}
    for d in (graph.get("ninja") or {}).get("devices_with_pending", [])[:100]:
        fid = next((f["id"] for f in findings if d.get("name") and d["name"].lower() in (f.get("title", "") + f.get("evidence", "")).lower()), None)
        out.append({"id": f"ninja.os_patches:{d['id']}", "recipe": "ninja.os_patches", "target": d.get("name") or str(d["id"]),
                    "title": f"Install {d.get('count', '')} pending OS patch(es) on {d.get('name') or d['id']} through NinjaOne".replace("  ", " "),
                    "why": (f"{fid}: " if fid else "") + f"NinjaOne lists {d.get('count')} pending patch(es)" + (f", {d['critical']} critical" if d.get("critical") else ""),
                    "finding": fid, "params": {"device": int(d["id"])}, "ready": bool(ninja.get("client_id")),
                    "blocked": None if ninja.get("client_id") else "Needs NinjaOne patch credentials (add them below)."})
    return out
