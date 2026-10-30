"""Remediation: the only changes Guardian can make, each from a fixed, tested recipe.

Nothing here is reachable by the AI agents. The console runs a recipe only when an admin has turned remediation on
(passkey, time-limited) and approved that one change (passkey again). Every recipe records a backup before it changes
anything, verifies the result, and rolls back automatically if the check fails.
"""
import re
import shlex
import subprocess
import threading
import time
from pathlib import Path

from . import connectors as conn
from . import fixes
from .fixes import Failed

SSHD_DROPIN = "/etc/ssh/sshd_config.d/00-guardian.conf"
SSHD_SETTING = "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
SUDOERS = ('Defaults:guardian-fix env_keep += "DEBIAN_FRONTEND"\n'
           "guardian-fix ALL=(root) NOPASSWD: /usr/bin/tee " + SSHD_DROPIN + ", /usr/bin/cat " + SSHD_DROPIN +
           ", /usr/bin/rm -f " + SSHD_DROPIN + ", /usr/sbin/sshd -t, /usr/bin/systemctl reload ssh, /usr/bin/systemctl reload sshd"
           + fixes.SUDOERS_EXTRA)

RECIPES = {
    "upnp.delete": {
        "title": "Close a port forward opened through UPnP",
        "applies": "Router port forwards that devices opened themselves (UPnP)",
        "risk": "low", "status": "active",
        "backup": "The forward's details are recorded", "rollback": "Automatic: re-created through UPnP",
        "needs": "Nothing: uses UPnP on the local network",
        "breaks": "The device that opened it (often a game console, BitTorrent or a camera app) can no longer be reached "
                  "from the internet on that port. It may open it again unless UPnP is turned off on the router.",
    },
    "linux.ssh_password_off": {
        "title": "Turn off SSH password login",
        "applies": "Linux servers (Debian, Ubuntu)",
        "risk": "medium", "status": "active",
        "backup": "Guardian's settings file is saved (or noted as new)",
        "rollback": "Automatic if the server stops accepting key login; one click otherwise",
        "needs": "A fix account on the server, allowed to run 6 commands with sudo",
        "breaks": "Anyone who logs in with a password instead of an SSH key is locked out. Guardian checks that key "
                  "login works first, and keeps its own key access.",
    },
    "snmp.v1_off": {"title": "Turn off SNMPv1/v2c", "applies": "Printers, switches", "risk": "low", "status": "planned",
                    "backup": "Settings export", "rollback": "Manual", "needs": "Device admin account", "breaks": ""},
    "https.force": {"title": "Force HTTPS on admin pages", "applies": "Synology DSM, Proxmox", "risk": "low", "status": "planned",
                    "backup": "Setting snapshot", "rollback": "Automatic", "needs": "NAS / hypervisor fix account", "breaks": ""},
    "firmware.update": {"title": "Update firmware", "applies": "Any device", "risk": "high", "status": "manual",
                        "backup": "Instructions only", "rollback": "Manual", "needs": "You", "breaks": ""},
}
RECIPES.update(fixes.RECIPES)

NEVER = ["Firmware flashes: a failed flash can brick the device.",
         "Router WAN and firewall rules: one mistake cuts the whole site off.",
         "The SSH or admin path Guardian itself connects through: it could lock itself (and you) out.",
         "Anything on a device without a backup method."]

MAPPING = re.compile(r"^\s*\d+\s+(TCP|UDP)\s+(\d+)->([\d.]+):(\d+)\s+'([^']*)'", re.I)


def parse_mapping(line):
    m = MAPPING.match(line or "")
    if not m:
        return None
    proto, ext, ip, port, desc = m.groups()
    return {"proto": proto.upper(), "external": int(ext), "ip": ip, "internal": int(port), "description": desc[:60]}


def proposals(graph, fix, collector_ip=None):
    """Fixes Guardian can offer for this run, each tied to what it found. `fix` is the vault's fix-accounts record."""
    fix_hosts = (fix or {}).get("hosts") or {}
    findings = [f for f in graph.get("findings") or [] if f.get("status") != "resolved"]
    upnp_finding = next((f["id"] for f in findings if "upnp" in (f.get("title", "") + f.get("evidence", "")).lower()), None)
    out = []
    for line in (graph.get("wan") or {}).get("upnp_port_mappings") or []:
        m = parse_mapping(line)
        if not m:
            continue
        out.append({"id": f"upnp:{m['proto']}:{m['external']}", "recipe": "upnp.delete", "target": "router",
                    "title": f"Close {m['proto']} {m['external']} → {m['ip']}:{m['internal']}" + (f" ({m['description']})" if m["description"] else ""),
                    "why": "Opened through UPnP: reachable from the internet." + (f" Finding {upnp_finding}." if upnp_finding else ""),
                    "finding": upnp_finding, "params": m, "ready": True, "blocked": None})
    for f in findings:
        text = (f.get("title", "") + " " + f.get("evidence", "")).lower()
        ip = f.get("asset", "")
        if "ssh" in text and "password" in text and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            blocked = None
            if ip == collector_ip:
                blocked = "This is Guardian's own host: change it by hand."
            elif ip not in fix_hosts:
                blocked = "Needs a fix account on this server (add it below)."
            out.append({"id": f"sshpw:{ip}", "recipe": "linux.ssh_password_off", "target": ip,
                        "title": f"Turn off SSH password login on {ip}", "why": f'{f["id"]}: {f.get("title", "")}',
                        "finding": f["id"], "params": {"host": ip}, "ready": blocked is None, "blocked": blocked})
    return out + fixes.proposals(graph, fix, collector_ip)


class Context:
    """What a recipe may use. `run` is replaceable so the recipes can be tested without touching a device."""

    def __init__(self, vault, state_dir, fix_hosts, record, run=None, fix=None, winrm_factory=None, wait=None):
        self.vault, self.state_dir, self.fix_hosts, self.record = vault, Path(state_dir), fix_hosts, record
        self.fix = fix or {"hosts": fix_hosts}
        self.winrm_factory, self.m365_token = winrm_factory, None
        self.wait = wait or (lambda seconds: seconds)          # tests shorten the waits
        self.run = run or (lambda cmd, timeout=60, stdin=None: subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout))

    def step(self, name, ok, text):
        self.record["steps"].append({"t": time.time(), "step": name, "ok": ok, "text": str(text)[:500]})

    def ssh(self, host, command, stdin=None, timeout=60):
        acct = self.fix_hosts[host]
        (self.state_dir / "ssh").mkdir(mode=0o700, exist_ok=True)
        with conn.ssh_key_file(self.vault) as key:
            cmd = ["ssh", "-i", key, "-p", str(int(acct.get("port") or 22)), "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                   "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={self.state_dir / 'ssh' / 'known_hosts'}",
                   f'{acct.get("user") or "guardian-fix"}@{host}', command]
            return self.run(cmd, timeout=timeout, stdin=stdin)


def _check(r, what):
    if r.returncode != 0:
        raise Failed(f"{what}: {(r.stderr or r.stdout or 'failed').strip()[-300:]}")
    return r.stdout


# -- recipes: backup -> apply -> verify; rollback(ctx, backup) undoes ------------------------------------------
def upnp_backup(ctx, p):
    listing = _check(ctx.run(["upnpc", "-l"], timeout=60), "Read UPnP forwards")
    if not any((m := parse_mapping(l)) and m["proto"] == p["proto"] and m["external"] == p["external"] for l in listing.splitlines()):
        raise Failed("That forward no longer exists on the router: nothing to do.")
    return dict(p)


def upnp_apply(ctx, p):
    _check(ctx.run(["upnpc", "-d", str(p["external"]), p["proto"]], timeout=60), "Delete forward")


def upnp_verify(ctx, p):
    listing = _check(ctx.run(["upnpc", "-l"], timeout=60), "Re-read UPnP forwards")
    still = [l for l in listing.splitlines() if (m := parse_mapping(l)) and m["proto"] == p["proto"] and m["external"] == p["external"]]
    if still:
        raise Failed("The router still lists the forward.")
    return "Forward gone from the router's list"


def upnp_rollback(ctx, b):
    _check(ctx.run(["upnpc", "-e", b.get("description") or "restored by Guardian", "-a", b["ip"], str(b["internal"]),
                    str(b["external"]), b["proto"]], timeout=60), "Re-create forward")


def sshpw_backup(ctx, p):
    h = p["host"]
    _check(ctx.ssh(h, "true"), "Key login with the fix account")
    _check(ctx.ssh(h, "grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/' /etc/ssh/sshd_config"),
           "This sshd doesn't read /etc/ssh/sshd_config.d (older system): change it by hand")
    _check(ctx.ssh(h, "sudo -n /usr/sbin/sshd -t"), "Current sshd settings are invalid; not touching them")
    old = ctx.ssh(h, f"sudo -n /usr/bin/cat {SSHD_DROPIN}")
    return {"host": h, "existed": old.returncode == 0, "content": old.stdout if old.returncode == 0 else ""}


def _reload(ctx, h):
    r = ctx.ssh(h, "sudo -n /usr/bin/systemctl reload ssh")
    if r.returncode != 0:
        _check(ctx.ssh(h, "sudo -n /usr/bin/systemctl reload sshd"), "Reload sshd")


def sshpw_apply(ctx, p):
    h = p["host"]
    _check(ctx.ssh(h, f"sudo -n /usr/bin/tee {SSHD_DROPIN} >/dev/null", stdin=SSHD_SETTING), "Write setting")
    _check(ctx.ssh(h, "sudo -n /usr/sbin/sshd -t"), "New settings rejected by sshd")
    _reload(ctx, h)


def sshpw_verify(ctx, p):
    h = p["host"]
    _check(ctx.ssh(h, "true"), "Key login after the change")
    out = _check(ctx.run(["nmap", "-Pn", "-n", "-p", str(int(ctx.fix_hosts[h].get("port") or 22)), "--script", "ssh-auth-methods", h],
                         timeout=120), "Check login methods from outside")
    if re.search(r"\bpassword\b", out.split("ssh-auth-methods", 1)[-1], re.I):
        raise Failed("The server still offers password login.")
    return "Key login works; password login no longer offered"


def sshpw_rollback(ctx, b):
    h = b["host"]
    if b["existed"]:
        _check(ctx.ssh(h, f"sudo -n /usr/bin/tee {SSHD_DROPIN} >/dev/null", stdin=b["content"]), "Restore setting")
    else:
        _check(ctx.ssh(h, f"sudo -n /usr/bin/rm -f {SSHD_DROPIN}"), "Remove setting")
    _reload(ctx, h)


STEPS = {"upnp.delete": (upnp_backup, upnp_apply, upnp_verify, upnp_rollback),
         "linux.ssh_password_off": (sshpw_backup, sshpw_apply, sshpw_verify, sshpw_rollback), **fixes.STEPS}
ERRORS = (Failed, conn.Result, subprocess.TimeoutExpired, OSError)


def _why(e):
    return e if isinstance(e, ERRORS) else f"{type(e).__name__}: {e}"
_one_at_a_time = threading.Lock()


def execute(ctx, proposal):
    """Backup, apply, verify; roll back on any failure after the change. Fills ctx.record; returns it."""
    rec = ctx.record
    backup_f, apply_f, verify_f, rollback_f = STEPS[proposal["recipe"]]
    with _one_at_a_time:
        rec["status"] = "running"
        try:
            rec["backup"] = backup_f(ctx, proposal["params"])
            ctx.step("backup", True, "Backup saved")
        except Exception as e:                             # noqa: BLE001 - always end in a known state
            ctx.step("backup", False, _why(e))
            rec["status"] = "not-applied"
            return rec
        try:
            apply_f(ctx, proposal["params"])
            ctx.step("apply", True, "Change applied")
            ctx.step("verify", True, verify_f(ctx, proposal["params"]))
            rec["status"] = "done"
        except Exception as e:                             # noqa: BLE001 - always end in a known state
            ctx.step("verify" if any(s["step"] == "apply" for s in rec["steps"]) else "apply", False, _why(e))
            try:
                rollback_f(ctx, rec["backup"])
                ctx.step("rollback", True, "Rolled back to the backup")
                rec["status"] = "rolled-back"
            except Exception as e2:                            # noqa: BLE001 - always end in a known state
                ctx.step("rollback", False, _why(e2))
                rec["status"] = "needs-attention"
        return rec


def rollback(ctx, record):
    with _one_at_a_time:
        try:
            STEPS[record["recipe"]][3](ctx, record["backup"])
            ctx.step("rollback", True, "Rolled back on request")
            record["status"] = "rolled-back"
        except Exception as e:                             # noqa: BLE001
            ctx.step("rollback", False, _why(e))
            record["status"] = "needs-attention"
    return record
