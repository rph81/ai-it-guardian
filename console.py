#!/usr/bin/env python3
"""AI IT Guardian - web console.

Starts and stops runs of run.py, follows their log live, shows the reports, and manages connectors,
users and the encrypted vault. Serves HTTPS on port 8443 (GUARDIAN_CONSOLE_PORT) at the hostname set
in GUARDIAN_HOSTNAME (passkeys need a real hostname with a trusted certificate).

People sign in with Google or Microsoft (or a passkey alone) and confirm with a passkey. Admins and
operators unlock the vault with their passkey; viewers only read reports. On first start, the setup
code in console/setup-code creates the first admin:  cat /opt/ai-guardian/console/setup-code
"""
import asyncio
import base64
import collections
import csv
import ctypes
import hmac
import io
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from guardian import auth
from guardian import chat
from guardian import remediate
from guardian import notify
from guardian import ticketing
from guardian import sitestore
from guardian import connectors as conn
from guardian.agents import ANALYSTS, LAYERS
from guardian.controls import FRAMEWORKS, STATUSES as CONTROL_STATUSES
from guardian.graph import is_open
from guardian.tools import PRIORITY_DAYS
from guardian.vault import ROLES, VAULT_ROLES, Vault, VaultLocked

BASE = Path(__file__).resolve().parent
RUNS = BASE / "runs"
ENV = BASE / ".env"
WEB = BASE / "guardian" / "web"
STATE = BASE / "console"
SETUP_FILE = STATE / "setup-code"
CERT, KEY = STATE / "cert.pem", STATE / "key.pem"
PYTHON = str(BASE / "venv" / "bin" / "python") if (BASE / "venv" / "bin" / "python").exists() else sys.executable

RUN_ID = re.compile(r"^\d{8}-\d{6}$")
API_KEY = re.compile(r"^[A-Za-z0-9_\-]{20,200}$")
EMAIL = re.compile(r"^[^@\s<>]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,}$")
MODELS = {"claude-opus-5-5": "Opus 5.5 (default)", "claude-fable-5-1": "Fable 5.1 (stronger, ~2.5x cost)"}
EFFORTS = ("low", "medium", "high")
SESSION_HOURS, IDENTIFIED_MINUTES = 8, 10
MAX_FAILS, FAIL_WINDOW = 5, 900

MODES = {
    "collect": {"label": "Scan only", "args": ["--collect-only"], "steps": ["Scanning the network"]},
    "full": {"label": "Scan + AI assessment", "args": [],
             "steps": ["Scanning the network", "Identifying devices", "AI specialists", "Analysts", "Writing the report"]},
    "resume": {"label": "Re-run AI on a scan", "args": ["--resume"],
               "steps": ["Identifying devices", "AI specialists", "Analysts", "Writing the report"]},
    "report": {"label": "Rebuild report", "args": ["--report"], "steps": ["Rebuilding the report"]},
    "followup": {"label": "Follow-up from the chat", "args": ["--followup"], "steps": ["AI specialists", "Analysts", "Writing the report"]},
}
ROUNDS, PARALLELS = (20, 40, 60), tuple(range(1, 13))
SCALE_MODES = ("auto", "manual")


def parse_scale(text):
    out = {}
    for item in (text or "").split(","):
        p = item.split(":")
        if len(p) == 4 and p[0] in LAYERS and all(x.isdigit() for x in p[1:]):
            out[p[0]] = {"min": int(p[1]), "max": int(p[2]), "manual": int(p[3])}
    return out
STEP_OF_AGENT = {"collector": "Scanning the network", "discovery": "Identifying devices", "report": "Writing the report",
                 **{a: "Analysts" for a in ANALYSTS}}


def harden_process():
    """No core dumps and no ptrace from other non-root processes: vault keys stay out of dumps."""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)        # PR_SET_DUMPABLE = 4
    except (OSError, ValueError, AttributeError):
        pass


# -- state on disk ----------------------------------------------------------------------------
def ensure_state():
    STATE.mkdir(mode=0o700, exist_ok=True)
    if not (CERT.exists() and KEY.exists()):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-days", "825", "-subj", "/CN=ai-guardian console",
                        "-keyout", str(KEY), "-out", str(CERT)], check=True, capture_output=True)
        KEY.chmod(0o600)


STATE.mkdir(mode=0o700, exist_ok=True)
vault = Vault(STATE / "guardian.db")
store = conn.Store(vault, STATE)


def setup_done():
    return bool(vault.credentials())


def setup_code():
    """One-time code that creates the first admin. Exists until someone has registered a passkey."""
    if setup_done():
        if SETUP_FILE.exists():
            SETUP_FILE.unlink()
        return None
    if not SETUP_FILE.exists():
        SETUP_FILE.write_text(f"{secrets.token_hex(3)}-{secrets.token_hex(3)}-{secrets.token_hex(3)}\n")
        SETUP_FILE.chmod(0o600)
    return SETUP_FILE.read_text().strip()


def site():
    host = os.environ.get("GUARDIAN_HOSTNAME") or vault.get("hostname") or socket.getfqdn()
    port = int(os.environ.get("GUARDIAN_CONSOLE_PORT", "8443"))
    base = os.environ.get("GUARDIAN_PUBLIC_URL") or f"https://{host}" + ("" if port == 443 else f":{port}")
    return host, base, [base, f"https://{host}"]


def providers():
    """Configured sign-in providers. Client secrets are needed before anyone signs in, so they can't live in the vault."""
    cfg = vault.get("oidc", {})
    return {k: v for k, v in cfg.items() if k in auth.PROVIDERS and v.get("client_id") and v.get("client_secret")}


# -- .env (non-secret settings only) ------------------------------------------------------------
def read_env():
    out = {}
    if ENV.exists():
        for line in ENV.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def write_env(updates):
    lines = ENV.read_text().splitlines() if ENV.exists() else []
    done = set()
    for i, line in enumerate(lines):
        k = line.split("=", 1)[0].strip()
        if k in updates and not line.lstrip().startswith("#"):
            lines[i] = f"{k}={updates[k]}"
            done.add(k)
    lines += [f"{k}={v}" for k, v in updates.items() if k not in done]
    tmp = ENV.with_suffix(".tmp")
    tmp.write_text("\n".join(lines) + "\n")
    tmp.chmod(0o600)
    os.replace(tmp, ENV)


def api_keys():
    """API keys are vault records; an empty dict while the vault is locked."""
    if not vault.unlocked:
        return {}
    return next((r for r in vault.load_records("settings") if r.get("kind") == "api-keys"), {})


def public_config():
    env, keys = read_env(), vault.get("api_keys_set", {})
    return {"model": env.get("GUARDIAN_MODEL") or "claude-opus-5-5", "effort": env.get("GUARDIAN_EFFORT") or "medium",
            "max_rounds": int(env.get("GUARDIAN_MAX_TURNS") or 40), "parallel": int(env.get("GUARDIAN_PARALLEL") or 3),
            "agents_off": [x for x in (env.get("GUARDIAN_AGENTS_OFF") or "").split(",") if x in LAYERS],
            "scale_mode": env.get("GUARDIAN_SCALE_MODE") if env.get("GUARDIAN_SCALE_MODE") in SCALE_MODES else "auto",
            "per_copy": int(env.get("GUARDIAN_PER_COPY") or 25),
            "scale": {k: parse_scale(env.get("GUARDIAN_SCALE")).get(k, {"min": 1, "max": 1 if k == "wan" else 8, "manual": 1})
                      for k in LAYERS if k not in ANALYSTS},
            "agents": {k: v["title"] for k, v in LAYERS.items()}, "analysts": ANALYSTS,
            "anthropic_key_set": bool(keys.get("anthropic")), "nvd_key_set": bool(keys.get("nvd")),
            "models": MODELS, "efforts": EFFORTS, "rounds": ROUNDS, "parallels": PARALLELS}


def migrate_legacy():
    """Move secrets that older versions kept on disk into the vault (needs the vault unlocked)."""
    moved = []
    env = read_env()
    if env.get("ANTHROPIC_API_KEY") or env.get("NVD_API_KEY"):
        rec = api_keys() or {"kind": "api-keys"}
        rec.update({k: v for k, v in (("anthropic", env.get("ANTHROPIC_API_KEY")), ("nvd", env.get("NVD_API_KEY"))) if v})
        vault.save_record("api-keys", "settings", rec)
        vault.put("api_keys_set", {"anthropic": bool(rec.get("anthropic")), "nvd": bool(rec.get("nvd"))})
        write_env({"ANTHROPIC_API_KEY": "", "NVD_API_KEY": ""})
        moved.append("API keys")
    old_json, old_key = STATE / "connectors.json", STATE / "secret.key"
    if old_json.exists():
        data = json.loads(old_json.read_text())
        f = None
        if old_key.exists():
            from cryptography.fernet import Fernet
            f = Fernet(old_key.read_bytes())
        for c in data.get("connectors", []):
            c["secrets"] = {k: f.decrypt(v.encode()).decode() for k, v in c.get("secrets", {}).items()} if f else {}
            store.save_connector(c)
        vault.put("dismissed", data.get("dismissed", []))
        vault.put("inventory", data.get("inventory", {}))
        vault.put("inventory_runs", data.get("inventory_runs", []))
        moved.append(f"{len(data.get('connectors', []))} connectors")
        for p in (old_json, old_key):
            if p.exists():
                p.write_bytes(os.urandom(p.stat().st_size))
                p.unlink()
    old_ssh = STATE / "ssh" / "id_ed25519"
    if old_ssh.exists():
        vault.save_record("ssh-key", "secret", {"private": old_ssh.read_text()})
        vault.put("ssh_public_key", (STATE / "ssh" / "id_ed25519.pub").read_text().strip())
        old_ssh.write_bytes(os.urandom(old_ssh.stat().st_size))
        old_ssh.unlink()
        (STATE / "ssh" / "id_ed25519.pub").unlink(missing_ok=True)
        moved.append("SSH key")
    for p in (STATE / "access-code",):
        p.unlink(missing_ok=True)
    if moved:
        vault.audit("system", "migrated", "Moved into the vault: " + ", ".join(moved))


# -- sessions -----------------------------------------------------------------------------------
sessions = {}                                   # sid -> {"uid", "stage": identified|active, ...}
oidc_pending = {}                               # state -> pending sign-in
fails = collections.defaultdict(list)


def new_session(uid, stage, **extra):
    sid = secrets.token_urlsafe(32)
    sessions[sid] = {"uid": uid, "stage": stage, "created": time.time(), "last": time.time(), **extra}
    return sid


def end_session(sid):
    s = sessions.pop(sid, None)
    if s:
        vault.release(sid)
        _forget_private(s)


def _forget_private(s):
    priv = s.pop("priv", None)
    if priv:
        for i in range(len(priv[0])):
            priv[0][i] = 0


def current(request, stage="active"):
    sid = request.cookies.get("gsid")
    s = sessions.get(sid) if sid else None
    if not s:
        return None, None
    limit = SESSION_HOURS * 3600 if s["stage"] == "active" else IDENTIFIED_MINUTES * 60
    if time.time() - s["created"] > limit:
        end_session(sid)
        return None, None
    if stage == "active" and s["stage"] != "active":
        return None, None
    s["last"] = time.time()
    vault.touch(sid)
    return sid, s


def require(request, role="viewer", unlocked=False):
    sid, s = current(request)
    if not s:
        raise HTTPException(401, "Sign in first")
    user = vault.user(s["uid"])
    if not user or user["status"] != "active":
        end_session(sid)
        raise HTTPException(401, "Sign in first")
    if ROLES.index(user["role"]) < ROLES.index(role):
        raise HTTPException(403, "Your role doesn't allow this")
    if unlocked and not (vault.unlocked and sid in vault.holders):
        raise HTTPException(423, "Unlock the vault with your passkey first")
    return sid, s, user


def set_cookie(resp, sid):
    resp.set_cookie("gsid", sid, max_age=SESSION_HOURS * 3600, httponly=True, secure=True, samesite="strict")
    return resp


def throttle(request):
    ip = request.client.host if request.client else "?"
    now = time.time()
    fails[ip] = [t for t in fails[ip] if now - t < FAIL_WINDOW]
    if len(fails[ip]) >= MAX_FAILS:
        raise HTTPException(429, "Too many attempts. Try again in 15 minutes.")
    return ip


def failed(ip):
    fails[ip].append(time.time())


async def autolock_loop():
    while True:
        await asyncio.sleep(30)
        cfg = vault.get("autolock", {"idle": 30, "max": 8})
        for sid in [k for k in vault.holders if k not in sessions]:
            vault.release(sid)
        if vault.expire(cfg["idle"] * 60, cfg["max"] * 3600):
            vault.audit("system", "vault-locked", "Locked automatically (idle or time limit)")


# -- the one job that can run at a time --------------------------------------------------------
class Job:
    def __init__(self):
        self.proc = None
        self.mode = None
        self.run_id = None
        self.started = None
        self.ended = None
        self.exit_code = None
        self.stopped = False
        self.step = None
        self.by = None
        self.note = None                       # e.g. why a scheduled AI run fell back to a scan
        self.lines = collections.deque(maxlen=3000)
        self.seq = 0                           # number of lines ever written, for incremental reads

    @property
    def running(self):
        return self.proc is not None and self.proc.returncode is None

    def add(self, text):
        self.seq += 1
        self.lines.append((self.seq, time.strftime("%H:%M:%S"), text))
        m = re.match(r"^\[(\w+)\]", text)
        if m and m.group(1) != "console" and self.mode in ("full", "resume", "followup"):
            self.step = STEP_OF_AGENT.get(m.group(1), "AI specialists")
        if self.mode in ("full", "collect") and not self.run_id:
            m = re.search(r"runs/(\d{8}-\d{6})", text)
            if m:
                self.run_id = m.group(1)

    def status(self, since=0):
        steps = MODES[self.mode]["steps"] if self.mode else []
        return {"running": self.running, "mode": self.mode, "label": MODES[self.mode]["label"] if self.mode else None,
                "run_id": self.run_id, "started": self.started, "ended": self.ended, "exit_code": self.exit_code,
                "stopped": self.stopped, "by": self.by, "steps": steps,
                "step": steps.index(self.step) + 1 if self.step in steps else (1 if steps else 0),
                "seq": self.seq, "lines": [{"n": n, "t": t, "text": s} for n, t, s in self.lines if n > since]}


job = Job()


async def run_job(cmd, extra_env, stdin=None):
    try:
        job.proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=str(BASE), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            stdin=asyncio.subprocess.PIPE if stdin else asyncio.subprocess.DEVNULL,
            env={**os.environ, "PYTHONUNBUFFERED": "1", **extra_env, **({"GUARDIAN_ACCESS": "stdin"} if stdin else {})},
            start_new_session=True)
        extra_env.clear()
        if stdin:
            job.proc.stdin.write(stdin)
            await job.proc.stdin.drain()
            job.proc.stdin.close()
            stdin = None
        async for raw in job.proc.stdout:
            job.add(raw.decode("utf-8", "replace").rstrip("\n"))
        job.exit_code = await job.proc.wait()
    except Exception as e:                                      # noqa: BLE001 - shown to the user
        job.add(f"[console] could not run: {e}")
        job.exit_code = -1
    job.ended = time.time()
    job.add("[console] stopped by user" if job.stopped else f"[console] finished, exit code {job.exit_code}")
    if not job.stopped and job.exit_code == 0 and job.run_id and job.mode in ("collect", "full", "resume", "followup"):
        try:
            await asyncio.to_thread(after_run, job.run_id, job.mode, job.note)
        except Exception as e:                                      # noqa: BLE001 - never breaks the job record
            job.add(f"[console] after-run steps failed: {e}")


# -- run listing --------------------------------------------------------------------------------
def run_summary(d):
    info = {"id": d.name, "has_graph": (d / "graph.json").exists(), "has_report": (d / "report.html").exists(),
            "devices": None, "score": None, "grade": None, "counts": {}, "analysed": False}
    if info["has_graph"]:
        try:
            g = json.loads((d / "graph.json").read_text())
            info["devices"] = len(g.get("assets") or {})
            s = g.get("summary") or {}
            info["score"], info["grade"] = s.get("score"), s.get("grade")
            info["cost"] = round(g["cost_total"], 2) if g.get("cost_total") else None
            info["has_agents"] = bool(g.get("agents"))
            info["analysed"] = bool(s)
            for f in g.get("findings") or []:
                if not is_open(f):
                    continue
                sev = f.get("severity", "info")
                info["counts"][sev] = info["counts"].get(sev, 0) + 1
        except (OSError, ValueError):
            pass
    return info


def run_dir(run_id):
    if not RUN_ID.match(run_id or ""):
        raise HTTPException(404, "Unknown run")
    d = RUNS / run_id
    if not d.is_dir():
        raise HTTPException(404, "Unknown run")
    return d


def latest_scan():
    if not RUNS.exists():
        return None, None
    done = sorted(d for d in RUNS.iterdir() if RUN_ID.match(d.name) and (d / "graph.json").exists())
    if not done:
        return None, None
    try:
        return done[-1].name, json.loads((done[-1] / "graph.json").read_text())
    except (OSError, ValueError):
        return None, None


# -- app ------------------------------------------------------------------------------------------
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

PAGE_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "frame-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
REPORT_CSP = ("sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; "
              "style-src 'unsafe-inline'; img-src data:; font-src data:")
STATIC = {"/console.css": ("console.css", "text/css"), "/theme.js": ("theme.js", "text/javascript"), "/console.js": ("console.js", "text/javascript"),
          "/settings.js": ("settings.js", "text/javascript"), "/signin.js": ("signin.js", "text/javascript"),
          "/passkey.js": ("passkey.js", "text/javascript"), "/agents.js": ("agents.js", "text/javascript"),
          "/remediate.js": ("remediate.js", "text/javascript"), "/code.js": ("code.js", "text/javascript"),
          "/plan.js": ("plan.js", "text/javascript"), "/schedule.js": ("schedule.js", "text/javascript"),
          "/ticketing.js": ("ticketing.js", "text/javascript"), "/sites.js": ("sites.js", "text/javascript")}
PAGES = {"/": "console.html", "/settings": "settings.html", "/signin": "signin.html"}


@app.on_event("startup")
async def _startup():
    harden_process()
    setup_code()
    asyncio.create_task(autolock_loop())
    asyncio.create_task(scheduler_loop())
    try:
        sites_db()                       # the gateway needs the job key before the first collector enrolls
    except Exception as e:                                         # noqa: BLE001 - the console must start anyway
        print(f"Sites database unavailable: {e}", file=sys.stderr, flush=True)


@app.middleware("http")
async def guard(request: Request, call_next):
    if request.method not in ("GET", "HEAD"):
        # Cross-site requests can't set this header without a CORS preflight, which is never allowed.
        if request.headers.get("x-guardian") != "1":
            return JSONResponse({"detail": "Bad request"}, status_code=403)
        origin = request.headers.get("origin")
        if origin and origin.split("://", 1)[-1] != request.headers.get("host"):
            return JSONResponse({"detail": "Bad origin"}, status_code=403)
    resp = await call_next(request)
    resp.headers.setdefault("Content-Security-Policy", PAGE_CSP)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if resp.headers.get("X-Frame-Options") == "":
        del resp.headers["X-Frame-Options"]
    else:
        resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Cache-Control", "no-store")
    return resp


def _page(name):
    return FileResponse(WEB / name, media_type="text/html")


@app.get("/")
def page_console(request: Request):
    if not current(request)[1]:
        return Response(status_code=303, headers={"Location": "/signin"})
    return _page("console.html")


@app.get("/fix")
def page_fix(request: Request):
    if not current(request)[1]:
        return Response(status_code=303, headers={"Location": "/signin"})
    return _page("remediate.html")


@app.get("/code")
def page_code(request: Request):
    if not current(request)[1]:
        return Response(status_code=303, headers={"Location": "/signin"})
    return _page("code.html")


@app.get("/settings")
def page_settings(request: Request):
    if not current(request)[1]:
        return Response(status_code=303, headers={"Location": "/signin"})
    return _page("settings.html")


@app.get("/signin")
def page_signin():
    return _page("signin.html")


def _static(file, media_type):
    def serve():
        return FileResponse(WEB / file, media_type=media_type)
    return serve


for _path, (_file, _type) in STATIC.items():
    app.add_api_route(_path, _static(_file, _type), methods=["GET"])

FONT = re.compile(r"^[a-z0-9-]{1,40}\.woff2$")


@app.get("/fonts/{name}")
def font(name: str):
    path = WEB / "fonts" / name
    if not FONT.match(name) or not path.is_file():
        raise HTTPException(404, "Not found")
    return FileResponse(path, media_type="font/woff2", headers={"Cache-Control": "public, max-age=604800"})


# -- sign-in: state ----------------------------------------------------------------------------
@app.get("/api/auth/state")
def auth_state(request: Request):
    sid, s = current(request, stage="any")
    user = vault.user(s["uid"]) if s else None
    host, base, _ = site()
    return {
        "setup": not setup_done(),
        "providers": {k: auth.PROVIDERS[k]["label"] for k in providers()},
        "stage": s["stage"] if s else None,
        "user": {"name": user["name"], "email": user["email"], "role": user["role"]} if user else None,
        "passkeys": len(vault.credentials(user["id"])) if user else 0,
        "can_unlock": bool(user and user["role"] in VAULT_ROLES and vault.has_slot(user["id"])),
        "vault_ready": vault.initialized,
        "unlocked": bool(sid and sid in vault.holders),
        "invite": bool(request.cookies.get("ginv")),
        "hostname": host,
        "wrong_host": request.headers.get("host", "").split(":")[0] != host,
        "base": base,
    }


class SetupBody(BaseModel):
    code: str
    name: str
    email: str


@app.post("/api/setup/start")
def setup_start(body: SetupBody, request: Request):
    ip = throttle(request)
    code = setup_code()
    if not code:
        raise HTTPException(409, "Guardian is already set up")
    if not hmac.compare_digest(body.code.strip().lower().encode(), code.encode()):
        failed(ip)
        time.sleep(1)
        raise HTTPException(401, "Wrong setup code")
    if not EMAIL.match(body.email.strip()) or not body.name.strip() or len(body.name) > 80:
        raise HTTPException(400, "Enter your name and e-mail address")
    for u in vault.users():                                 # an abandoned earlier attempt
        vault.delete_user(u["id"])
    uid = vault.create_user(body.email.strip(), body.name.strip(), "admin")
    vault.audit(body.email.strip().lower(), "setup", "Created the first admin with the setup code")
    return set_cookie(JSONResponse({"ok": True}), new_session(uid, "identified", setup=True))


# -- sign-in: Google / Microsoft ---------------------------------------------------------------
@app.get("/auth/{provider}/start")
def oidc_start(provider: str, request: Request, link: int = 0):
    cfg = providers().get(provider)
    if not cfg:
        raise HTTPException(404, "This sign-in method isn't set up")
    _, base, _ = site()
    url, pending = auth.authorize_url(provider, cfg["client_id"], f"{base}/auth/callback/{provider}")
    if link:
        sid, s = current(request)
        if not s:
            raise HTTPException(401, "Sign in first")
        pending["link_uid"] = s["uid"]
    pending["invite"] = request.cookies.get("ginv")
    for k in [k for k, v in oidc_pending.items() if time.time() - v["created"] > 600]:
        oidc_pending.pop(k, None)
    oidc_pending[pending["state"]] = pending
    resp = Response(status_code=303, headers={"Location": url})
    resp.set_cookie("gstate", pending["state"], max_age=600, httponly=True, secure=True, samesite="lax")
    return resp


def _bounce(path):
    """Leave the provider's redirect through a same-site page, so the Strict session cookie is sent afterwards."""
    return HTMLResponse(f'<!doctype html><meta http-equiv="refresh" content="0;url={path}">'
                        f'<p>Continuing… <a href="{path}">continue</a></p>',
                        headers={"Content-Security-Policy": "default-src 'none'"})


@app.get("/auth/callback/{provider}")
def oidc_callback(provider: str, request: Request, state: str = "", code: str = "", error: str = ""):
    pending = oidc_pending.pop(state, None)
    if error or not pending or pending["provider"] != provider or request.cookies.get("gstate") != state:
        return _bounce("/signin?error=" + ("cancelled" if error else "expired"))
    cfg = providers().get(provider)
    _, base, _ = site()
    try:
        ident = auth.exchange_code(provider, cfg["client_id"], cfg["client_secret"], f"{base}/auth/callback/{provider}", code, pending)
    except Exception as e:                                      # noqa: BLE001 - reported to the user, never details
        vault.audit("unknown", "signin-failed", f"{provider}: {str(e)[:120]}")
        return _bounce("/signin?error=provider")
    users = [u for u in vault.users() if u["provider"] == provider and u["subject"] == ident["subject"]]
    user = vault.user(users[0]["id"]) if users else None
    if pending.get("link_uid"):
        target = vault.user(pending["link_uid"])
        if user and user["id"] != target["id"]:
            return _bounce("/settings?error=linked-elsewhere#users")
        vault.update_user(target["id"], provider=provider, subject=ident["subject"])
        vault.audit(target["email"], "account-linked", f"Linked {auth.PROVIDERS[provider]['label']} account {ident['email']}")
        return _bounce("/settings#users")
    if not user and pending.get("invite"):
        inv = vault.invite(pending["invite"])
        if inv and inv["email"] == ident["email"]:
            existing = vault.user(email=ident["email"])
            if existing and existing["subject"]:
                return _bounce("/signin?error=exists")
            uid = existing["id"] if existing else vault.create_user(ident["email"], ident["name"], inv["role"], provider, ident["subject"])
            vault.update_user(uid, provider=provider, subject=ident["subject"], role=inv["role"], name=ident["name"])
            vault.use_invite(pending["invite"])
            vault.audit(ident["email"], "invite-accepted", f"Joined as {inv['role']} with {auth.PROVIDERS[provider]['label']}")
            user = vault.user(uid)
        elif inv:
            vault.audit(ident["email"], "signin-refused", "Invite is for a different e-mail address")
            return _bounce("/signin?error=wrong-account")
    if not user or user["status"] != "active":
        vault.audit(ident["email"], "signin-refused", f"Not invited ({auth.PROVIDERS[provider]['label']})")
        return _bounce("/signin?error=not-invited")
    resp = _bounce("/signin?step=passkey")
    resp.delete_cookie("ginv")
    resp.delete_cookie("gstate")
    return set_cookie(resp, new_session(user["id"], "identified", provider=provider))


@app.get("/invite/{token}")
def invite_link(token: str):
    if not vault.invite(token):
        return _bounce("/signin?error=invite")
    resp = _bounce("/signin?invite=1")
    resp.set_cookie("ginv", token, max_age=1800, httponly=True, secure=True, samesite="lax")
    return resp


@app.post("/api/auth/invite-passkey")
def invite_passkey_only(request: Request):
    """Accept an invite without Google/Microsoft (only when neither is configured)."""
    if providers():
        raise HTTPException(400, "Sign in with Google or Microsoft to accept the invite")
    inv = vault.invite(request.cookies.get("ginv") or "")
    if not inv:
        raise HTTPException(400, "This invite is no longer valid")
    existing = vault.user(email=inv["email"])
    uid = existing["id"] if existing else vault.create_user(inv["email"], inv["email"].split("@")[0], inv["role"])
    vault.use_invite(request.cookies.get("ginv"))
    vault.audit(inv["email"], "invite-accepted", f"Joined as {inv['role']} with a passkey")
    resp = set_cookie(JSONResponse({"ok": True}), new_session(uid, "identified"))
    resp.delete_cookie("ginv")
    return resp


# -- passkeys -------------------------------------------------------------------------------------
class PasskeyVerify(BaseModel):
    credential: dict
    prf: Optional[str] = None
    unlock: bool = True
    name: Optional[str] = None


@app.post("/api/auth/register/options")
def register_options(request: Request):
    sid, s = current(request, stage="any")
    if not s:
        raise HTTPException(401, "Sign in first")
    if vault.credentials(s["uid"]):
        fresh = s["stage"] == "active" and ((s.get("priv") and s["priv"][1] > time.time())
                                             or (s.get("via") == "passkey" and time.time() - s["created"] < 300))
        if not fresh:
            raise HTTPException(409, "Confirm with one of your passkeys first, then add the new one")
    user = vault.user(s["uid"])
    host, _, _ = site()
    opts, challenge = auth.registration_options(host, user, vault.credentials(user["id"]))
    s["reg_challenge"] = challenge
    return opts


@app.post("/api/auth/register/verify")
def register_verify(body: PasskeyVerify, request: Request):
    sid, s = current(request, stage="any")
    if not s or not s.get("reg_challenge"):
        raise HTTPException(401, "Start again")
    host, _, origins = site()
    try:
        cid, pub, count = auth.verify_registration(body.credential, s.pop("reg_challenge"), host, origins)
    except Exception as e:                                      # noqa: BLE001
        raise HTTPException(400, f"The passkey couldn't be registered: {e}")
    name = (body.name or "Passkey").strip()[:40] or "Passkey"
    vault.add_credential(s["uid"], cid, name, pub, count)
    vault.audit(vault.user(s["uid"])["email"], "passkey-added", f'Registered passkey "{name}"')
    return {"ok": True, "id": cid}


@app.post("/api/auth/passkey/options")
def passkey_options(request: Request):
    sid, s = current(request, stage="any")
    host, _, _ = site()
    creds = vault.credentials(s["uid"]) if s and s["uid"] else []
    if s and s["uid"] and not creds:
        raise HTTPException(409, "No passkey yet")
    salt = vault.get("prf_salt")
    if not salt:
        salt = secrets.token_hex(32)
        vault.put("prf_salt", salt)
    opts, challenge = auth.authentication_options(host, creds if s and s["uid"] else [], bytes.fromhex(salt))
    if s:
        s["auth_challenge"] = challenge
        return opts
    else:
        sid = new_session(None, "anonymous")
        sessions[sid]["auth_challenge"] = challenge
        return set_cookie(JSONResponse(opts), sid)


@app.post("/api/auth/passkey/verify")
def passkey_verify(body: PasskeyVerify, request: Request):
    ip = throttle(request)
    sid, s = current(request, stage="any")
    if not s or not s.get("auth_challenge"):
        raise HTTPException(401, "Start again")
    cid = body.credential.get("id", "")
    stored = vault.credential(cid)
    if not stored or (s["uid"] and stored["user_id"] != s["uid"]):
        failed(ip)
        raise HTTPException(401, "This passkey isn't registered here")
    host, _, origins = site()
    try:
        count = auth.verify_authentication(body.credential, s.pop("auth_challenge"), host, origins, stored)
    except Exception:                                           # noqa: BLE001
        failed(ip)
        raise HTTPException(401, "The passkey check failed")
    vault.touch_credential(cid, count)
    user = vault.user(stored["user_id"])
    if user["status"] != "active":
        raise HTTPException(403, "This account is disabled")
    prf = auth.b64u_dec(body.prf) if body.prf else None
    note = None
    priv = None
    if prf and len(prf) >= 32:
        if stored["wrapped_private_key"]:
            try:
                priv = vault.private_key(cid, prf)
            except Exception:                                   # noqa: BLE001
                note = "This passkey couldn't open your key."
        elif s.get("priv"):
            vault.add_wrapped_credential(user["id"], cid, prf, s["priv"][0])
            priv = bytearray(s["priv"][0])
        else:
            try:
                priv = vault.bind_credential(user["id"], cid, prf)
            except ValueError as e:
                note = str(e)
    elif user["role"] in VAULT_ROLES:
        note = "This passkey can't unlock the vault (its device doesn't support the PRF feature). Signed in read-only."
    recovery = None
    # promote the session
    old = sessions.pop(sid)
    _forget_private(old)
    new = new_session(user["id"], "active", via="passkey")
    sessions[new]["setup"] = old.get("setup")
    was_holder = sid in vault.holders
    vault.update_user(user["id"], last_login=time.time())
    vault.audit(user["email"], "signed-in", f'Passkey "{stored["name"]}"' + (f" after {old.get('provider')}" if old.get("provider") else ""))
    sessions[new]["fresh_at"] = time.time()                    # remediation asks for a passkey this recent
    if priv is not None:
        sessions[new]["priv"] = (priv, time.time() + 300)          # lets this session add another passkey for 5 minutes
        if not vault.initialized and user["role"] == "admin":
            recovery = vault.initialize(user["id"], priv)
            vault.holders[new] = time.time()
            vault.unlocked_by, vault.unlocked_at = user["email"], time.time()
            vault.audit(user["email"], "vault-created", "Created the vault and the recovery key")
            migrate_legacy()
            setup_code()
        elif old.get("recovery") and was_holder:
            vault.grant(user["id"], user["email"])               # recovery: seal the vault key for the new passkey
            vault.holders[new] = time.time()
            recovery = vault.rotate_recovery()
            vault.audit(user["email"], "recovery-replaced", "New passkey set up after recovery; a new recovery key was created")
        elif body.unlock and user["role"] in VAULT_ROLES:
            if vault.unlock_with_private_key(user["id"], priv, new, user["email"]):
                vault.audit(user["email"], "vault-unlocked", f'Passkey "{stored["name"]}"')
                migrate_legacy()
            else:
                note = note or "An admin still has to give you access to the vault."
    if was_holder:
        vault.holders.pop(sid, None)
        if not vault.holders:
            vault.lock_now()
    if old.get("recovery") and new not in vault.holders:
        sessions[new]["recovery"] = True
    resp = JSONResponse({"ok": True, "recovery_key": recovery, "note": note,
                         "unlocked": new in vault.holders, "role": user["role"]})
    end = set_cookie(resp, new)
    return end


@app.post("/api/auth/recovery")
def recovery_signin(request: Request, body: dict):
    ip = throttle(request)
    email, key = str(body.get("email", "")).strip().lower(), str(body.get("key", ""))
    user = vault.user(email=email)
    if not user or user["role"] != "admin" or user["status"] != "active" or not vault.initialized:
        failed(ip)
        time.sleep(1)
        raise HTTPException(401, "Wrong e-mail address or recovery key")
    sid = new_session(user["id"], "active", via="recovery")
    try:
        vault.unlock_with_recovery(key, sid, user["email"])
    except Exception:                                           # noqa: BLE001
        sessions.pop(sid, None)
        failed(ip)
        time.sleep(1)
        vault.audit(email, "recovery-failed", "Wrong recovery key")
        raise HTTPException(401, "Wrong e-mail address or recovery key")
    # The person lost their passkeys: their old ones can no longer open anything new, so start them afresh.
    for c in vault.credentials(user["id"]):
        vault.delete_credential(c["id"])
    vault.update_user(user["id"], public_key=None)
    vault.revoke(user["id"])
    sessions[sid]["recovery"] = True
    vault.audit(user["email"], "recovery-used", "Signed in and unlocked with the recovery key; old passkeys removed")
    return set_cookie(JSONResponse({"ok": True}), sid)


@app.post("/api/auth/signout")
def signout(request: Request):
    sid = request.cookies.get("gsid")
    s = sessions.get(sid)
    if s and s.get("uid"):
        vault.audit(vault.user(s["uid"])["email"], "signed-out", "")
    end_session(sid)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("gsid")
    return resp


@app.post("/api/vault/lock")
def vault_lock(request: Request):
    sid, s, user = require(request)
    if sid in vault.holders:
        vault.lock_now()
        vault.audit(user["email"], "vault-locked", "Locked by hand")
    return {"ok": True}


@app.get("/api/me")
def me(request: Request):
    sid, s, user = require(request)
    return {"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"],
            "provider": user["provider"], "unlocked": sid in vault.holders, "can_unlock": vault.has_slot(user["id"]),
            "passkeys": [{"id": c["id"], "name": c["name"], "created": c["created"], "last_used": c["last_used"],
                          "unlock": bool(c["wrapped_private_key"])} for c in vault.credentials(user["id"])],
            "recovery": bool(s.get("recovery")), "can_add_passkey": bool(s.get("priv") and s["priv"][1] > time.time()),
            "providers": {k: auth.PROVIDERS[k]["label"] for k in providers()},
            "prefs": vault.get(f"prefs:{user['id']}", {})}


THEMES, THEME_MODES = ("ember", "arctic", "volt", "crimson", "mono"), ("light", "dark", "system")
TEXT_SIZES = ("auto", "100", "115", "130", "150", "175", "200")


class Prefs(BaseModel):
    mode: str
    theme: str
    size: str = "auto"


@app.post("/api/me/prefs")
def my_prefs(body: Prefs, request: Request):
    """Appearance is per person and follows them to every device; it's not a secret, so it lives outside the vault."""
    sid, s, user = require(request)
    if body.mode not in THEME_MODES or body.theme not in THEMES or body.size not in TEXT_SIZES:
        raise HTTPException(400, "Unknown mode, theme or text size")
    vault.put(f"prefs:{user['id']}", {"mode": body.mode, "theme": body.theme, "size": body.size})
    return {"ok": True}


# -- remediation tracking: owner, due date, status per finding; kept beside the run, written only by the console ----
TRACK_STATUSES = ("open", "in_progress", "fixed", "accepted")
SEV_PRIORITY = {"critical": 1, "high": 2, "medium": 3}


def priority_of(f):
    """The Risk analyst's priority, or one derived from severity when it hasn't ranked the finding."""
    return (f.get("risk") or {}).get("priority") or SEV_PRIORITY.get(f.get("severity"), 4)


def _tracking(d):
    try:
        return json.loads((d / "tracking.json").read_text())
    except (OSError, ValueError):
        return {}


def _save_tracking(d, data):
    tmp = d / "tracking.json.tmp"
    tmp.write_text(json.dumps(data, indent=1))
    os.replace(tmp, d / "tracking.json")


def carry_tracking(run_id):
    """Copy owner, due date and status from the previous assessment onto findings the Risk analyst linked to it."""
    d = run_dir(run_id)
    g = _read_graph(d)
    own = _tracking(d)
    prev_cache = {}
    changed = False
    for f in g.get("findings") or []:
        link = f.get("previous")
        if not link or f["id"] in own or not RUN_ID.match(link.get("run", "")):
            continue
        if link["run"] not in prev_cache:
            prev_cache[link["run"]] = _tracking(RUNS / link["run"]) if (RUNS / link["run"]).is_dir() else {}
        old = prev_cache[link["run"]].get(link["id"])
        if old:
            own[f["id"]] = {**old, "carried_from": f"{link['run']}/{link['id']}"}
            changed = True
    if changed:
        _save_tracking(d, own)


def tracking_rows(d, g):
    own = _tracking(d)
    started = g.get("started") or ""
    rows = []
    for f in g.get("findings") or []:
        if f.get("status") == "duplicate":
            continue
        t = own.get(f["id"], {})
        pr = priority_of(f)
        first = (f.get("first_seen") or started)[:10]
        try:
            due_default = time.strftime("%Y-%m-%d", time.localtime(time.mktime(time.strptime(first, "%Y-%m-%d")) + PRIORITY_DAYS[pr] * 86400))
        except ValueError:
            due_default = None
        due = t.get("due") or due_default
        verified = f.get("status") == "resolved"
        status = "verified" if verified else t.get("status", "open")
        r = f.get("risk") or {}
        rows.append({"id": f["id"], "title": f.get("title"), "asset": f.get("asset"), "layer": f.get("layer"),
                     "severity": f.get("severity"), "priority": pr, "ranked": bool(r), "reason": r.get("reason"),
                     "kev": r.get("kev"), "ransomware": r.get("ransomware"), "epss": r.get("epss"), "exposure": r.get("exposure"),
                     "recommendation": f.get("recommendation"), "first_seen": first, "due": due,
                     "overdue": bool(due and not verified and status not in ("fixed", "accepted") and due < time.strftime("%Y-%m-%d")),
                     "owner": t.get("owner", ""), "status": status, "note": t.get("note", ""), "updated_by": t.get("updated_by"),
                     "recheck": t.get("recheck"), "carried_from": t.get("carried_from"), "ticket": t.get("ticket")})
    rows.sort(key=lambda r: (r["status"] == "verified", r["priority"], SEV_ORDER.index(r["severity"] or "info"), r["id"]))
    return rows


@app.get("/api/runs/{run_id}/tracking")
def run_tracking(run_id: str, request: Request):
    require(request)
    d = run_dir(run_id)
    g = _read_graph(d)
    rows = tracking_rows(d, g)
    return {"rows": rows, "ranked": any(r["ranked"] for r in rows), "sla": PRIORITY_DAYS,
            "counts": {"open": sum(1 for r in rows if r["status"] in ("open", "in_progress")),
                       "overdue": sum(1 for r in rows if r["overdue"]), "verified": sum(1 for r in rows if r["status"] == "verified")}}


class TrackBody(BaseModel):
    owner: Optional[str] = None
    due: Optional[str] = None
    status: Optional[str] = None
    note: Optional[str] = None


@app.post("/api/runs/{run_id}/tracking/{fid}")
def run_tracking_set(run_id: str, fid: str, body: TrackBody, request: Request):
    sid, s, user = require(request, "operator")
    d = run_dir(run_id)
    if not any(f["id"] == fid for f in _read_graph(d).get("findings") or []):
        raise HTTPException(404, "No such finding")
    if body.status is not None and body.status not in TRACK_STATUSES:
        raise HTTPException(400, "Unknown status")
    if body.due and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", body.due):
        raise HTTPException(400, "Due date must be YYYY-MM-DD")
    data = _tracking(d)
    t = data.setdefault(fid, {})
    for k in ("owner", "due", "status", "note"):
        v = getattr(body, k)
        if v is not None:
            t[k] = v.strip()[:300 if k == "note" else 80]
    t.update(updated_by=user["name"], updated=time.time())
    _save_tracking(d, data)
    vault.audit(user["email"], "finding-tracked", f"{run_id} {fid}: " + ", ".join(f"{k}={getattr(body, k)}" for k in ("owner", "due", "status") if getattr(body, k) is not None))
    return {"ok": True}


@app.post("/api/runs/{run_id}/findings/{fid}/recheck")
async def run_recheck(run_id: str, fid: str, request: Request):
    """Send one finding back to the agent that found it; it re-checks read-only and marks it resolved if it's gone."""
    sid, s, user = require(request, "operator")
    d = run_dir(run_id)
    f = next((x for x in _read_graph(d).get("findings") or [] if x["id"] == fid), None)
    if not f:
        raise HTTPException(404, "No such finding")
    layer = f.get("layer")
    if layer not in LAYERS or layer in ANALYSTS or layer == "discovery":
        raise HTTPException(400, "This finding can't be re-checked automatically")
    if job.running:
        raise HTTPException(409, "A run is already in progress")
    order = {"agent": layer, "id": "RC-" + secrets.token_hex(3),
             "instruction": f"Re-check finding {fid} \"{f.get('title')}\" on {f.get('asset')}. Repeat the read-only checks "
                            f"that found it. If the issue is gone, call update_finding with status resolved and quote what you "
                            f"observed; if it is still there, call update_finding with status open and the new evidence."}
    status = launch("followup", run_id, sid, user, inbox=order)
    data = _tracking(d)
    data.setdefault(fid, {})["recheck"] = {"by": user["name"], "at": time.time()}
    _save_tracking(d, data)
    vault.audit(user["email"], "finding-recheck", f"{run_id} {fid} by {layer}")
    return status


# -- attack paths and compliance from the analyst agents ---------------------------------------------------
@app.get("/api/runs/{run_id}/paths")
def run_paths(run_id: str, request: Request):
    require(request)
    g = _read_graph(run_dir(run_id))
    titles = {f["id"]: {"title": f.get("title"), "severity": f.get("severity"), "priority": priority_of(f), "asset": f.get("asset")}
              for f in g.get("findings") or []}
    return {"paths": g.get("attack_paths") or [], "findings": titles, "analysed": "paths" in (g.get("agents") or {})}


@app.get("/api/runs/{run_id}/compliance")
def run_compliance(run_id: str, request: Request):
    require(request)
    g = _read_graph(run_dir(run_id))
    done = g.get("compliance") or {}
    titles = {f["id"]: f.get("title") for f in g.get("findings") or []}
    out = {}
    for key, fw in FRAMEWORKS.items():
        got = done.get(key, {})
        if fw.get("optional") and not got:
            continue
        controls = [{"id": c, "title": t, **got.get(c, {"status": "not_assessed", "findings": [], "note": "Not mapped by the Compliance agent."})}
                    for c, t in fw["controls"]]
        out[key] = {"title": fw["title"], "controls": controls, "mapped": bool(got),
                    "counts": {st: sum(1 for c in controls if c["status"] == st) for st in CONTROL_STATUSES}}
    return {"frameworks": out, "findings": titles, "analysed": "compliance" in (g.get("agents") or {})}


# -- schedules, unattended AI runs and alerts -----------------------------------------------------------
UNATTENDED = STATE / "unattended.key"
EVERY = {"quick": ("off", "daily", "weekly"), "full": ("off", "weekly", "monthly")}
DEFAULT_SCHEDULE = {"quick": {"every": "off", "time": "02:00", "day": 0, "mday": 1},
                    "full": {"every": "off", "time": "03:00", "day": 6, "mday": 1}}
DEFAULT_NOTIFY = {"threshold": "p2", "changes": True, "email": {"on": False, "host": "", "port": 587, "username": "",
                  "sender": "", "to": []}, "teams": {"on": False}, "slack": {"on": False}, "webhook": {"on": False}}
SECRET_FIELDS = {"email": "password", "teams": "url", "slack": "url", "webhook": "url"}


def schedule_cfg():
    cfg = vault.get("schedule", {})
    return {k: {**DEFAULT_SCHEDULE[k], **cfg.get(k, {})} for k in DEFAULT_SCHEDULE} | {"last": cfg.get("last", {})}


def notify_cfg():
    cfg = vault.get("notify", {})
    return {**DEFAULT_NOTIFY, **cfg, **{k: {**DEFAULT_NOTIFY[k], **cfg.get(k, {})} for k in ("email", "teams", "slack", "webhook")}}


def _target(c, now):
    """Today's scheduled time for this entry, or None when it doesn't fall on today."""
    lt = time.localtime(now)
    if c["every"] == "off" or (c["every"] == "weekly" and lt.tm_wday != int(c["day"])) or \
            (c["every"] == "monthly" and lt.tm_mday != int(c["mday"])):
        return None
    hh, mm = map(int, c["time"].split(":"))
    return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, hh, mm, 0, 0, 0, -1))


def next_runs(cfg, now=None):
    now = now or time.time()
    out = {}
    for k in ("quick", "full"):
        if cfg[k]["every"] == "off":
            continue
        for day in range(0, 32):
            t = _target(cfg[k], now + day * 86400)
            if t and t > now:
                out[k] = t
                break
    return out


def unattended_key():
    try:
        return UNATTENDED.read_text().strip() or None
    except OSError:
        return None


async def scheduler_loop():
    while True:
        await asyncio.sleep(60)
        try:
            scheduled_tick()
        except Exception as e:                                      # noqa: BLE001 - keep the scheduler alive
            print(f"[scheduler] {e}", flush=True)


def scheduled_tick(now=None):
    now = now or time.time()
    cfg = schedule_cfg()
    due = None
    for kind in ("full", "quick"):                 # a full run includes the scan, so it wins when both are due
        t = _target(cfg[kind], now)
        if t and t <= now < t + 3600 and cfg["last"].get(kind, 0) < t:
            due = due or kind
            cfg["last"][kind] = now                 # both count as done when the full run goes
    if not due or job.running:
        return None
    note, extra, mode = None, {}, "full" if due == "full" else "collect"
    if mode == "full":
        key = api_keys().get("anthropic") if vault.unlocked else None
        key = key or unattended_key()
        if key:
            extra["ANTHROPIC_API_KEY"] = key
            nvd = api_keys().get("nvd") if vault.unlocked else None
            if nvd:
                extra["NVD_API_KEY"] = nvd
        else:
            mode, note = "collect", "The scheduled AI run was skipped: the vault was locked and unattended AI runs are off. A scan ran instead."
    stored = vault.get("schedule", {})
    stored["last"] = cfg["last"]
    vault.put("schedule", stored)
    start_job(mode, None, "Schedule", extra, note=note, stdin=connector_handoff() if mode == "full" else None)
    vault.audit("system", "scheduled-run", MODES[mode]["label"] + (f" ({note})" if note else ""))
    return mode


def after_run(run_id, mode, note=None):
    """Runs in the console once a run has finished: carry tracking over, then send alerts."""
    if mode in ("full", "resume", "followup"):
        carry_tracking(run_id)
        try:
            sync_tickets(run_id, auto=True)
        except Exception as e:                                      # noqa: BLE001 - tickets must not block alerts
            vault.audit("system", "ticketing-failed", str(e)[:200])
    cfg = notify_cfg()
    if not any(cfg[c].get("on") for c in ("email", "teams", "slack", "webhook")):
        return
    g = _read_graph(run_dir(run_id))
    alert = notify.build_alert(g, run_id, site()[1], cfg.get("threshold", "p2"), cfg.get("changes", True))
    if note:
        alert = alert or {"subject": f"Guardian: scheduled run {run_id}", "body": "", "lines": []}
        alert["lines"].insert(0, note)
        alert["body"] = note + "\n\n" + alert["body"]
    if not alert:
        return
    result = notify.send(_notify_secrets(cfg), alert)
    vault.put("notify_last", {"t": time.time(), "run": run_id, "result": result, "subject": alert["subject"]})
    vault.audit("system", "alert-sent", f"{run_id}: " + ", ".join(f"{k} {v if v == 'ok' else 'failed'}" for k, v in result.items()))


def _notify_secrets(cfg):
    sec = vault.get("notify_secrets", {})
    return {**cfg, **{k: {**cfg[k], SECRET_FIELDS[k]: sec.get(k, "")} for k in SECRET_FIELDS}}


@app.get("/api/schedule")
def schedule_get(request: Request):
    require(request, "admin")
    cfg, n = schedule_cfg(), notify_cfg()
    sec = vault.get("notify_secrets", {})
    return {"schedule": {k: cfg[k] for k in ("quick", "full")}, "last": cfg["last"], "next": next_runs(cfg),
            "unattended": bool(unattended_key()), "unattended_info": vault.get("unattended", {}),
            "notify": {**n, **{k: {**n[k], "secret_set": bool(sec.get(k))} for k in SECRET_FIELDS}},
            "notify_last": vault.get("notify_last", {}), "anthropic_key_set": bool(vault.get("api_keys_set", {}).get("anthropic"))}


class ScheduleEntry(BaseModel):
    every: str
    time: str
    day: int = 0
    mday: int = 1


class ScheduleBody(BaseModel):
    quick: ScheduleEntry
    full: ScheduleEntry


@app.post("/api/schedule")
def schedule_set(body: ScheduleBody, request: Request):
    sid, s, user = require(request, "admin")
    out = {}
    for k in ("quick", "full"):
        e = getattr(body, k)
        if e.every not in EVERY[k] or not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", e.time) or not 0 <= e.day <= 6 or not 1 <= e.mday <= 28:
            raise HTTPException(400, f"Check the {k} schedule")
        out[k] = e.model_dump()
    stored = vault.get("schedule", {})
    stored.update(out)
    vault.put("schedule", stored)
    vault.audit(user["email"], "schedule-changed", f"scan {out['quick']['every']} {out['quick']['time']}, AI {out['full']['every']} {out['full']['time']}")
    return {"ok": True, "next": next_runs(schedule_cfg())}


class UnattendedBody(BaseModel):
    on: bool


@app.post("/api/schedule/unattended")
def schedule_unattended(body: UnattendedBody, request: Request):
    """Scheduled AI runs while the vault is locked need a copy of the Anthropic key outside the vault (root-only file)."""
    if not body.on:
        sid, s, user = require(request, "admin")
        try:
            UNATTENDED.unlink()
        except FileNotFoundError:
            pass
        vault.put("unattended", {})
        vault.audit(user["email"], "unattended-off", "Removed the unattended copy of the Anthropic key")
        return {"ok": True}
    sid, s, user = require_fresh(request)
    key = api_keys().get("anthropic")
    if not key:
        raise HTTPException(400, "Add the Anthropic API key in Settings first")
    fd = os.open(UNATTENDED, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key)
    vault.put("unattended", {"by": user["name"], "at": time.time()})
    vault.audit(user["email"], "unattended-on", "Stored a copy of the Anthropic key for scheduled AI runs (file permissions)")
    return {"ok": True}


class ChannelBody(BaseModel):
    on: bool = False
    url: Optional[str] = None


class EmailBody(BaseModel):
    on: bool = False
    host: str = ""
    port: int = 587
    username: str = ""
    password: Optional[str] = None
    sender: str = ""
    to: list[str] = []


class NotifyBody(BaseModel):
    threshold: str = "p2"
    changes: bool = True
    email: EmailBody
    teams: ChannelBody
    slack: ChannelBody
    webhook: ChannelBody


@app.post("/api/notify")
def notify_set(body: NotifyBody, request: Request):
    sid, s, user = require(request, "admin")
    if body.threshold not in notify.THRESHOLDS:
        raise HTTPException(400, "Unknown threshold")
    sec = vault.get("notify_secrets", {})
    for ch in ("teams", "slack", "webhook"):
        c = getattr(body, ch)
        if c.url:
            if not c.url.startswith("https://") or len(c.url) > 2000:
                raise HTTPException(400, f"The {ch} address must start with https://")
            sec[ch] = c.url.strip()
        if c.on and not sec.get(ch):
            raise HTTPException(400, f"Paste the {ch} address first")
    e = body.email
    if e.password:
        sec["email"] = e.password
    to = [x.strip() for x in e.to if x.strip()]
    if e.on and (not e.host or not e.sender or not to or any(not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", x) for x in to + [e.sender])):
        raise HTTPException(400, "E-mail needs a server, a sender and valid recipient addresses")
    vault.put("notify_secrets", sec)
    vault.put("notify", {"threshold": body.threshold, "changes": body.changes,
                         "email": {"on": e.on, "host": e.host.strip(), "port": e.port, "username": e.username.strip(), "sender": e.sender.strip(), "to": to},
                         **{ch: {"on": getattr(body, ch).on} for ch in ("teams", "slack", "webhook")}})
    vault.audit(user["email"], "alerts-changed", ", ".join(ch for ch in ("email", "teams", "slack", "webhook") if getattr(body, ch).on) or "all off")
    return {"ok": True}


@app.post("/api/notify/test")
def notify_test(request: Request):
    sid, s, user = require(request, "admin")
    cfg = notify_cfg()
    if not any(cfg[c].get("on") for c in ("email", "teams", "slack", "webhook")):
        raise HTTPException(400, "Turn on at least one channel and save first")
    alert = {"subject": "Guardian: test alert", "lines": ["This is a test from Guardian's alert settings."],
             "body": f"This is a test from Guardian's alert settings, sent by {user['name']}.\n\nOpen the console: {site()[1]}/"}
    result = notify.send(_notify_secrets(cfg), alert)
    vault.audit(user["email"], "alert-test", ", ".join(f"{k} {v if v == 'ok' else 'failed'}" for k, v in result.items()))
    return {"result": result}


# -- ticketing (ServiceNow first) ----------------------------------------------------------------------
TICKET_DEFAULT = {"system": "servicenow", "on": False, "auto": False, "threshold": "p2", "resolve_on_verify": False,
                  "instance": "", "username": "", "table": "incident", "assignment_group": "", "caller_id": "", "category": ""}


def ticket_cfg():
    return {**TICKET_DEFAULT, **vault.get("ticketing", {})}


def ticket_client(cfg=None):
    cfg = cfg or ticket_cfg()
    if not cfg.get("on"):
        raise HTTPException(400, "Ticketing is off: set it up in Settings › Ticketing")
    pw = vault.get("ticketing_secrets", {}).get("servicenow")
    if not pw:
        raise HTTPException(400, "The ServiceNow password isn't saved yet")
    try:
        return ticketing.ServiceNow(cfg, pw)
    except ticketing.TicketError as e:
        raise HTTPException(400, str(e))


def _ticket_finding(run_id, row, g):
    f = next((x for x in g.get("findings") or [] if x["id"] == row["id"]), {})
    return {**row, "evidence": f.get("evidence"), "key": f"{run_id}/{row['id']}"}


def sync_tickets(run_id, auto=False):
    """Open tickets for new high-priority findings (auto), and read ticket states back into the Fix plan."""
    cfg = ticket_cfg()
    if not cfg.get("on") or not vault.get("ticketing_secrets", {}).get("servicenow"):
        return {"created": 0, "updated": 0}
    sn = ticketing.ServiceNow(cfg, vault.get("ticketing_secrets", {})["servicenow"])
    d = run_dir(run_id)
    g = _read_graph(d)
    data = _tracking(d)
    limit = notify.THRESHOLDS.get(cfg.get("threshold", "p2"), 2)
    created = updated = 0
    for row in tracking_rows(d, g):
        t = data.get(row["id"], {})
        tk = t.get("ticket")
        if not tk and auto and cfg.get("auto") and row["priority"] <= limit and row["status"] in ("open", "in_progress"):
            fnd = _ticket_finding(run_id, row, g)
            tk = sn.find(fnd["key"]) or sn.create(fnd, run_id, site()[1])
            tk["key"] = fnd["key"]
            data[row["id"]] = {**t, "ticket": tk}
            created += 1
            continue
        if not tk or tk.get("system") != "servicenow":
            continue
        data[row["id"]] = t
        st = sn.state(tk["sys_id"])
        if st["state"] != tk.get("state"):
            tk["state"], updated = st["state"], updated + 1
        if st["state"] in ("resolved", "closed") and t.get("status", "open") in ("open", "in_progress") and row["status"] != "verified":
            t["status"] = "fixed"
            t["note"] = (t.get("note", "") + f" · {tk['number']} {st['state']} in ServiceNow; Re-check to verify").strip(" ·")[:300]
        if row["status"] == "verified" and not tk.get("verified_noted"):
            sn.note(tk["sys_id"], f"Guardian re-checked {row['id']} \"{row['title']}\" and confirmed it is fixed.",
                    resolve=bool(cfg.get("resolve_on_verify")) and st["state"] not in ("resolved", "closed"))
            tk["verified_noted"] = True
            updated += 1
    _save_tracking(d, data)
    if created or updated:
        vault.audit("system", "tickets-synced", f"{run_id}: {created} created, {updated} updated")
    return {"created": created, "updated": updated}


@app.get("/api/ticketing")
def ticketing_get(request: Request):
    require(request, "admin")
    return {**ticket_cfg(), "secret_set": bool(vault.get("ticketing_secrets", {}).get("servicenow"))}


class TicketingBody(BaseModel):
    on: bool = False
    auto: bool = False
    threshold: str = "p2"
    resolve_on_verify: bool = False
    instance: str = ""
    username: str = ""
    password: Optional[str] = None
    table: str = "incident"
    assignment_group: str = ""
    caller_id: str = ""
    category: str = ""


@app.post("/api/ticketing")
def ticketing_set(body: TicketingBody, request: Request):
    sid, s, user = require(request, "admin")
    if body.threshold not in notify.THRESHOLDS:
        raise HTTPException(400, "Unknown threshold")
    cfg = {k: (v.strip() if isinstance(v, str) else v) for k, v in body.model_dump().items() if k != "password"}
    cfg["system"] = "servicenow"
    if cfg["on"]:
        if not ticketing.INSTANCE_RE.match(cfg["instance"].rstrip("/")) or not cfg["username"]:
            raise HTTPException(400, "Enter the instance address (https://yourcompany.service-now.com) and the integration user")
        if not re.fullmatch(r"[a-z_][a-z0-9_]{0,79}", cfg["table"]):
            raise HTTPException(400, "Unknown table name")
    for k in ("assignment_group", "caller_id", "category"):
        if len(cfg[k]) > 100:
            raise HTTPException(400, f"{k} is too long")
    if body.password:
        vault.put("ticketing_secrets", {"servicenow": body.password})
    if cfg["on"] and not vault.get("ticketing_secrets", {}).get("servicenow"):
        raise HTTPException(400, "Enter the integration user's password")
    vault.put("ticketing", cfg)
    vault.audit(user["email"], "ticketing-changed", f"ServiceNow {'on' if cfg['on'] else 'off'}, auto {cfg['auto']} ({cfg['threshold']})")
    return {"ok": True}


@app.post("/api/ticketing/test")
def ticketing_test(request: Request):
    sid, s, user = require(request, "admin")
    try:
        return {"ok": True, **ticket_client().test()}
    except ticketing.TicketError as e:
        raise HTTPException(400, str(e))


@app.post("/api/runs/{run_id}/tracking/{fid}/ticket")
def ticket_create(run_id: str, fid: str, request: Request):
    sid, s, user = require(request, "operator")
    d = run_dir(run_id)
    g = _read_graph(d)
    row = next((r for r in tracking_rows(d, g) if r["id"] == fid), None)
    if not row:
        raise HTTPException(404, "No such finding")
    data = _tracking(d)
    if (data.get(fid) or {}).get("ticket"):
        raise HTTPException(409, "This finding already has a ticket")
    sn = ticket_client()
    fnd = _ticket_finding(run_id, row, g)
    try:
        tk = sn.find(fnd["key"]) or sn.create(fnd, run_id, site()[1])
    except ticketing.TicketError as e:
        raise HTTPException(502, str(e))
    tk["key"] = fnd["key"]
    data.setdefault(fid, {})["ticket"] = tk
    _save_tracking(d, data)
    vault.audit(user["email"], "ticket-created", f"{run_id} {fid} -> {tk.get('number')}")
    return tk


@app.post("/api/runs/{run_id}/tickets/sync")
def ticket_sync(run_id: str, request: Request):
    sid, s, user = require(request, "operator")
    run_dir(run_id)
    try:
        return sync_tickets(run_id)
    except ticketing.TicketError as e:
        raise HTTPException(502, str(e))


# -- sites and on-site collectors (phase A) ------------------------------------------------------------
GATEWAY_DATA = Path(os.environ.get("GUARDIAN_GATEWAY_DATA", BASE / "gateway"))
GATEWAY_USER = "guardian-gw"
JOB_KEY = STATE / "job-signing.key"
_site_store = None
_site_lock = threading.Lock()


def job_pubkey():
    """The key collectors use to check jobs (phase B). Its private half stays here; the gateway never has it."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if not JOB_KEY.exists():
        k = Ed25519PrivateKey.generate()
        fd = os.open(JOB_KEY, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    k = serialization.load_pem_private_key(JOB_KEY.read_bytes(), None)
    raw = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def sites_db():
    """The database shared with the gateway. It belongs to the gateway's user so both services can write it."""
    global _site_store
    with _site_lock:
        if _site_store is None:
            GATEWAY_DATA.mkdir(mode=0o700, exist_ok=True)
            db = GATEWAY_DATA / "gateway.db"
            if not db.exists():
                os.close(os.open(db, os.O_WRONLY | os.O_CREAT, 0o600))
            if os.geteuid() == 0:
                try:
                    import pwd
                    pw = pwd.getpwnam(GATEWAY_USER)
                    for p in (GATEWAY_DATA, db):
                        os.chown(p, pw.pw_uid, pw.pw_gid)
                except KeyError:
                    pass
            _site_store = sitestore.Store(db)
            _site_store.set_meta("job_pubkey", job_pubkey())
        return _site_store


def gateway_info():
    host = site()[0]
    url = os.environ.get("GUARDIAN_GATEWAY_URL") or f"https://{host}:{os.environ.get('GUARDIAN_GATEWAY_PORT', '8444')}"
    cert = GATEWAY_DATA / "tls-cert.pem"
    try:
        pin = sitestore.spki_pin(cert) if cert.exists() else None
    except (OSError, ValueError):
        pin = None
    return {"url": url, "pin": pin}


def site_or_404(site_id):
    st = sites_db().site(site_id)
    if not st:
        raise HTTPException(404, "No such site")
    return st


@app.get("/api/sites")
def sites_list(request: Request):
    require(request, "operator")
    return {"sites": sites_db().sites(), "gateway": gateway_info(), "now": time.time()}


@app.get("/api/sites/{site_id}/events")
def site_events(site_id: str, request: Request):
    require(request, "operator")
    site_or_404(site_id)
    return {"events": sites_db().events(site_id)}


class SiteBody(BaseModel):
    name: str
    customer: str = ""


@app.post("/api/sites")
def sites_add(body: SiteBody, request: Request):
    sid, s, user = require(request, "admin")
    name, customer = body.name.strip(), body.customer.strip()
    if not 1 <= len(name) <= 80 or len(customer) > 120 or any(ord(c) < 32 for c in name + customer):
        raise HTTPException(400, "Give the site a name (up to 80 characters)")
    new = sites_db().add_site(name, customer)
    vault.audit(user["email"], "site-added", f"{new} {name}")
    return {"id": new}


@app.delete("/api/sites/{site_id}")
def sites_delete(site_id: str, request: Request):
    sid, s, user = require(request, "admin")
    st = site_or_404(site_id)
    if site_id == sitestore.LOCAL_SITE:
        raise HTTPException(400, "This network can't be removed")
    sites_db().delete_site(site_id)
    vault.audit(user["email"], "site-deleted", f"{site_id} {st['name']} (its collector is revoked)")
    return {"ok": True}


@app.post("/api/sites/{site_id}/enroll")
def sites_enroll(site_id: str, request: Request):
    sid, s, user = require_fresh(request)
    st = site_or_404(site_id)
    if site_id == sitestore.LOCAL_SITE:
        raise HTTPException(400, "This network is assessed by the server itself")
    code, expires = sites_db().create_code(site_id, user["email"])
    s["fresh_at"] = 0
    vault.audit(user["email"], "collector-code", f"{site_id} {st['name']}: one-time enrollment code, valid 24 h")
    return {"code": code, "expires": expires, **gateway_info()}


@app.delete("/api/sites/{site_id}/enroll")
def sites_enroll_cancel(site_id: str, request: Request):
    sid, s, user = require(request, "admin")
    site_or_404(site_id)
    sites_db().cancel_code(site_id)
    vault.audit(user["email"], "collector-code-cancelled", site_id)
    return {"ok": True}


@app.post("/api/sites/{site_id}/revoke")
def sites_revoke(site_id: str, request: Request):
    sid, s, user = require(request, "admin")
    st = site_or_404(site_id)
    n = sites_db().revoke(site_id)
    vault.audit(user["email"], "collector-revoked", f"{site_id} {st['name']}")
    return {"revoked": n}


# -- console --------------------------------------------------------------------------------------------
@app.get("/api/overview")
def overview(request: Request):
    require(request)
    RUNS.mkdir(exist_ok=True)
    runs = [run_summary(d) for d in sorted(RUNS.iterdir(), reverse=True) if d.is_dir() and RUN_ID.match(d.name)]
    return {"runs": runs, "config": public_config(), "job": job.status(since=job.seq)}


@app.get("/api/runs/{run_id}/report")
def report(run_id: str, request: Request):
    require(request)
    path = run_dir(run_id) / "report.html"
    if not path.exists():
        raise HTTPException(404, "No report for this run")
    # Chrome gives a CSP-sandboxed page an opaque origin, so frame-ancestors 'self' / SAMEORIGIN would block
    # the console's own frame; X-Frame-Options is dropped for this response only.
    return FileResponse(path, media_type="text/html", headers={"Content-Security-Policy": REPORT_CSP, "X-Frame-Options": ""})


@app.get("/api/runs/{run_id}/graph")
def graph(run_id: str, request: Request):
    require(request)
    path = run_dir(run_id) / "graph.json"
    if not path.exists():
        raise HTTPException(404, "No data for this run")
    return FileResponse(path, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="graph-{run_id}.json"'})


class Start(BaseModel):
    mode: str
    run_id: Optional[str] = None


@app.post("/api/job/start")
async def start(body: Start, request: Request):
    sid, s, user = require(request, "operator")
    if body.mode == "followup":
        raise HTTPException(400, "Follow-ups start from the chat")
    return launch(body.mode, body.run_id, sid, user)


def launch(mode, run_id, sid, user, inbox=None):
    if job.running:
        raise HTTPException(409, "A run is already in progress")
    if mode not in MODES:
        raise HTTPException(400, "Unknown mode")
    if mode in ("resume", "report", "followup"):
        d = run_dir(run_id)
        if not (d / "graph.json").exists():
            raise HTTPException(400, "That run has no scan data")
    extra = {}
    if mode in ("full", "resume", "followup"):
        if sid not in vault.holders:
            raise HTTPException(423, "Unlock the vault with your passkey first: the AI step needs the API key")
        keys = api_keys()
        if not keys.get("anthropic"):
            raise HTTPException(400, "Add your Anthropic API key in Settings first")
        extra["ANTHROPIC_API_KEY"] = keys["anthropic"]           # handed to the run in memory, never written to disk
        if keys.get("nvd"):
            extra["NVD_API_KEY"] = keys["nvd"]
        vault.audit(user["email"], "secret-used", "API keys for an AI assessment")
    stdin = None
    if mode in ("full", "resume", "followup"):
        stdin = connector_handoff()
        if stdin:
            vault.audit(user["email"], "secret-used", "Connectors for the connector agents (AD, Microsoft 365, devices, patch & configuration)")
    if inbox:
        chat.send_to_inbox(run_dir(run_id), inbox, user["name"])
    status = start_job(mode, run_id, user["name"], extra, stdin=stdin)
    vault.audit(user["email"], "scan-started", MODES[mode]["label"])
    return status


HANDOFF_TYPES = ("active_directory", "linux_ssh", "synology", "proxmox_ve", "proxmox_bs", "m365", "windows", "azure")


def connector_handoff():
    """The connectors the connector agents use, decrypted, as bytes for the run's stdin. None when there are none."""
    if not vault.unlocked:
        return None
    items = [{"id": c["id"], "type": c["type"], "name": c.get("name") or conn.CATALOG[c["type"]]["label"],
              "fields": store.fields_with_secrets(c), "pin": c.get("pin")}
             for c in store.connectors() if c.get("type") in HANDOFF_TYPES]
    if not items:
        return None
    key = next((r["private"] for r in vault.load_records("secret") if "private" in r), None) \
        if any(i["type"] == "linux_ssh" for i in items) else None
    return json.dumps({"connectors": items, "ssh_private_key": key, "state_dir": str(STATE)}).encode()


def start_job(mode, run_id, by, extra, note=None, stdin=None):
    """Start run.py for this mode. Callers have checked permissions and gathered the keys it needs."""
    cmd = [PYTHON, str(BASE / "run.py"), *MODES[mode]["args"]]
    target = None
    if mode in ("resume", "report", "followup"):
        d = run_dir(run_id)
        cmd.append(str(d))
        target = d.name
    job.__init__()
    job.mode, job.run_id, job.started, job.by, job.note = mode, target, time.time(), by, note
    job.step = MODES[mode]["steps"][0]
    job.add(f"[console] {MODES[mode]['label']} started by {by}")
    if note:
        job.add(f"[console] {note}")
    asyncio.create_task(run_job(cmd, extra, stdin))
    return job.status()


@app.post("/api/job/stop")
async def stop(request: Request):
    sid, s, user = require(request, "operator")
    if not job.running:
        raise HTTPException(409, "Nothing is running")
    job.stopped = True
    os.killpg(job.proc.pid, signal.SIGTERM)
    for _ in range(20):
        if not job.running:
            break
        await asyncio.sleep(0.5)
    if job.running:
        os.killpg(job.proc.pid, signal.SIGKILL)
    vault.audit(user["email"], "scan-stopped", "")
    return {"ok": True}


@app.get("/api/job")
def job_status(request: Request, since: int = 0):
    require(request)
    return job.status(since=since)


class Settings(BaseModel):
    model: str
    effort: str
    max_rounds: int = 40
    parallel: int = 3
    agents_off: list[str] = []
    scale_mode: str = "auto"
    per_copy: int = 25
    scale: dict = {}
    anthropic_key: Optional[str] = None
    nvd_key: Optional[str] = None


@app.post("/api/settings")
def save_settings(body: Settings, request: Request):
    sid, s, user = require(request, "admin")
    if body.model not in MODELS or body.effort not in EFFORTS:
        raise HTTPException(400, "Unknown model or effort")
    if body.max_rounds not in ROUNDS or body.parallel not in PARALLELS:
        raise HTTPException(400, "Unknown engine setting")
    if body.scale_mode not in SCALE_MODES or not 5 <= body.per_copy <= 200:
        raise HTTPException(400, "Unknown scaling setting")
    scale = []
    for layer, v in (body.scale or {}).items():
        try:
            lo, hi, man = (int(v.get(k, 1)) for k in ("min", "max", "manual"))
        except (TypeError, ValueError, AttributeError):
            raise HTTPException(400, "Scaling limits must be numbers")
        if layer not in LAYERS or not (1 <= lo <= hi <= 20 and 1 <= man <= 20):
            raise HTTPException(400, f"Check the limits for {layer}: 1 ≤ min ≤ max ≤ 20")
        scale.append(f"{layer}:{lo}:{1 if layer == 'wan' else hi}:{man}")
    off = sorted(set(body.agents_off))
    if any(a not in LAYERS or a == "discovery" for a in off):
        raise HTTPException(400, "Discovery can't be turned off: the other agents depend on it")
    before = public_config()
    write_env({"GUARDIAN_MODEL": body.model, "GUARDIAN_EFFORT": body.effort, "GUARDIAN_MAX_TURNS": body.max_rounds,
               "GUARDIAN_PARALLEL": body.parallel, "GUARDIAN_AGENTS_OFF": ",".join(off),
               "GUARDIAN_SCALE_MODE": body.scale_mode, "GUARDIAN_PER_COPY": body.per_copy, "GUARDIAN_SCALE": ",".join(sorted(scale))})
    if off != before["agents_off"]:
        vault.audit(user["email"], "agents-changed", "Turned off: " + (", ".join(off) or "none"))
    new = {k: (v or "").strip() for k, v in (("anthropic", body.anthropic_key), ("nvd", body.nvd_key)) if (v or "").strip()}
    if new:
        if sid not in vault.holders:
            raise HTTPException(423, "Unlock the vault with your passkey to change API keys")
        for k, v in new.items():
            if not API_KEY.match(v):
                raise HTTPException(400, f"The {k} key doesn't look like a valid key")
        rec = api_keys() or {"kind": "api-keys"}
        rec.update(new)
        vault.save_record("api-keys", "settings", rec)
        vault.put("api_keys_set", {"anthropic": bool(rec.get("anthropic")), "nvd": bool(rec.get("nvd"))})
        vault.audit(user["email"], "secret-changed", "API keys: " + ", ".join(new))
    return public_config()


# -- agents: live map, agent cards, Orchestrator chat ------------------------------------------------
def _read_graph(d):
    try:
        return json.loads((d / "graph.json").read_text())
    except (OSError, ValueError):
        return {}


SEV_ORDER = ["critical", "high", "medium", "low", "info"]


@app.get("/api/runs/{run_id}/summary")
def run_overview(run_id: str, request: Request):
    """The numbers for the overview panel: posture, exposure, top findings, riskiest devices, run cost."""
    require(request)
    g = _read_graph(run_dir(run_id))
    if not g:
        raise HTTPException(404, "No data for this run")
    assets = g.get("assets") or {}
    findings = [f for f in g.get("findings") or [] if is_open(f)]
    sev = collections.Counter(f.get("severity", "info") for f in findings)
    risk = {}
    for f in findings:
        ip = f.get("asset")
        if ip in assets:
            cur = risk.get(ip)
            if cur is None or SEV_ORDER.index(f.get("severity", "info")) < SEV_ORDER.index(cur):
                risk[ip] = f.get("severity", "info")
    def name(ip, a):
        return a.get("hostname") or " ".join(x for x in (a.get("vendor"), a.get("model")) if x) or a.get("mac_vendor") or ip
    inv = [{"ip": ip, "name": name(ip, a)[:40], "type": a.get("device_type") or "unknown", "risk": risk.get(ip, "ok")}
           for ip, a in assets.items()]
    inv.sort(key=lambda r: (SEV_ORDER.index(r["risk"]) if r["risk"] in SEV_ORDER else 9, tuple(map(int, r["ip"].split(".")))))
    top = sorted(findings, key=lambda f: (priority_of(f), SEV_ORDER.index(f.get("severity", "info")), f.get("id", "")))[:6]
    agents = g.get("agents") or {}
    times = [a.get(k) for a in agents.values() for k in ("started", "ended") if a.get(k)]
    usage = collections.Counter()
    for a in agents.values():
        usage.update(a.get("usage") or {})
    wan = g.get("wan") or {}
    s = g.get("summary") or {}
    return {
        "score": s.get("score"), "grade": s.get("grade"), "headline": s.get("headline"),
        "devices": len(assets),
        "unidentified": sum(1 for a in assets.values() if (a.get("device_type") or "unknown") == "unknown"),
        "forwards": len(wan.get("upnp_port_mappings") or []),
        "services": sum(1 for a in assets.values() for p in a.get("ports", []) if p.get("state") == "open"),
        "severity": {k: sev.get(k, 0) for k in SEV_ORDER}, "open": len(findings),
        "resolved": sum(1 for f in g.get("findings") or [] if f.get("status") == "resolved"),
        "top": [{**{k: f.get(k) for k in ("id", "title", "severity", "asset", "layer")}, "priority": priority_of(f),
                 "ranked": bool(f.get("risk")), "kev": (f.get("risk") or {}).get("kev")} for f in top],
        "paths": len(g.get("attack_paths") or []),
        "changes": g.get("changes"),
        "inventory": inv[:8],
        "cost": round(g.get("cost_total") or 0, 2),
        "cost_by": {k: round(a.get("cost", 0), 2) for k, a in agents.items() if a.get("cost")},
        "minutes": round((max(times) - min(times)) / 60) if len(times) > 1 else None,
        "rounds": sum(a.get("rounds", 0) for a in agents.values()),
        "checks": sum(sum((a.get("checks") or {}).values()) for a in agents.values()),
        "notes": len(g.get("notes") or []),
        "tokens": sum(usage.values()) - usage.get("searches", 0),
        "cache_read": usage.get("cache_read", 0),
        "started": g.get("started"),
    }


@app.get("/api/runs/{run_id}/live")
def run_live(run_id: str, request: Request, since: int = 0):
    """Everything the agent map and the agent cards need; events are incremental (n > since)."""
    require(request)
    d = run_dir(run_id)
    events = []
    path = d / "events.jsonl"
    if path.exists():
        with open(path) as f:
            for i, line in enumerate(f, 1):
                if i > since:
                    try:
                        events.append(json.loads(line))
                    except ValueError:
                        pass
                    if len(events) >= 3000:
                        break
    g = _read_graph(d)
    per_layer = collections.Counter(f.get("layer") for f in g.get("findings", []) if is_open(f))
    by_sev = collections.defaultdict(collections.Counter)
    for f in g.get("findings", []):
        if is_open(f):
            by_sev[f.get("layer")][f.get("severity", "info")] += 1
    agents = {}
    for name, a in (g.get("agents") or {}).items():
        agents[name] = {k: a.get(k) for k in ("status", "activity", "rounds", "max_rounds", "cost", "usage", "checks",
                                               "started", "ended", "devices", "followups", "copies", "running")}
        agents[name]["findings"] = per_layer.get(name, 0)
        agents[name]["by_severity"] = dict(by_sev.get(name, {}))
    return {"events": events, "agents": agents, "notes": g.get("notes", []), "cost_total": g.get("cost_total", 0),
            "ai": g.get("ai"), "running": job.running and job.run_id == run_id,
            "titles": {**{k: v["title"] for k, v in LAYERS.items()}, "orchestrator": "Orchestrator",
                       "report": "Report writer", "collector": "Scanner"}}


chat_times = collections.defaultdict(list)


@app.get("/api/runs/{run_id}/chat")
def chat_history(run_id: str, request: Request):
    sid, s, user = require(request)
    d = run_dir(run_id)
    items = [{k: v for k, v in m.items() if k != "uid"} for m in chat.history(d)]
    return {"messages": items, "can_ask": vault.unlocked and bool(api_keys().get("anthropic")),
            "can_order": ROLES.index(user["role"]) >= ROLES.index("operator"),
            "waiting": chat.inbox_waiting(d) and not (job.running and job.run_id == run_id)}


class ChatBody(BaseModel):
    message: str


@app.post("/api/runs/{run_id}/chat")
def chat_ask(run_id: str, body: ChatBody, request: Request):
    sid, s, user = require(request)
    d = run_dir(run_id)
    msg = body.message.strip()
    if not msg or len(msg) > 2000:
        raise HTTPException(400, "Write a message (up to 2000 characters)")
    if not (d / "graph.json").exists():
        raise HTTPException(400, "This run has no scan data yet")
    now = time.time()
    chat_times[user["id"]] = [t for t in chat_times[user["id"]] if now - t < 600]
    if len(chat_times[user["id"]]) >= 30:
        raise HTTPException(429, "That's a lot of questions in 10 minutes; wait a little")
    chat_times[user["id"]].append(now)
    key = api_keys().get("anthropic")
    if not key:
        raise HTTPException(423, "The chat needs the API key: an operator or admin has to unlock the vault")
    can_order = ROLES.index(user["role"]) >= ROLES.index("operator")
    model = read_env().get("GUARDIAN_MODEL") or "claude-opus-5-5"
    try:
        entry = chat.ask(d, msg, user, can_order, key, model)
    except chat.anthropic.APIError as e:
        raise HTTPException(502, f"The AI service returned an error: {str(e)[:200]}")
    vault.audit(user["email"], "chat", f"Run {run_id}: {msg[:120]}")
    return entry


@app.post("/api/runs/{run_id}/chat/orders/{oid}")
async def chat_order(run_id: str, oid: str, request: Request, body: dict):
    sid, s, user = require(request, "operator")
    d = run_dir(run_id)
    action = body.get("action")
    if action == "dismiss":
        o = chat.set_order(d, oid, "dismissed", user["name"])
        if not o:
            raise HTTPException(404, "That order was already handled")
        return {"order": o}
    if action != "send":
        raise HTTPException(400, "Unknown action")
    live = job.running and job.run_id == run_id
    if job.running and not live:
        raise HTTPException(409, "Another run is in progress; send this when it finishes")
    if not live and sid not in vault.holders:
        raise HTTPException(423, "Unlock the vault with your passkey first: the follow-up needs the API key")
    o = chat.set_order(d, oid, "sent", user["name"])
    if not o:
        raise HTTPException(404, "That order was already handled")
    chat.send_to_inbox(d, o, user["name"])
    vault.audit(user["email"], "agent-order", f'Run {run_id} → {o["agent"]}: {o["instruction"][:160]}')
    status = None
    if not live:
        status = launch("followup", run_id, sid, user)
    return {"order": o, "delivered": "live" if live else "follow-up", "job": status}


@app.post("/api/runs/{run_id}/followup")
async def run_followup(run_id: str, request: Request):
    """Run instructions that arrived after the run stopped reading them."""
    sid, s, user = require(request, "operator")
    d = run_dir(run_id)
    if not chat.inbox_waiting(d):
        raise HTTPException(400, "Nothing is waiting")
    return launch("followup", run_id, sid, user)


# -- remediation ------------------------------------------------------------------------------------------
FRESH_SECONDS = 120
fix_state = {"until": 0, "by": None, "scope": "all"}


def fix_on():
    return fix_state["until"] > time.time()


def require_fresh(request):
    """Admin, vault unlocked by this session, and a passkey confirmed in the last two minutes."""
    sid, s, user = require(request, "admin", unlocked=True)
    if time.time() - s.get("fresh_at", 0) > FRESH_SECONDS:
        raise HTTPException(428, "Confirm with your passkey first")
    return sid, s, user


def fix_hosts():
    rec = next((r for r in vault.load_records("settings") if r.get("kind") == "fix-accounts"), None) if vault.unlocked else None
    return (rec or {}).get("hosts", {})


def changes():
    return vault.get("changes", [])


def save_change(rec):
    items = [c for c in changes() if c["id"] != rec["id"]] + [rec]
    vault.put("changes", items[-200:])


def latest_analysed():
    if not RUNS.exists():
        return None, {}
    for d in sorted((d for d in RUNS.iterdir() if RUN_ID.match(d.name)), reverse=True):
        g = _read_graph(d)
        if g.get("findings") or (g.get("wan") or {}).get("upnp_port_mappings"):
            return d.name, g
    return None, {}


@app.get("/api/fix")
def fix_overview(request: Request):
    sid, s, user = require(request, "operator")
    run_id, g = latest_analysed()
    hosts = fix_hosts()
    done = {c["proposal"]: c for c in changes() if c["status"] in ("done", "running")}
    props = remediate.proposals(g, hosts, (g.get("site") or {}).get("collector_ip")) if g else []
    for p in props:
        p["change"] = done.get(p["id"], {}).get("id")
    return {"on": fix_on(), "until": fix_state["until"], "by": fix_state["by"], "run": run_id,
            "proposals": props, "recipes": remediate.RECIPES, "never": remediate.NEVER, "sudoers": remediate.SUDOERS,
            "public_key": vault.get("ssh_public_key"), "hosts": hosts if user["role"] == "admin" else {},
            "changes": sorted(changes(), key=lambda c: -c["created"])[:50], "admin": user["role"] == "admin",
            "unlocked": sid in vault.holders, "fresh": time.time() - s.get("fresh_at", 0) <= FRESH_SECONDS}


class FixOn(BaseModel):
    minutes: int


@app.post("/api/fix/on")
def fix_turn_on(body: FixOn, request: Request):
    sid, s, user = require_fresh(request)
    if body.minutes not in (30, 60, 240):
        raise HTTPException(400, "Choose 30 minutes, 1 hour or 4 hours")
    fix_state.update(until=time.time() + body.minutes * 60, by=user["name"])
    s["fresh_at"] = 0                                    # the next approval needs its own passkey
    vault.audit(user["email"], "remediation-on", f"For {body.minutes} minutes")
    return {"on": True, "until": fix_state["until"]}


@app.post("/api/fix/off")
def fix_turn_off(request: Request):
    sid, s, user = require(request, "admin")
    fix_state.update(until=0)
    vault.audit(user["email"], "remediation-off", "Turned off")
    return {"on": False}


class FixAccount(BaseModel):
    host: str
    user: str = "guardian-fix"
    port: int = 22
    remove: bool = False


@app.post("/api/fix/accounts")
def fix_account(body: FixAccount, request: Request):
    sid, s, user = require(request, "admin", unlocked=True)
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", body.host) or not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", body.user) or not 1 <= body.port <= 65535:
        raise HTTPException(400, "Check the address, user name and port")
    rec = next((r for r in vault.load_records("settings") if r.get("kind") == "fix-accounts"), None) or {"kind": "fix-accounts", "hosts": {}}
    if body.remove:
        rec["hosts"].pop(body.host, None)
    else:
        rec["hosts"][body.host] = {"user": body.user, "port": body.port}
        conn.guardian_ssh_key(vault)
    vault.save_record("fix-accounts", "settings", rec)
    vault.audit(user["email"], "fix-account-" + ("removed" if body.remove else "saved"), body.host)
    return {"hosts": rec["hosts"]}


class FixApply(BaseModel):
    proposal: str


def _run_change(rec, proposal):
    ctx = remediate.Context(vault, STATE, fix_hosts(), rec)
    step = ctx.step
    ctx.step = lambda *a: (step(*a), save_change(rec))     # the page follows each step as it happens
    remediate.execute(ctx, proposal)
    save_change(rec)
    vault.audit(rec["by_email"], "remediation-" + rec["status"], f'{rec["id"]} {rec["title"]}')


@app.post("/api/fix/apply")
def fix_apply(body: FixApply, request: Request):
    sid, s, user = require_fresh(request)
    if not fix_on():
        raise HTTPException(409, "Remediation is off: turn it on first")
    run_id, g = latest_analysed()
    p = next((x for x in remediate.proposals(g, fix_hosts(), (g.get("site") or {}).get("collector_ip")) if x["id"] == body.proposal), None)
    if not p:
        raise HTTPException(404, "That fix is no longer proposed")
    if not p["ready"]:
        raise HTTPException(400, p["blocked"] or "Not ready")
    if any(c["proposal"] == p["id"] and c["status"] in ("running", "done") for c in changes()):
        raise HTTPException(409, "Already applied")
    s["fresh_at"] = 0
    rec = {"id": "CR-%04d" % (len(changes()) + 1), "proposal": p["id"], "recipe": p["recipe"], "title": p["title"],
           "target": p["target"], "finding": p["finding"], "run": run_id, "by": user["name"], "by_email": user["email"],
           "created": time.time(), "status": "approved", "steps": [{"t": time.time(), "step": "approve", "ok": True,
                                                                    "text": f'Approved by {user["name"]} with a passkey'}]}
    save_change(rec)
    vault.audit(user["email"], "remediation-approved", f'{rec["id"]} {p["title"]}')
    threading.Thread(target=_run_change, args=(rec, p), daemon=True).start()
    return rec


@app.post("/api/fix/changes/{cid}/rollback")
def fix_rollback(cid: str, request: Request):
    sid, s, user = require_fresh(request)
    rec = next((c for c in changes() if c["id"] == cid), None)
    if not rec or rec["status"] not in ("done", "needs-attention") or not rec.get("backup"):
        raise HTTPException(400, "Nothing to roll back")
    s["fresh_at"] = 0
    ctx = remediate.Context(vault, STATE, fix_hosts(), rec)
    remediate.rollback(ctx, rec)
    save_change(rec)
    vault.audit(user["email"], "remediation-rollback", f'{cid}: {rec["status"]}')
    return rec


# -- connectors -----------------------------------------------------------------------------------------
# -- code scan: check a public GitHub repository for malicious code -------------------------------------
CODE_DIR = RUNS / "code"
SCAN_ID = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{4}$")
SCAN_TIMEOUT = 20 * 60


class CodeJob:
    proc = None
    scan_id = None


codejob = CodeJob()


def scan_dir(scan_id):
    if not SCAN_ID.match(scan_id or ""):
        raise HTTPException(404, "No such scan")
    d = CODE_DIR / scan_id
    if not (d / "scan.json").exists():
        raise HTTPException(404, "No such scan")
    return d


def read_scan(d):
    try:
        return json.loads((d / "scan.json").read_text())
    except (OSError, ValueError):
        return None


def scan_limits():
    """Runs in the scan process before it starts: caps memory, CPU time and open files."""
    import resource
    for limit, value in ((resource.RLIMIT_AS, 3 * 2**30), (resource.RLIMIT_CPU, SCAN_TIMEOUT), (resource.RLIMIT_NOFILE, 256)):
        try:
            resource.setrlimit(limit, (value, value))
        except (ValueError, OSError):                               # not every limit exists on every OS
            pass


async def run_scan(cmd, env, d):
    try:
        codejob.proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=str(BASE), env=env, stdout=asyncio.subprocess.DEVNULL, stderr=open(d / "scan.log", "wb"),
            start_new_session=True, preexec_fn=scan_limits)
        env.clear()
        try:
            await asyncio.wait_for(codejob.proc.wait(), SCAN_TIMEOUT)
        except asyncio.TimeoutError:
            os.killpg(codejob.proc.pid, signal.SIGKILL)
            await codejob.proc.wait()
    except Exception as e:                                          # noqa: BLE001 - recorded in the scan
        (d / "scan.log").write_text(f"could not run: {e}")
    data = read_scan(d)
    if data and data.get("status") == "running":                    # killed, timed out or crashed
        data.update(status="failed", finished=time.time(),
                    error=data.get("error") or ("Stopped" if codejob.scan_id is None else "The scan stopped unexpectedly or took longer than 20 minutes"))
        (d / "scan.json").write_text(json.dumps(data))
    codejob.proc = codejob.scan_id = None


def scan_row(d):
    data = read_scan(d)
    if not data:
        return None
    counts = {}
    for f in data.get("findings") or []:
        if not f.get("dismissed") and (f.get("ai") or {}).get("verdict") != "false_positive":
            counts[f["sev"]] = counts.get(f["sev"], 0) + 1
    return {"id": data["id"], "repo": data.get("repo"), "sha": (data.get("sha") or "")[:7], "ref": data.get("ref"),
            "by": data.get("by"), "started": data.get("started"), "status": data.get("status"),
            "verdict": (data.get("verdict") or {}).get("word"), "counts": counts, "cost": data.get("cost"), "error": data.get("error")}


@app.get("/api/code")
def code_overview(request: Request):
    sid, s, user = require(request)
    CODE_DIR.mkdir(parents=True, exist_ok=True)
    rows = [r for r in (scan_row(d) for d in sorted(CODE_DIR.iterdir(), reverse=True)[:100] if SCAN_ID.match(d.name)) if r]
    return {"scans": rows, "running": codejob.scan_id, "role": user["role"],
            "ai_ready": sid in vault.holders and bool(api_keys().get("anthropic")),
            "unlocked": sid in vault.holders}


class CodeScanBody(BaseModel):
    url: str
    ref: Optional[str] = None
    ai: bool = True
    deps: bool = True


@app.post("/api/code/scan")
async def code_scan(body: CodeScanBody, request: Request):
    sid, s, user = require(request, "operator")
    from guardian import codescan
    try:
        owner, repo, ref = codescan.parse_url(body.url, body.ref)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if codejob.scan_id:
        raise HTTPException(409, "A code scan is already running")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "PYTHONUNBUFFERED": "1",
           "HOME": str(BASE), **{k: v for k, v in os.environ.items() if k.startswith("GUARDIAN_")}}
    ai = body.ai
    if ai:
        key = api_keys().get("anthropic") if sid in vault.holders else None
        if key:
            env["ANTHROPIC_API_KEY"] = key                          # handed over in memory, never written to disk
            vault.audit(user["email"], "secret-used", "API key for a code scan")
    scan_id = time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(2)
    d = CODE_DIR / scan_id
    d.mkdir(parents=True)
    (d / "scan.json").write_text(json.dumps({                        # placeholder until the scan writes its own
        "id": scan_id, "url": f"https://github.com/{owner}/{repo}", "repo": f"{owner}/{repo}", "ref": ref, "by": user["name"],
        "started": time.time(), "status": "running", "stage": "fetch", "stages": {}, "findings": [], "deps_requested": body.deps}))
    cmd = [PYTHON, "-m", "guardian.codescan", str(d), f"https://github.com/{owner}/{repo}", "--by", user["name"]]
    if ref:
        cmd += ["--ref", ref]
    if not ai:
        cmd.append("--no-ai")
    if not body.deps:
        cmd.append("--no-deps")
    codejob.scan_id = scan_id
    vault.audit(user["email"], "code-scan", f"{owner}/{repo}" + (f" @ {ref}" if ref else ""))
    asyncio.create_task(run_scan(cmd, env, d))
    return {"id": scan_id}


@app.post("/api/code/stop")
async def code_stop(request: Request):
    sid, s, user = require(request, "operator")
    if not codejob.proc:
        raise HTTPException(409, "No code scan is running")
    codejob.scan_id = None
    os.killpg(codejob.proc.pid, signal.SIGKILL)
    vault.audit(user["email"], "code-scan-stopped", "")
    return {"ok": True}


@app.get("/api/code/{scan_id}")
def code_result(scan_id: str, request: Request, download: int = 0):
    require(request)
    d = scan_dir(scan_id)
    if download:
        return FileResponse(d / "scan.json", media_type="application/json",
                            headers={"Content-Disposition": f'attachment; filename="guardian-code-scan-{scan_id}.json"'})
    return read_scan(d) or {}


class Dismiss(BaseModel):
    dismissed: bool


@app.post("/api/code/{scan_id}/findings/{n}")
def code_dismiss(scan_id: str, n: int, body: Dismiss, request: Request):
    sid, s, user = require(request, "operator")
    d = scan_dir(scan_id)
    if codejob.scan_id == scan_id:
        raise HTTPException(409, "Wait for the scan to finish")
    data = read_scan(d)
    f = next((f for f in data.get("findings") or [] if f.get("n") == n), None)
    if not f:
        raise HTTPException(404, "No such finding")
    f["dismissed"] = body.dismissed
    f["dismissed_by"] = user["name"] if body.dismissed else None
    (d / "scan.json").write_text(json.dumps(data))
    vault.audit(user["email"], "code-finding", f"{'Marked' if body.dismissed else 'Unmarked'} as false positive: {data.get('repo')} #{n} {f['title'][:80]}")
    return {"ok": True}


@app.get("/api/connectors")
def connectors_overview(request: Request):
    sid, s, user = require(request, "operator")
    run_id, g = latest_scan()
    store.update_inventory(run_id, g)
    unlocked = sid in vault.holders
    suggestions = conn.suggest(g, store) if unlocked else []
    covered = {h for x in suggestions for h in x["hosts"]} | {h for hs in store.configured_targets().values() for h in hs}
    return {"catalog": conn.CATALOG, "locked": not unlocked,
            "connectors": [store.public(c) for c in store.connectors()] if unlocked else [],
            "suggestions": suggestions, "dismissed": len(store.dismissed), "scan": run_id,
            "devices": len((g or {}).get("assets", {})),
            "uncovered": sum(1 for ip in (g or {}).get("assets", {}) if ip not in covered),
            "can_edit": user["role"] == "admin"}


@app.get("/api/connectors/ssh-key")
def ssh_key(request: Request):
    require(request, "admin", unlocked=True)
    return {"public_key": conn.guardian_ssh_key(vault)}


class ConnectorBody(BaseModel):
    id: Optional[str] = None
    type: str
    name: str = ""
    fields: dict = {}


def merged_fields(body):
    try:
        fields = conn.validate(body.type, body.fields)
    except ValueError as e:
        raise HTTPException(400, str(e))
    existing = store.get(body.id) if body.id else None
    if body.id and (not existing or existing["type"] != body.type):
        raise HTTPException(404, "Unknown connector")
    stored = store.fields_with_secrets(existing) if existing else {}
    for fd in conn.CATALOG[body.type]["fields"]:
        if fd.get("secret") and not fields.get(fd["name"]):
            fields[fd["name"]] = stored.get(fd["name"], "")
    return fields, existing


@app.post("/api/connectors/test")
def connector_test(body: ConnectorBody, request: Request):
    sid, s, user = require(request, "operator", unlocked=True)
    fields, existing = merged_fields(body)
    level, message, details, _ = conn.test(body.type, fields, (existing or {}).get("pin"), STATE, vault)
    if existing:
        vault.audit(user["email"], "secret-used", f'Tested connector "{existing["name"]}"')
    return {"level": level, "message": message, "details": details}


@app.post("/api/connectors")
def connector_save(body: ConnectorBody, request: Request):
    sid, s, user = require(request, "admin", unlocked=True)
    name = body.name.strip()
    if not name or len(name) > 60 or re.search(r"[\r\n<>]", name):
        raise HTTPException(400, "Give the connector a short name (up to 60 characters)")
    fields, existing = merged_fields(body)
    spec = conn.CATALOG[body.type]
    missing = [fd["label"] for fd in spec["fields"] if fd.get("secret") and not fields.get(fd["name"])]
    if missing:
        raise HTTPException(400, f"{missing[0]} is required")
    level, message, details, pin = conn.test(body.type, fields, (existing or {}).get("pin"), STATE, vault)
    secret_names = {fd["name"] for fd in spec["fields"] if fd.get("secret")}
    c = existing or {"id": conn.new_id(), "type": body.type, "created": time.time()}
    c.update(name=name, status=level, message=message, details=details, last_check=time.time(),
             fields={k: v for k, v in fields.items() if k not in secret_names},
             secrets={k: fields[k] for k in secret_names})
    if pin:
        c["pin"] = pin
    store.save_connector(c)
    vault.audit(user["email"], "connector-saved" if existing else "connector-added", f'"{name}" ({spec["label"]})')
    return store.public(c)


@app.post("/api/connectors/{cid}/recheck")
def connector_recheck(cid: str, request: Request):
    sid, s, user = require(request, "operator", unlocked=True)
    c = store.get(cid)
    if not c:
        raise HTTPException(404, "Unknown connector")
    level, message, details, pin = conn.test(c["type"], store.fields_with_secrets(c), c.get("pin"), STATE, vault)
    c.update(status=level, message=message, details=details, last_check=time.time())
    if pin:
        c["pin"] = pin
    store.save_connector(c)
    vault.audit(user["email"], "secret-used", f'Re-checked connector "{c["name"]}"')
    return store.public(c)


@app.post("/api/connectors/{cid}/delete")
def connector_delete(cid: str, request: Request):
    sid, s, user = require(request, "admin", unlocked=True)
    c = store.get(cid)
    if not c:
        raise HTTPException(404, "Unknown connector")
    store.delete(cid)
    vault.audit(user["email"], "connector-removed", f'"{c["name"]}"')
    return {"ok": True}


class SuggestionBody(BaseModel):
    key: str = ""


@app.post("/api/suggestions/dismiss")
def suggestion_dismiss(body: SuggestionBody, request: Request):
    require(request, "admin")
    if not re.match(r"^[a-z_]+:[A-Za-z0-9:._-]{1,100}$", body.key):
        raise HTTPException(400, "Bad suggestion")
    if body.key not in store.dismissed:
        store.set_dismissed(store.dismissed + [body.key])
    return {"ok": True}


@app.post("/api/suggestions/restore")
def suggestion_restore(request: Request):
    require(request, "admin")
    store.set_dismissed([])
    return {"ok": True}


# -- users ---------------------------------------------------------------------------------------------------
@app.get("/api/users")
def users_list(request: Request):
    require(request, "admin")
    _, base, _ = site()
    return {"users": [{k: u[k] for k in ("id", "email", "name", "provider", "role", "status", "created", "last_login",
                                          "passkeys", "passkey_names", "vault")} | {"has_key": bool(vault.user(u["id"])["public_key"])}
                      for u in vault.users()],
            "invites": [{"id": i["token_hash"][:16], "email": i["email"], "role": i["role"], "created": i["created"],
                         "expires": i["expires"]} for i in vault.invites()],
            "providers": {k: auth.PROVIDERS[k]["label"] for k in providers()}, "base": base}


class InviteBody(BaseModel):
    email: str
    role: str


@app.post("/api/users/invite")
def users_invite(body: InviteBody, request: Request):
    sid, s, user = require(request, "admin")
    email = body.email.strip().lower()
    if not EMAIL.match(email) or body.role not in ROLES:
        raise HTTPException(400, "Enter an e-mail address and a role")
    existing = vault.user(email=email)
    if existing and existing["subject"]:
        raise HTTPException(409, "That person already has access")
    token = vault.create_invite(email, body.role, user["email"])
    _, base, _ = site()
    vault.audit(user["email"], "invited", f"{email} as {body.role}")
    return {"link": f"{base}/invite/{token}", "email": email, "role": body.role}


def _guard_last_admin(uid):
    u = vault.user(uid)
    if u and u["role"] == "admin" and vault.has_slot(uid) and vault.admins_with_vault() <= 1:
        raise HTTPException(400, "This is the last admin who can open the vault")


class UserUpdate(BaseModel):
    role: Optional[str] = None
    status: Optional[str] = None


@app.post("/api/users/{uid}")
def users_update(uid: str, body: UserUpdate, request: Request):
    sid, s, me_ = require(request, "admin")
    target = vault.user(uid)
    if not target:
        raise HTTPException(404, "Unknown user")
    if body.role and body.role not in ROLES or body.status and body.status not in ("active", "disabled"):
        raise HTTPException(400, "Bad value")
    if (body.role and body.role != "admin") or body.status == "disabled":
        _guard_last_admin(uid)
    if body.role:
        vault.update_user(uid, role=body.role)
        if body.role not in VAULT_ROLES:
            vault.revoke(uid)
        vault.audit(me_["email"], "role-changed", f"{target['email']}: {target['role']} → {body.role}")
    if body.status:
        vault.update_user(uid, status=body.status)
        if body.status == "disabled":
            for k, v in list(sessions.items()):
                if v.get("uid") == uid:
                    end_session(k)
        vault.audit(me_["email"], "user-" + body.status, target["email"])
    return {"ok": True}


@app.post("/api/users/{uid}/grant")
def users_grant(uid: str, request: Request):
    sid, s, me_ = require(request, "admin", unlocked=True)
    target = vault.user(uid)
    if not target or target["role"] not in VAULT_ROLES:
        raise HTTPException(400, "Only admins and operators can get vault access")
    try:
        vault.grant(uid, me_["email"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    vault.audit(me_["email"], "vault-granted", target["email"])
    return {"ok": True}


@app.post("/api/users/{uid}/revoke")
def users_revoke(uid: str, request: Request):
    sid, s, me_ = require(request, "admin")
    _guard_last_admin(uid)
    vault.revoke(uid)
    vault.audit(me_["email"], "vault-revoked", vault.user(uid)["email"])
    return {"ok": True}


@app.post("/api/users/{uid}/delete")
def users_delete(uid: str, request: Request):
    sid, s, me_ = require(request, "admin")
    if uid == me_["id"]:
        raise HTTPException(400, "You can't remove yourself")
    _guard_last_admin(uid)
    target = vault.user(uid)
    for k, v in list(sessions.items()):
        if v.get("uid") == uid:
            end_session(k)
    vault.delete_user(uid)
    vault.audit(me_["email"], "user-removed", target["email"] if target else uid)
    return {"ok": True}


@app.post("/api/invites/{iid}/revoke")
def invite_revoke(iid: str, request: Request):
    sid, s, me_ = require(request, "admin")
    inv = next((i for i in vault.invites() if i["token_hash"].startswith(iid)), None)
    if not inv:
        raise HTTPException(404, "Unknown invite")
    vault.revoke_invite(inv["token_hash"])
    vault.audit(me_["email"], "invite-revoked", inv["email"])
    return {"ok": True}


@app.post("/api/me/passkeys/{cid}/delete")
def my_passkey_delete(cid: str, request: Request):
    sid, s, user = require(request)
    creds = vault.credentials(user["id"])
    if not any(c["id"] == cid for c in creds):
        raise HTTPException(404, "Unknown passkey")
    if len(creds) <= 1:
        raise HTTPException(400, "Keep at least one passkey")
    vault.delete_credential(cid)
    vault.audit(user["email"], "passkey-removed", "")
    return {"ok": True}


# -- security -------------------------------------------------------------------------------------------
@app.get("/api/security")
def security(request: Request):
    sid, s, user = require(request, "admin")
    rec = vault.get("recovery") or {}
    host, base, _ = site()
    cfg = vault.get("oidc", {})
    return {"unlocked": vault.unlocked, "unlocked_by": vault.unlocked_by, "unlocked_at": vault.unlocked_at,
            "holders": len(vault.holders), "autolock": vault.get("autolock", {"idle": 30, "max": 8}),
            "recovery_created": rec.get("created"), "vault_ready": vault.initialized,
            "records": vault.record_count("connector"), "hostname": host, "base": base,
            "oidc": {k: {"client_id": cfg.get(k, {}).get("client_id", ""), "secret_set": bool(cfg.get(k, {}).get("client_secret")),
                         "redirect": f"{base}/auth/callback/{k}"} for k in auth.PROVIDERS}}


class AutolockBody(BaseModel):
    idle: int
    max: int


@app.post("/api/security/autolock")
def security_autolock(body: AutolockBody, request: Request):
    sid, s, user = require(request, "admin")
    if body.idle not in (5, 15, 30, 60) or body.max not in (1, 4, 8, 12):
        raise HTTPException(400, "Pick one of the listed values")
    vault.put("autolock", {"idle": body.idle, "max": body.max})
    vault.audit(user["email"], "settings-changed", f"Auto-lock: {body.idle} min idle, {body.max} h max")
    return {"ok": True}


@app.post("/api/security/recovery")
def security_recovery(request: Request):
    sid, s, user = require(request, "admin", unlocked=True)
    key = vault.rotate_recovery()
    vault.audit(user["email"], "recovery-replaced", "A new recovery key was created; the old one stopped working")
    return {"recovery_key": key}


class OidcBody(BaseModel):
    provider: str
    client_id: str
    client_secret: Optional[str] = None


@app.post("/api/security/oidc")
def security_oidc(body: OidcBody, request: Request):
    sid, s, user = require(request, "admin")
    if body.provider not in auth.PROVIDERS:
        raise HTTPException(400, "Unknown provider")
    cid = body.client_id.strip()
    if cid and not re.match(r"^[A-Za-z0-9._\-]{8,200}$", cid):
        raise HTTPException(400, "That doesn't look like a client ID")
    cfg = vault.get("oidc", {})
    entry = cfg.get(body.provider, {})
    entry["client_id"] = cid
    if (body.client_secret or "").strip():
        if len(body.client_secret.strip()) > 300 or re.search(r"\s", body.client_secret.strip()):
            raise HTTPException(400, "That doesn't look like a client secret")
        entry["client_secret"] = body.client_secret.strip()
    if not cid:
        entry = {}
    cfg[body.provider] = entry
    vault.put("oidc", cfg)
    vault.audit(user["email"], "settings-changed", f"{auth.PROVIDERS[body.provider]['label']} sign-in " + ("configured" if cid else "removed"))
    return {"ok": True}


@app.get("/api/audit")
def audit_list(request: Request, limit: int = 200):
    require(request, "admin")
    return {"rows": [{k: r[k] for k in ("id", "ts", "actor", "action", "detail")} for r in vault.audit_rows(min(limit, 2000))]}


@app.get("/api/audit/verify")
def audit_verify(request: Request):
    require(request, "admin")
    ok, n, bad = vault.audit_verify()
    if ok:
        vault.anchor_audit()
    return {"ok": ok, "entries": n, "broken_at": bad}


@app.get("/api/audit.csv")
def audit_csv(request: Request):
    require(request, "admin")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["time", "who", "action", "detail", "hash"])
    for r in reversed(vault.audit_rows(100000)):
        w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"])), r["actor"], r["action"], r["detail"], r["hash"]])
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="guardian-audit.csv"'})


if __name__ == "__main__":
    import uvicorn
    ensure_state()
    harden_process()
    code = setup_code()
    if code:
        print(f"First-time setup code: {code}  (also in {SETUP_FILE})", flush=True)
    host = site()[0]
    le_cert, le_key = STATE / "acme" / "certificates" / f"{host}.crt", STATE / "acme" / "certificates" / f"{host}.key"
    cert, key = (le_cert, le_key) if le_cert.exists() and le_key.exists() else (CERT, KEY)
    print(f"Serving https://{host}:{os.environ.get('GUARDIAN_CONSOLE_PORT', '8443')} with {'Let' + chr(39) + 's Encrypt' if cert == le_cert else 'a self-signed'} certificate", flush=True)
    uvicorn.run(app, host=os.environ.get("GUARDIAN_CONSOLE_HOST", "0.0.0.0"),
                port=int(os.environ.get("GUARDIAN_CONSOLE_PORT", "8443")),
                ssl_certfile=str(cert), ssl_keyfile=str(key), server_header=False, log_level="warning")
