#!/usr/bin/env python3
"""AI IT Guardian - web console.

Starts and stops runs of run.py, follows their log live, and shows the reports.
Serves HTTPS on port 8443 (GUARDIAN_CONSOLE_PORT). Sign-in is off unless .env has
GUARDIAN_CONSOLE_AUTH=on; it then uses the access code in console/access-code, created on
first start. Read it with:  cat /opt/ai-guardian/console/access-code
"""
import asyncio
import collections
import hmac
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

from guardian import connectors as conn

BASE = Path(__file__).resolve().parent
RUNS = BASE / "runs"
ENV = BASE / ".env"
WEB = BASE / "guardian" / "web"
STATE = BASE / "console"
CODE_FILE = STATE / "access-code"
CERT, KEY = STATE / "cert.pem", STATE / "key.pem"
PYTHON = str(BASE / "venv" / "bin" / "python") if (BASE / "venv" / "bin" / "python").exists() else sys.executable

RUN_ID = re.compile(r"^\d{8}-\d{6}$")
API_KEY = re.compile(r"^[A-Za-z0-9_\-]{20,200}$")
MODELS = {"claude-opus-5-5": "Opus 5.5 (default)", "claude-fable-5-1": "Fable 5.1 (stronger, ~2.5x cost)"}
EFFORTS = ("low", "medium", "high")
SESSION_HOURS = 12
MAX_FAILS, FAIL_WINDOW = 5, 900

MODES = {
    "collect": {"label": "Scan only", "args": ["--collect-only"], "steps": ["Scanning the network"]},
    "full": {"label": "Scan + AI assessment", "args": [],
             "steps": ["Scanning the network", "Identifying devices", "AI specialists", "Writing the report"]},
    "resume": {"label": "Re-run AI on a scan", "args": ["--resume"],
               "steps": ["Identifying devices", "AI specialists", "Writing the report"]},
    "report": {"label": "Rebuild report", "args": ["--report"], "steps": ["Rebuilding the report"]},
}
STEP_OF_AGENT = {"collector": "Scanning the network", "discovery": "Identifying devices", "report": "Writing the report"}


# -- first-start setup: access code and TLS certificate ------------------------
def ensure_state():
    STATE.mkdir(mode=0o700, exist_ok=True)
    if not CODE_FILE.exists():
        CODE_FILE.write_text(secrets.token_urlsafe(18) + "\n")
        CODE_FILE.chmod(0o600)
    if not (CERT.exists() and KEY.exists()):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-nodes", "-days", "825", "-subj", "/CN=ai-guardian console",
             "-keyout", str(KEY), "-out", str(CERT)],
            check=True, capture_output=True)
        KEY.chmod(0o600)


def access_code():
    if not CODE_FILE.exists():
        ensure_state()
    return CODE_FILE.read_text().strip()


# -- sessions and sign-in throttling -------------------------------------------
sessions = {}                                 # session id -> expiry time
fails = collections.defaultdict(list)          # client ip -> failure times


def auth_on():
    return read_env().get("GUARDIAN_CONSOLE_AUTH", "off").lower() in ("on", "1", "true", "yes")


def valid_session(request):
    if not auth_on():
        return True
    sid = request.cookies.get("gsid")
    exp = sessions.get(sid) if sid else None
    if exp and exp > time.time():
        return True
    sessions.pop(sid, None)
    return False


# -- .env handling ---------------------------------------------------------------
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


def public_config():
    env = read_env()
    return {
        "model": env.get("GUARDIAN_MODEL") or "claude-opus-5-5",
        "effort": env.get("GUARDIAN_EFFORT") or "medium",
        "anthropic_key_set": bool(env.get("ANTHROPIC_API_KEY")),
        "nvd_key_set": bool(env.get("NVD_API_KEY")),
        "models": MODELS,
        "efforts": EFFORTS,
    }


# -- the one job that can run at a time ------------------------------------------
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
        self.lines = collections.deque(maxlen=3000)
        self.seq = 0                           # number of lines ever written, for incremental reads

    @property
    def running(self):
        return self.proc is not None and self.proc.returncode is None

    def add(self, text):
        self.seq += 1
        self.lines.append((self.seq, time.strftime("%H:%M:%S"), text))
        m = re.match(r"^\[(\w+)\]", text)
        if m and m.group(1) != "console" and self.mode in ("full", "resume"):
            self.step = STEP_OF_AGENT.get(m.group(1), "AI specialists")
        if self.mode in ("full", "collect") and not self.run_id:
            m = re.search(r"runs/(\d{8}-\d{6})", text)
            if m:
                self.run_id = m.group(1)

    def status(self, since=0):
        steps = MODES[self.mode]["steps"] if self.mode else []
        return {
            "running": self.running,
            "mode": self.mode,
            "label": MODES[self.mode]["label"] if self.mode else None,
            "run_id": self.run_id,
            "started": self.started,
            "ended": self.ended,
            "exit_code": self.exit_code,
            "stopped": self.stopped,
            "steps": steps,
            "step": steps.index(self.step) + 1 if self.step in steps else (1 if steps else 0),
            "seq": self.seq,
            "lines": [{"n": n, "t": t, "text": s} for n, t, s in self.lines if n > since],
        }


job = Job()


async def run_job(cmd):
    try:
        job.proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=str(BASE), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, "PYTHONUNBUFFERED": "1"}, start_new_session=True)
        async for raw in job.proc.stdout:
            job.add(raw.decode("utf-8", "replace").rstrip("\n"))
        job.exit_code = await job.proc.wait()
    except Exception as e:                                      # noqa: BLE001 - shown to the user
        job.add(f"[console] could not run: {e}")
        job.exit_code = -1
    job.ended = time.time()
    job.add("[console] stopped by user" if job.stopped else f"[console] finished, exit code {job.exit_code}")


# -- run listing -------------------------------------------------------------------
def run_summary(d):
    info = {"id": d.name, "has_graph": (d / "graph.json").exists(), "has_report": (d / "report.html").exists(),
            "devices": None, "score": None, "grade": None, "counts": {}, "analysed": False}
    if info["has_graph"]:
        try:
            g = json.loads((d / "graph.json").read_text())
            info["devices"] = len(g.get("assets") or {})
            s = g.get("summary") or {}
            info["score"], info["grade"] = s.get("score"), s.get("grade")
            info["analysed"] = bool(s)
            for f in g.get("findings") or []:
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


# -- app ---------------------------------------------------------------------------------
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

PAGE_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "frame-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
REPORT_CSP = ("sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; "
              "style-src 'unsafe-inline'; img-src data:")
OPEN_PATHS = {"/", "/console.css", "/console.js", "/settings", "/settings.js", "/api/login", "/api/session"}


@app.middleware("http")
async def guard(request: Request, call_next):
    path = request.url.path
    if path not in OPEN_PATHS and not valid_session(request):
        return JSONResponse({"detail": "Sign in first"}, status_code=401)
    if request.method == "POST":
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
    if resp.headers.get("X-Frame-Options") == "":
        del resp.headers["X-Frame-Options"]
    else:
        resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/")
def page():
    return FileResponse(WEB / "console.html", media_type="text/html")


@app.get("/console.css")
def css():
    return FileResponse(WEB / "console.css", media_type="text/css")


@app.get("/console.js")
def js():
    return FileResponse(WEB / "console.js", media_type="text/javascript")


class Login(BaseModel):
    code: str


@app.post("/api/login")
def login(body: Login, request: Request):
    ip = request.client.host if request.client else "?"
    now = time.time()
    fails[ip] = [t for t in fails[ip] if now - t < FAIL_WINDOW]
    if len(fails[ip]) >= MAX_FAILS:
        raise HTTPException(429, "Too many attempts. Try again in 15 minutes.")
    if not hmac.compare_digest(body.code.strip().encode(), access_code().encode()):
        fails[ip].append(now)
        time.sleep(1)
        raise HTTPException(401, "Wrong access code")
    fails.pop(ip, None)
    sid = secrets.token_urlsafe(32)
    sessions[sid] = now + SESSION_HOURS * 3600
    resp = JSONResponse({"ok": True})
    resp.set_cookie("gsid", sid, max_age=SESSION_HOURS * 3600, httponly=True, secure=True, samesite="strict")
    return resp


@app.get("/api/session")
def session(request: Request):
    return {"signed_in": valid_session(request), "auth": auth_on()}


@app.post("/api/logout")
def logout(request: Request):
    sessions.pop(request.cookies.get("gsid"), None)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("gsid")
    return resp


@app.get("/api/overview")
def overview():
    RUNS.mkdir(exist_ok=True)
    runs = [run_summary(d) for d in sorted(RUNS.iterdir(), reverse=True) if d.is_dir() and RUN_ID.match(d.name)]
    return {"runs": runs, "config": public_config(),
            "job": job.status(since=job.seq)}


@app.get("/api/runs/{run_id}/report")
def report(run_id: str):
    path = run_dir(run_id) / "report.html"
    if not path.exists():
        raise HTTPException(404, "No report for this run")
    # Served as a sandboxed, unique origin: its scripts can't reach the console API.
    # Chrome gives a CSP-sandboxed page an opaque origin, so frame-ancestors 'self' / SAMEORIGIN would block
    # the console's own frame; X-Frame-Options is dropped for this response only.
    return FileResponse(path, media_type="text/html",
                        headers={"Content-Security-Policy": REPORT_CSP, "X-Frame-Options": ""})


@app.get("/api/runs/{run_id}/graph")
def graph(run_id: str):
    path = run_dir(run_id) / "graph.json"
    if not path.exists():
        raise HTTPException(404, "No data for this run")
    return FileResponse(path, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="graph-{run_id}.json"'})


class Start(BaseModel):
    mode: str
    run_id: Optional[str] = None


@app.post("/api/job/start")
async def start(body: Start):
    if job.running:
        raise HTTPException(409, "A run is already in progress")
    if body.mode not in MODES:
        raise HTTPException(400, "Unknown mode")
    cmd = [PYTHON, str(BASE / "run.py"), *MODES[body.mode]["args"]]
    target = None
    if body.mode in ("resume", "report"):
        d = run_dir(body.run_id)
        if not (d / "graph.json").exists():
            raise HTTPException(400, "That run has no scan data")
        cmd.append(str(d))
        target = d.name
    if body.mode in ("full", "resume") and not read_env().get("ANTHROPIC_API_KEY"):
        raise HTTPException(400, "Add your Anthropic API key in Settings first")
    job.__init__()
    job.mode, job.run_id, job.started = body.mode, target, time.time()
    job.step = MODES[body.mode]["steps"][0]
    job.add(f"[console] {MODES[body.mode]['label']} started")
    asyncio.create_task(run_job(cmd))
    return job.status()


@app.post("/api/job/stop")
async def stop():
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
    return {"ok": True}


@app.get("/api/job")
def job_status(since: int = 0):
    return job.status(since=since)


class Settings(BaseModel):
    model: str
    effort: str
    anthropic_key: Optional[str] = None
    nvd_key: Optional[str] = None


@app.post("/api/settings")
def save_settings(body: Settings):
    if body.model not in MODELS or body.effort not in EFFORTS:
        raise HTTPException(400, "Unknown model or effort")
    updates = {"GUARDIAN_MODEL": body.model, "GUARDIAN_EFFORT": body.effort}
    for name, value in (("ANTHROPIC_API_KEY", body.anthropic_key), ("NVD_API_KEY", body.nvd_key)):
        value = (value or "").strip()
        if value:
            if not API_KEY.match(value):
                raise HTTPException(400, f"{name} doesn't look like a valid key")
            updates[name] = value
    write_env(updates)
    return public_config()


# -- settings page: connectors and access --------------------------------------------------
_store = None
store_lock = threading.Lock()


def get_store():
    global _store
    if _store is None:
        STATE.mkdir(mode=0o700, exist_ok=True)
        _store = conn.Store(STATE)
    return _store


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


@app.get("/settings")
def settings_page():
    return FileResponse(WEB / "settings.html", media_type="text/html")


@app.get("/settings.js")
def settings_js():
    return FileResponse(WEB / "settings.js", media_type="text/javascript")


@app.get("/api/connectors")
def connectors_overview():
    s = get_store()
    run_id, g = latest_scan()
    with store_lock:
        s.update_inventory(run_id, g)
        suggestions = conn.suggest(g, s)
    covered = {h for x in suggestions for h in x["hosts"]} | {h for hs in s.configured_targets().values() for h in hs}
    return {
        "catalog": conn.CATALOG,
        "connectors": [s.public(c) for c in s.data["connectors"]],
        "suggestions": suggestions,
        "dismissed": len(s.data["dismissed"]),
        "scan": run_id,
        "devices": len((g or {}).get("assets", {})),
        "uncovered": sum(1 for ip in (g or {}).get("assets", {}) if ip not in covered),
    }


@app.get("/api/connectors/ssh-key")
def ssh_key():
    _, pub = conn.guardian_ssh_key(get_store().dir)
    return {"public_key": pub}


class ConnectorBody(BaseModel):
    id: Optional[str] = None
    type: str
    name: str = ""
    fields: dict = {}


def merged_fields(body):
    """Validated fields, with blank secret fields filled from the stored connector."""
    try:
        fields = conn.validate(body.type, body.fields)
    except ValueError as e:
        raise HTTPException(400, str(e))
    existing = get_store().get(body.id) if body.id else None
    if body.id and (not existing or existing["type"] != body.type):
        raise HTTPException(404, "Unknown connector")
    stored = get_store().fields_with_secrets(existing) if existing else {}
    for fd in conn.CATALOG[body.type]["fields"]:
        if fd.get("secret") and not fields.get(fd["name"]):
            fields[fd["name"]] = stored.get(fd["name"], "")
    return fields, existing


@app.post("/api/connectors/test")
def connector_test(body: ConnectorBody):
    fields, existing = merged_fields(body)
    level, message, details, _ = conn.test(body.type, fields, (existing or {}).get("pin"), get_store().dir)
    return {"level": level, "message": message, "details": details}


@app.post("/api/connectors")
def connector_save(body: ConnectorBody):
    name = body.name.strip()
    if not name or len(name) > 60 or re.search(r"[\r\n<>]", name):
        raise HTTPException(400, "Give the connector a short name (up to 60 characters)")
    fields, existing = merged_fields(body)
    spec = conn.CATALOG[body.type]
    missing = [fd["label"] for fd in spec["fields"] if fd.get("secret") and not fields.get(fd["name"])]
    if missing:
        raise HTTPException(400, f"{missing[0]} is required")
    s = get_store()
    level, message, details, pin = conn.test(body.type, fields, (existing or {}).get("pin"), s.dir)
    with store_lock:
        c = existing or {"id": conn.new_id(), "type": body.type, "created": time.time()}
        c.update(name=name, status=level, message=message, details=details, last_check=time.time(),
                 fields={k: v for k, v in fields.items() if not any(fd["name"] == k and fd.get("secret") for fd in spec["fields"])},
                 secrets={fd["name"]: s.encrypt(fields[fd["name"]]) for fd in spec["fields"] if fd.get("secret")})
        if pin:
            c["pin"] = pin
        if not existing:
            s.data["connectors"].append(c)
        s.save()
    return s.public(c)


@app.post("/api/connectors/{cid}/recheck")
def connector_recheck(cid: str):
    s = get_store()
    c = s.get(cid)
    if not c:
        raise HTTPException(404, "Unknown connector")
    level, message, details, pin = conn.test(c["type"], s.fields_with_secrets(c), c.get("pin"), s.dir)
    with store_lock:
        c.update(status=level, message=message, details=details, last_check=time.time())
        if pin:
            c["pin"] = pin
        s.save()
    return s.public(c)


@app.post("/api/connectors/{cid}/delete")
def connector_delete(cid: str):
    s = get_store()
    with store_lock:
        before = len(s.data["connectors"])
        s.data["connectors"] = [c for c in s.data["connectors"] if c["id"] != cid]
        if len(s.data["connectors"]) == before:
            raise HTTPException(404, "Unknown connector")
        s.save()
    return {"ok": True}


class SuggestionBody(BaseModel):
    key: str = ""


@app.post("/api/suggestions/dismiss")
def suggestion_dismiss(body: SuggestionBody):
    if not re.match(r"^[a-z_]+:[A-Za-z0-9:._-]{1,100}$", body.key):
        raise HTTPException(400, "Bad suggestion")
    s = get_store()
    with store_lock:
        if body.key not in s.data["dismissed"]:
            s.data["dismissed"].append(body.key)
        s.save()
    return {"ok": True}


@app.post("/api/suggestions/restore")
def suggestion_restore():
    s = get_store()
    with store_lock:
        s.data["dismissed"] = []
        s.save()
    return {"ok": True}


@app.get("/api/access")
def access_get():
    return {"auth": auth_on()}


class AccessBody(BaseModel):
    auth: bool


@app.post("/api/access")
def access_set(body: AccessBody, request: Request):
    write_env({"GUARDIAN_CONSOLE_AUTH": "on" if body.auth else "off"})
    if not body.auth:
        return {"auth": False}
    # Sign the person who switched it on in, and show the code once so they can use it elsewhere.
    sid = secrets.token_urlsafe(32)
    sessions[sid] = time.time() + SESSION_HOURS * 3600
    resp = JSONResponse({"auth": True, "code": access_code()})
    resp.set_cookie("gsid", sid, max_age=SESSION_HOURS * 3600, httponly=True, secure=True, samesite="strict")
    return resp


if __name__ == "__main__":
    import uvicorn
    ensure_state()
    uvicorn.run(app, host=os.environ.get("GUARDIAN_CONSOLE_HOST", "0.0.0.0"),
                port=int(os.environ.get("GUARDIAN_CONSOLE_PORT", "8443")),
                ssl_certfile=str(CERT), ssl_keyfile=str(KEY), server_header=False, log_level="warning")
