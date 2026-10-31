#!/usr/bin/env python3
"""Guardian site collector: enrollment, heartbeat, signed jobs, and the customer's Pause / Disconnect / quiet hours.

Runs at the customer and only ever connects out to the Guardian collector gateway. Every request is signed with the
collector's own Ed25519 key; the gateway's TLS key is pinned from the install command. The customer controls it
locally: pause (stay connected, refuse all work), disconnect (no connection at all until someone connects it again
here) and the scope (set here; the server can't change it). Every action goes into a hash-chained activity log.

  guardian-collector enroll https://SERVER:8444 CODE --pin sha256:... --scope 10.20.0.0/22,10.20.8.0/24
  guardian-collector run
  guardian-collector status | pause [--reason R] | resume | disconnect [--reason R] | connect | log
  guardian-collector quiet "mon-fri 08:00-18:00" | quiet off
  guardian-collector page                     (the status page on the LAN; see --help)
"""
import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import sys
import time
import urllib.parse
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography import x509

VERSION = "1.1.0"
DATA = Path(os.environ.get("GUARDIAN_COLLECTOR_DATA", "/var/lib/guardian-collector"))
SERVICE_USER = "guardian-collector"
HEARTBEAT = 60
MAX_RESPONSE = 1_000_000
TEXT = re.compile(r"^[^\x00-\x1f\x7f]{0,200}$")
CODE = re.compile(r"^[A-Za-z2-9]{4}-[A-Za-z2-9]{4}-[A-Za-z2-9]{4}$")
PIN = re.compile(r"^sha256:[A-Za-z0-9_-]{43}$")


class Refused(Exception):
    """The gateway said no (status code in .status)."""
    def __init__(self, status):
        super().__init__(f"gateway answered {status}")
        self.status = status


# -- local files --------------------------------------------------------------------------------------------------
def _own(path):
    """Files written by an admin with sudo must stay readable by the service user (and nobody else)."""
    if os.geteuid() == 0:
        try:
            import pwd
            pw = pwd.getpwnam(SERVICE_USER)
            os.chown(path, pw.pw_uid, pw.pw_gid)
        except (KeyError, ImportError):
            pass


def write_private(path, data):
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    _own(tmp)
    os.replace(tmp, path)


def load_state():
    try:
        return json.loads((DATA / "state.json").read_text())
    except FileNotFoundError:
        sys.exit("Not enrolled yet: run 'guardian-collector enroll' first.")


def save_state(st):
    write_private(DATA / "state.json", json.dumps(st, indent=1).encode())


def load_key():
    return serialization.load_pem_private_key((DATA / "key.pem").read_bytes(), None)


def activity(kind, detail=""):
    """Append to the activity log; each line carries the hash of the previous one, so removals show."""
    path = DATA / "activity.log"
    prev = "0" * 64
    if path.exists():
        with open(path, "rb") as f:
            f.seek(max(0, path.stat().st_size - 4096))
            lines = f.read().splitlines()
        if lines:
            prev = json.loads(lines[-1])["hash"]
    entry = {"t": int(time.time()), "kind": kind, "detail": str(detail)[:300], "prev": prev}
    entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
    new = not path.exists()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps(entry) + "\n")
    if new:
        _own(path)


def verify_log():
    prev, n = "0" * 64, 0
    path = DATA / "activity.log"
    if not path.exists():
        return True, 0
    for line in path.read_text().splitlines():
        e = json.loads(line)
        h = e.pop("hash")
        if e["prev"] != prev or hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() != h:
            return False, n
        prev, n = h, n + 1
    return True, n


# -- scope (set here, never by the server) ------------------------------------------------------------------------
def parse_scope(text):
    items = [x for x in re.split(r"[\s,]+", text or "") if x]
    if not 1 <= len(items) <= 32:
        raise ValueError("give 1 to 32 networks, e.g. 10.20.0.0/22,10.20.8.0/24")
    out = []
    for c in items:
        n = ipaddress.ip_network(c, strict=True)
        if n.prefixlen < (16 if n.version == 4 else 48):
            raise ValueError(f"{n} is too broad (at most /16)")
        if n.is_loopback or n.is_multicast or n.is_link_local or n.is_unspecified:
            raise ValueError(f"{n} can't be scanned")
        out.append(str(n))
    return sorted(set(out))


def in_scope(st, ip):
    """Used by every job in phase B: a target outside the local scope is refused here, whatever the server asks."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(n) for n in st["scope"])


# -- jobs (phase B): checked here, whatever the server asks ---------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import guardian_jobs as jobs                     # shipped next to this file by install.sh / the Dockerfile
except ImportError:                                  # running from the repository
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from guardian import jobs

NMAP = os.environ.get("GUARDIAN_NMAP", "nmap")
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def quiet_now(st, now=None):
    """Quiet hours set by the customer: jobs are refused while one is on."""
    t = time.localtime(now or time.time())
    hm = t.tm_hour * 60 + t.tm_min
    for w in st.get("quiet") or []:
        a, b = (int(x[:2]) * 60 + int(x[3:]) for x in (w["from"], w["to"]))
        if t.tm_wday in w["days"] and (a <= hm < b if a < b else hm >= a or hm < b):
            return True
    return False


def target_in_scope(st, target):
    try:
        n = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    return any(n.version == ipaddress.ip_network(s).version and n.subnet_of(ipaddress.ip_network(s)) for s in st["scope"])


def _run(cmd, timeout):
    import subprocess
    r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    if r.returncode not in (0, 1) and not r.stdout:
        raise RuntimeError((r.stderr or b"").decode(errors="replace")[:300] or f"exit {r.returncode}")
    return r.stdout


def run_job(job):
    """Fixed command lines only; nothing from the job is passed to a shell."""
    k, p = job["type"], job["params"]
    if k == "discover":
        return _run([NMAP, "-sn", "-n", "-oX", "-", *p["networks"]], 1800)
    if k == "scan":
        out = _run([NMAP, "-Pn", "-n", "-sT", "-sV", "--version-light", "-T4", "--top-ports", "1000", "-oX", "-", *p["hosts"]], 3 * 3600)
        if p["extra_ports"]:
            out += b"\n<!--guardian-split-->\n" + _run([NMAP, "-Pn", "-n", "-sT", "-sV", "--version-light", "-T4", "-p",
                                                        ",".join(map(str, p["extra_ports"])), "-oX", "-", *p["hosts"]], 3600)
        return out
    if k == "probe":
        return _run([NMAP, "-Pn", "-n", "-sU" if p["udp"] else "-sT", "-sV", "--version-light", "-p", ",".join(map(str, p["ports"])),
                     "--script", ",".join(p["scripts"]), "--script-timeout", "60s", "-oX", "-", p["ip"]], 400)
    if k == "http":
        import urllib.request

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw):
                return None
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
        req = urllib.request.Request(p["url"], method=p["method"], headers={"User-Agent": "ai-guardian-assessment/0.1"})
        try:
            r = opener.open(req, timeout=12)
            status, headers, body = r.status, dict(r.headers), r.read(8000)
        except urllib.error.HTTPError as e:
            status, headers, body = e.code, dict(e.headers or {}), e.read(8000)
        except (urllib.error.URLError, OSError) as e:
            return json.dumps({"error": str(getattr(e, "reason", e))[:200]}).encode()
        return json.dumps({"status": status, "headers": headers, "body": body.decode("utf-8", "replace")}).encode()
    if k == "tls":
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            with socket.create_connection((p["ip"], p["port"]), timeout=8) as s, ctx.wrap_socket(s, server_hostname=p["ip"]) as t:
                der, ver, cipher = t.getpeercert(binary_form=True), t.version(), t.cipher()
        except (OSError, ssl.SSLError) as e:
            return json.dumps({"port": p["port"], "error": str(e)[:200]}).encode()
        c = x509.load_der_x509_certificate(der)
        return json.dumps({"port": p["port"], "tls_version": ver, "cipher": cipher[0] if cipher else None,
                           "subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
                           "not_after": c.not_valid_after_utc.isoformat() if hasattr(c, "not_valid_after_utc") else str(c.not_valid_after),
                           "self_signed": c.subject == c.issuer}).encode()
    raise ValueError("unknown job type")


def handle_job(st, key, env):
    """Verify → refuse or run → report. Returns the status sent."""
    try:
        job = jobs.verify(env, st["job_key"], st["collector_id"])
    except (ValueError, KeyError) as e:
        activity("refused", f"invalid job: {e}")
        return "invalid"                               # unsigned or tampered: never answered, never run
    seen = {k: v for k, v in (st.get("seen_jobs") or {}).items() if v > time.time()}
    if job["id"] in seen:
        activity("refused", f"{job['id']} seen before (replay)")
        return "replay"
    seen[job["id"]] = job["expires"]
    st["seen_jobs"] = seen
    save_state(st)
    status, data, error = "done", None, None
    bad = [t for t in jobs.targets(job["type"], job["params"]) if not target_in_scope(st, t)]
    if load_state()["state"] != "connected":
        status, error = "refused", "paused at the customer"
    elif quiet_now(st):
        status, error = "refused", "quiet hours set at the customer"
    elif bad:
        status, error = "refused", f"outside the scope set here: {', '.join(bad[:5])}"
    else:
        try:
            data = jobs.pack(run_job(job))
        except Exception as e:                         # noqa: BLE001 - reported, never raised
            status, error = "failed", f"{type(e).__name__}: {e}"[:300]
    activity("job-" + status, f"{job['id']} {job['type']} {', '.join(jobs.targets(job['type'], job['params']))[:150]}" + (f" ({error})" if error else ""))
    body = {"job": job["id"], "status": status, "error": error, "data": data}
    try:
        call(st, "/c/v1/result", body, key, timeout=120)
    except (Refused, OSError, ssl.SSLError, ValueError) as e:
        buffer_result(body, e)
    return status


def buffer_result(body, err):
    """Phase D: keep results while the gateway can't be reached, and send them later (oldest first, at most 50 / 200 MB)."""
    q = DATA / "outbox"
    q.mkdir(mode=0o700, exist_ok=True)
    files = sorted(q.glob("*.json"))
    while len(files) >= 50 or sum(f.stat().st_size for f in files) > 200 * 2**20:
        files.pop(0).unlink()
    write_private(q / f"{int(time.time() * 1000)}-{body['job']}.json", json.dumps(body).encode())
    activity("buffered", f"{body['job']}: gateway unreachable ({str(err)[:80]})")


def flush_outbox(st, key):
    q = DATA / "outbox"
    for f in sorted(q.glob("*.json")) if q.exists() else []:
        body = json.loads(f.read_text())
        try:
            call(st, "/c/v1/result", body, key, timeout=120)
        except Refused as e:
            if e.status not in (404, 400):             # 404: expired or already answered at Guardian; drop it
                return
        f.unlink()
        activity("sent-buffered", body["job"])


# -- talking to the gateway ---------------------------------------------------------------------------------------
def spki_pin(der):
    cert = x509.load_der_x509_certificate(der)
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "sha256:" + base64.urlsafe_b64encode(hashlib.sha256(spki).digest()).decode().rstrip("=")


def check_url(url):
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or not u.hostname or u.path not in ("", "/") or u.query or u.fragment or u.username:
        raise ValueError("the server must look like https://host:port")
    return f"https://{u.netloc}"


def call(st, path, body, key=None, timeout=20):
    u = urllib.parse.urlsplit(st["url"])
    ctx = ssl.create_default_context()
    if st.get("pin"):                      # trust exactly the pinned key, not the certificate's name or issuer
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, context=ctx, timeout=timeout)
    try:
        conn.connect()
        if st.get("pin") and not secrets.compare_digest(spki_pin(conn.sock.getpeercert(binary_form=True)), st["pin"]):
            raise ssl.SSLError("the gateway's key doesn't match the pin from the install command")
        data = json.dumps(body, separators=(",", ":")).encode()
        headers = {"Content-Type": "application/json", "User-Agent": f"guardian-collector/{VERSION}"}
        if key:
            ts, nonce = str(int(time.time())), secrets.token_urlsafe(24)
            msg = "\n".join(["POST", path, st["collector_id"], ts, nonce, hashlib.sha256(data).hexdigest()]).encode()
            headers.update({"X-GC-Id": st["collector_id"], "X-GC-Time": ts, "X-GC-Nonce": nonce,
                            "X-GC-Sig": base64.urlsafe_b64encode(key.sign(msg)).decode().rstrip("=")})
        conn.request("POST", path, body=data, headers=headers)
        r = conn.getresponse()
        raw = r.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ValueError("response too large")
        if r.status != 200:
            raise Refused(r.status)
        out = json.loads(raw)
        if not isinstance(out, dict):
            raise ValueError("unexpected response")
        return out
    finally:
        conn.close()


def heartbeat(st, key):
    return call(st, "/c/v1/heartbeat", {"state": "paused" if st["state"] == "paused" else "connected",
                                        "reason": st.get("reason") or None, "host": st["host"], "version": VERSION,
                                        "scope": st["scope"]}, key)


# -- commands -----------------------------------------------------------------------------------------------------
def cmd_enroll(a):
    if (DATA / "state.json").exists() and not a.force:
        sys.exit("Already enrolled. Use --force to enroll again (the old enrollment stops working).")
    if not CODE.match(a.code):
        sys.exit("The code looks like XXXX-XXXX-XXXX.")
    if not PIN.match(a.pin):
        sys.exit("The pin looks like sha256:... (from the install command).")
    try:
        url, scope = check_url(a.url), parse_scope(a.scope)
    except ValueError as e:
        sys.exit(str(e))
    host = re.sub(r"[^A-Za-z0-9.-]", "-", a.host or socket.gethostname())[:63].strip("-.") or "collector"
    DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
    _own(DATA)
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    st = {"url": url, "pin": a.pin, "host": host, "scope": scope}
    try:
        r = call(st, "/c/v1/enroll", {"code": a.code.upper(), "pubkey": base64.urlsafe_b64encode(pub).decode().rstrip("="),
                                     "host": host, "version": VERSION, "scope": scope})
    except Refused as e:
        sys.exit({401: "Enrollment refused: the code is wrong, used or expired.", 429: "Too many attempts; try again later."}
                 .get(e.status, f"Enrollment failed ({e.status})."))
    except (OSError, ssl.SSLError, ValueError) as e:
        sys.exit(f"Can't reach the gateway: {e}")
    write_private(DATA / "key.pem", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    st.update(collector_id=r["collector_id"], site=r["site"], job_key=r["job_key"], state="connected", reason=None,
              enrolled=int(time.time()))
    save_state(st)
    activity("enrolled", f"{r['site']['name']} as {r['collector_id']}, scope {', '.join(scope)}")
    print(f"Enrolled for site '{r['site']['name']}' as {r['collector_id']}. Start the service to stay connected.")


def cmd_run(a):
    backoff = 5
    last_beat, last_state = 0, None
    activity("started", f"v{VERSION}")
    while True:
        st = load_state()
        if st["state"] == "disconnected":       # no connection at all until someone runs 'connect' here
            last_state = "disconnected"
            time.sleep(5)
            continue
        key = load_key()
        try:
            if time.time() - last_beat >= HEARTBEAT or (st["state"], st.get("reason")) != last_state:
                heartbeat(st, key)                # a pause / resume / connect reaches Guardian at once
                last_beat, last_state = time.time(), (st["state"], st.get("reason"))
            if st["state"] == "connected":
                flush_outbox(st, key)
                todo = call(st, "/c/v1/jobs", {}, key, timeout=40).get("jobs", [])
                for env in todo[:8] if isinstance(todo, list) else []:
                    handle_job(load_state(), key, env)
            else:
                for _ in range(5):
                    if (load_state()["state"], load_state().get("reason")) != last_state:
                        break
                    time.sleep(1)
            backoff = 5
        except Refused as e:
            if e.status == 401:
                activity("rejected", "the gateway doesn't accept this collector (revoked?)")
                time.sleep(300)
            else:
                time.sleep(backoff)
                backoff = min(backoff * 2, 300)
        except (OSError, ssl.SSLError, ValueError) as e:
            print(f"gateway unreachable: {e}", file=sys.stderr, flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 300)


def _tell(st):
    """Report a pause / resume / connect to Guardian right away (the service would otherwise do it within ~30 s)."""
    try:
        heartbeat(st, load_key())
    except Refused as e:
        print("Guardian no longer accepts this collector (revoked or removed); enroll again with a new code."
              if e.status == 401 else f"Saved here; Guardian answered {e.status}.", file=sys.stderr)
    except (OSError, ssl.SSLError, ValueError) as e:
        print(f"Saved here; Guardian will be told when it's reachable ({e}).", file=sys.stderr)


def _reason(a):
    r = (a.reason or "").strip()
    if not TEXT.match(r):
        sys.exit("The reason is limited to 200 characters on one line.")
    return r or None


def cmd_pause(a):
    st = load_state()
    st.update(state="paused", reason=_reason(a))
    save_state(st)
    activity("paused", st["reason"] or "")
    _tell(st)
    print("Paused: connected, but all work is refused until 'resume'.")


def cmd_resume(a):
    st = load_state()
    if st["state"] == "disconnected":
        sys.exit("Disconnected: use 'connect'.")
    st.update(state="connected", reason=None)
    save_state(st)
    activity("resumed")
    _tell(st)
    print("Resumed.")


def cmd_disconnect(a):
    st = load_state()
    reason = _reason(a)
    if st["state"] != "disconnected":
        try:                                   # tell Guardian why, then close for good
            call(st, "/c/v1/disconnect", {"reason": reason}, load_key())
        except (Refused, OSError, ssl.SSLError, ValueError) as e:
            print(f"Couldn't tell Guardian ({e}); disconnecting anyway.", file=sys.stderr)
    st.update(state="disconnected", reason=reason)
    save_state(st)
    activity("disconnected", reason or "")
    print("Disconnected: nothing is sent or received until 'connect'.")


def cmd_connect(a):
    st = load_state()
    st.update(state="connected", reason=None)
    save_state(st)
    activity("connected")
    _tell(st)
    print("Connected.")


def cmd_status(a):
    st = load_state()
    ok, n = verify_log()
    print(f"Site:       {st['site']['name']} ({st['collector_id']})\nServer:     {st['url']}  pin {st['pin']}\n"
          f"State:      {st['state']}" + (f'  "{st["reason"]}"' if st.get("reason") else "") +
          f"\nScope:      {', '.join(st['scope'])}\nQuiet:      {quiet_text(st.get('quiet'))}\nVersion:    {VERSION}\n"
          f"Activity:   {n} entries, chain {'intact' if ok else 'BROKEN (entries were changed or removed)'}")


def cmd_log(a):
    path = DATA / "activity.log"
    for line in (path.read_text().splitlines()[-a.n:] if path.exists() else []):
        e = json.loads(line)
        print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["t"])), f"{e['kind']:<13}", e["detail"])


# -- quiet hours and the status page (customer side) --------------------------------------------------------------
def parse_quiet(text):
    """'mon-fri 08:00-18:00; sat 00:00-24:00' → [{"days": [0..4], "from": "08:00", "to": "18:00"}, ...]"""
    out = []
    for part in [x.strip().lower() for x in (text or "").split(";") if x.strip()]:
        m = re.fullmatch(r"([a-z]{3})(?:-([a-z]{3}))?\s+(\d\d:\d\d)-(\d\d:\d\d)", part)
        if not m or m.group(1) not in DAYS or (m.group(2) and m.group(2) not in DAYS):
            raise ValueError(f"'{part}' should look like mon-fri 08:00-18:00")
        a, b = DAYS.index(m.group(1)), DAYS.index(m.group(2) or m.group(1))
        frm, to = m.group(3), "00:00" if m.group(4) == "24:00" else m.group(4)
        if not (int(frm[:2]) < 24 and int(frm[3:]) < 60 and int(to[:2]) < 24 and int(to[3:]) < 60):
            raise ValueError(f"'{part}': times are 00:00 to 24:00")
        out.append({"days": list(range(a, b + 1)) if a <= b else list(range(a, 7)) + list(range(0, b + 1)), "from": frm, "to": to})
    return out[:14]


def quiet_text(q):
    day = lambda w: DAYS[w["days"][0]] + ("" if len(w["days"]) == 1 else f"-{DAYS[w['days'][-1]]}")
    return "; ".join(f"{day(w)} {w['from']}-{w['to']}" for w in q or []) or "none"


def cmd_quiet(a):
    st = load_state()
    try:
        st["quiet"] = [] if a.spec.strip().lower() == "off" else parse_quiet(a.spec)
    except ValueError as e:
        sys.exit(str(e))
    save_state(st)
    activity("quiet-hours", quiet_text(st["quiet"]))
    print(f"Quiet hours: {quiet_text(st['quiet'])}. Jobs arriving then are refused and logged.")


PAGE_CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"


def page_password(a):
    import getpass
    pw = getpass.getpass("New status-page password (12+ characters): ")
    if len(pw) < 12 or pw != getpass.getpass("Again: "):
        sys.exit("Passwords must match and have at least 12 characters.")
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=2**26)
    write_private(DATA / "page.json", json.dumps({"salt": salt.hex(), "hash": h.hex()}).encode())
    activity("page-password", "set")
    print("Saved. Start the page with: guardian-collector page --listen 0.0.0.0:8443")


def _page_cert():
    cert, keyf = DATA / "page-cert.pem", DATA / "page-key.pem"
    if not cert.exists():
        import datetime
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        k = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "guardian-collector")])
        now = datetime.datetime.now(datetime.timezone.utc)
        c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650)).sign(k, hashes.SHA256()))
        write_private(keyf, k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        write_private(cert, c.public_bytes(serialization.Encoding.PEM))
    return str(cert), str(keyf)


def cmd_page(a):
    """The customer's status page on the LAN: what the collector is, what it did, and the Pause / Disconnect / quiet controls."""
    import html
    import http.server
    if not (DATA / "page.json").exists():
        sys.exit("Set a password first: guardian-collector page-password")
    host, _, port = a.listen.rpartition(":")
    sessions, fails = {}, {}
    esc = html.escape

    class H(http.server.BaseHTTPRequestHandler):
        server_version, sys_version = "collector", ""

        def log_message(self, *x):
            pass

        def send(self, code, body, ctype="text/html; charset=utf-8", extra=()):
            b = body.encode()
            self.send_response(code)
            for k, v in (("Content-Type", ctype), ("Content-Security-Policy", PAGE_CSP), ("X-Frame-Options", "DENY"),
                         ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"), ("Cache-Control", "no-store"),
                         ("Strict-Transport-Security", "max-age=31536000"), *extra):
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def session(self):
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "gcs" and v in sessions and sessions[v]["t"] > time.time() - 1800:
                    sessions[v]["t"] = time.time()
                    return v, sessions[v]
            return None, None

        def form(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > 4000:
                return {}
            return {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode(errors="replace")).items()}

        def page(self, s, msg=""):
            st = load_state()
            ok, n = verify_log()
            lines = (DATA / "activity.log").read_text().splitlines()[-40:] if (DATA / "activity.log").exists() else []
            rows = "".join(f"<tr><td>{time.strftime('%Y-%m-%d %H:%M', time.localtime(e['t']))}</td><td>{esc(e['kind'])}</td><td>{esc(e['detail'])}</td></tr>"
                           for e in (json.loads(x) for x in reversed(lines)))
            tok = s["csrf"]
            btn = lambda act, label, extra="": (f'<form method="post" action="/{act}"><input type="hidden" name="csrf" value="{tok}">{extra}'
                                                f'<button>{label}</button></form>')
            state = st["state"]
            self.send(200, f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Guardian collector</title><style>body{{font:15px system-ui,sans-serif;max-width:900px;margin:24px auto;padding:0 16px;color:#1c1d18;background:#f6f6f2}}
h1{{font-size:22px}}table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border-bottom:1px solid #ddd;padding:5px;text-align:left;vertical-align:top}}
form{{display:inline-block;margin:4px 8px 4px 0}}button{{padding:7px 12px}}.b{{padding:3px 8px;border-radius:4px;background:#e5e7eb}}
.connected{{background:#d1fae5}}.paused{{background:#fef3c7}}.disconnected{{background:#fee2e2}}input[type=text]{{padding:6px;width:260px}}.m{{color:#b45309}}</style></head><body>
<h1>Guardian collector · {esc(st['site']['name'])}</h1><p class="m">{esc(msg)}</p>
<p>State: <span class="b {state}">{state}</span> {esc(st.get('reason') or '')}</p>
<table><tr><th>Server</th><td>{esc(st['url'])}</td></tr><tr><th>Collector</th><td>{esc(st['collector_id'])} · v{VERSION}</td></tr>
<tr><th>Scope (set here only)</th><td>{esc(', '.join(st['scope']))}</td></tr><tr><th>Quiet hours</th><td>{esc(quiet_text(st.get('quiet')))}</td></tr>
<tr><th>Activity log</th><td>{n} entries, chain {'intact' if ok else 'BROKEN'}</td></tr></table>
<h2>Controls</h2>
{btn('resume', 'Resume') if state == 'paused' else btn('pause', 'Pause (stay connected, refuse work)', '<input type="text" name="reason" maxlength="200" placeholder="reason (optional)"> ') if state == 'connected' else ''}
{btn('connect', 'Connect') if state == 'disconnected' else btn('disconnect', 'Disconnect (no connection at all)', '<input type="text" name="reason" maxlength="200" placeholder="reason (optional)"> ')}
{btn('quiet', 'Save quiet hours', f'<input type="text" name="spec" maxlength="200" value="{esc(quiet_text(st.get("quiet")) if st.get("quiet") else "")}" placeholder="mon-fri 08:00-18:00 (empty = none)"> ')}
{btn('logout', 'Sign out')}
<h2>Recent activity</h2><table><tr><th>When</th><th>What</th><th>Detail</th></tr>{rows}</table></body></html>""")

        def do_GET(self):
            sid, s = self.session()
            if not s:
                return self.send(200, f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Guardian collector</title></head><body style="font:15px system-ui;max-width:420px;margin:15vh auto">
<h1>Guardian collector</h1><form method="post" action="/login"><p><label>Password <input type="password" name="password" autocomplete="current-password" autofocus></label></p><button>Sign in</button></form></body></html>""")
            self.page(s)

        def do_POST(self):
            ip = self.client_address[0]
            f = self.form()
            if self.path == "/login":
                fails[ip] = [t for t in fails.get(ip, []) if t > time.time() - 900]
                if len(fails[ip]) >= 5:
                    return self.send(429, "Too many attempts; wait 15 minutes.", "text/plain")
                cfg = json.loads((DATA / "page.json").read_text())
                h = hashlib.scrypt((f.get("password") or "").encode(), salt=bytes.fromhex(cfg["salt"]), n=2**15, r=8, p=1, maxmem=2**26)
                if not secrets.compare_digest(h.hex(), cfg["hash"]):
                    fails[ip].append(time.time())
                    activity("page-login-failed", ip)
                    return self.send(401, "Wrong password.", "text/plain")
                sid = secrets.token_urlsafe(32)
                sessions[sid] = {"t": time.time(), "csrf": secrets.token_urlsafe(24)}
                activity("page-login", ip)
                return self.send(303, "", extra=(("Location", "/"), ("Set-Cookie", f"gcs={sid}; Path=/; Secure; HttpOnly; SameSite=Strict")))
            sid, s = self.session()
            if not s or not secrets.compare_digest(f.get("csrf", ""), s["csrf"]):
                return self.send(403, "Sign in again.", "text/plain")
            st, reason = load_state(), (f.get("reason") or "").strip()[:200] or None
            msg = ""
            if reason and not TEXT.match(reason):
                reason = None
            if self.path == "/pause" and st["state"] == "connected":
                st.update(state="paused", reason=reason); save_state(st); activity("paused", (reason or "") + " (status page)"); _tell(st)
            elif self.path == "/resume" and st["state"] == "paused":
                st.update(state="connected", reason=None); save_state(st); activity("resumed", "status page"); _tell(st)
            elif self.path == "/disconnect" and st["state"] != "disconnected":
                try:
                    call(st, "/c/v1/disconnect", {"reason": reason}, load_key())
                except (Refused, OSError, ssl.SSLError, ValueError):
                    pass
                st.update(state="disconnected", reason=reason); save_state(st); activity("disconnected", (reason or "") + " (status page)")
            elif self.path == "/connect" and st["state"] == "disconnected":
                st.update(state="connected", reason=None); save_state(st); activity("connected", "status page"); _tell(st)
            elif self.path == "/quiet":
                try:
                    st["quiet"] = parse_quiet(f.get("spec") or "")
                    save_state(st); activity("quiet-hours", quiet_text(st["quiet"]) + " (status page)")
                except ValueError as e:
                    msg = str(e)
            elif self.path == "/logout":
                sessions.pop(sid, None)
                return self.send(303, "", extra=(("Location", "/"), ("Set-Cookie", "gcs=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict")))
            self.page(s, msg)

    srv = http.server.ThreadingHTTPServer((host or "0.0.0.0", int(port or 8443)), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(*_page_cert())
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    activity("page-started", a.listen)
    print(f"Status page on https://{a.listen} (self-signed certificate)")
    srv.serve_forever()


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(prog="guardian-collector", description="Guardian site collector")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enroll", help="enroll with a one-time code from Guardian")
    e.add_argument("url"), e.add_argument("code")
    e.add_argument("--pin", required=True), e.add_argument("--scope", required=True)
    e.add_argument("--host"), e.add_argument("--force", action="store_true")
    sub.add_parser("run", help="stay connected (the service runs this)")
    sub.add_parser("status")
    for name in ("pause", "disconnect"):
        sub.add_parser(name).add_argument("--reason")
    sub.add_parser("resume"), sub.add_parser("connect")
    sub.add_parser("log").add_argument("-n", type=int, default=50)
    sub.add_parser("quiet", help='quiet hours: "mon-fri 08:00-18:00; sat 00:00-24:00" or "off"').add_argument("spec")
    sub.add_parser("page-password", help="set the status page password")
    sub.add_parser("page", help="serve the status page on the LAN").add_argument("--listen", default="0.0.0.0:8443")
    a = p.parse_args()
    {"enroll": cmd_enroll, "run": cmd_run, "status": cmd_status, "pause": cmd_pause, "resume": cmd_resume,
     "disconnect": cmd_disconnect, "connect": cmd_connect, "log": cmd_log, "quiet": cmd_quiet, "page-password": page_password,
     "page": cmd_page}[a.cmd](a)


if __name__ == "__main__":
    main()
