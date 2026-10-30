#!/usr/bin/env python3
"""Guardian site collector (phase A): enrollment, heartbeat and the customer's Pause / Disconnect controls.

Runs at the customer and only ever connects out to the Guardian collector gateway. Every request is signed with the
collector's own Ed25519 key; the gateway's TLS key is pinned from the install command. The customer controls it
locally: pause (stay connected, refuse all work), disconnect (no connection at all until someone connects it again
here) and the scope (set here; the server can't change it). Every action goes into a hash-chained activity log.

  guardian-collector enroll https://SERVER:8444 CODE --pin sha256:... --scope 10.20.0.0/22,10.20.8.0/24
  guardian-collector run
  guardian-collector status | pause [--reason R] | resume | disconnect [--reason R] | connect | log
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

VERSION = "1.0.0"
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
                jobs = call(st, "/c/v1/jobs", {}, key, timeout=40).get("jobs", [])
                for j in jobs if isinstance(jobs, list) else []:
                    activity("refused", f"job type not supported in v{VERSION}")
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
          f"\nScope:      {', '.join(st['scope'])}\nVersion:    {VERSION}\n"
          f"Activity:   {n} entries, chain {'intact' if ok else 'BROKEN (entries were changed or removed)'}")


def cmd_log(a):
    path = DATA / "activity.log"
    for line in (path.read_text().splitlines()[-a.n:] if path.exists() else []):
        e = json.loads(line)
        print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["t"])), f"{e['kind']:<13}", e["detail"])


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
    a = p.parse_args()
    {"enroll": cmd_enroll, "run": cmd_run, "status": cmd_status, "pause": cmd_pause, "resume": cmd_resume,
     "disconnect": cmd_disconnect, "connect": cmd_connect, "log": cmd_log}[a.cmd](a)


if __name__ == "__main__":
    main()
