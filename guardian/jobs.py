"""Collector jobs (phase B): signed by the console, queued in the site database, relayed by the gateway, checked and
run by the collector at the customer.

The console signs every job with its Ed25519 job key; the gateway has only the database and can't sign, so a
compromised gateway can't create work. A job carries its collector, type, parameters and an expiry. The collector
checks the signature, the expiry, that it hasn't seen the job before, that the type and parameters are on its own
fixed list and that every target is inside the scope set at the customer.
"""
import base64
import gzip
import ipaddress
import json
import re
import secrets
import time
from pathlib import Path

TYPES = ("discover", "scan", "probe", "http", "tls")
SCRIPTS = {"ssl-enum-ciphers", "ssl-cert", "http-headers", "http-methods", "http-title", "http-robots.txt", "http-server-header",
           "ssh2-enum-algos", "ssh-auth-methods", "ssh-hostkey", "smb-protocols", "smb2-security-mode", "rdp-enum-encryption",
           "ntp-info", "dns-recursion", "upnp-info", "snmp-info", "ftp-anon", "smtp-commands", "mysql-info", "ms-sql-info",
           "vnc-info", "sip-methods", "mqtt-subscribe", "banner", "rtsp-methods"}
TTL = {"discover": 3600, "scan": 3 * 3600, "probe": 900, "http": 600, "tls": 600}
JOB_ID = re.compile(r"^j_[0-9a-f]{16}$")
MAX_RESULT = 6 * 2**20                    # compressed bytes


def b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _key(key_path):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_private_key(Path(key_path).read_bytes(), None)


def _ip(x):
    return str(ipaddress.ip_address(x))


def check_params(kind, p):
    """Shape of every job type. Used by the console before signing and by the collector before running."""
    if kind not in TYPES or not isinstance(p, dict):
        raise ValueError("unknown job type")
    if kind == "discover":
        nets = p.get("networks")
        if not isinstance(nets, list) or not 1 <= len(nets) <= 32:
            raise ValueError("networks")
        return {"networks": [str(ipaddress.ip_network(n, strict=False)) for n in nets]}
    if kind == "scan":
        hosts = p.get("hosts")
        if not isinstance(hosts, list) or not 1 <= len(hosts) <= 256:
            raise ValueError("hosts")
        extra = p.get("extra_ports") or []
        if not isinstance(extra, list) or len(extra) > 64 or any(not isinstance(x, int) or not 1 <= x <= 65535 for x in extra):
            raise ValueError("extra_ports")
        return {"hosts": [_ip(h) for h in hosts], "extra_ports": extra, "udp": bool(p.get("udp"))}
    if kind == "probe":
        ports = p.get("ports")
        scripts = p.get("scripts")
        if not isinstance(ports, list) or not 1 <= len(ports) <= 32 or any(not isinstance(x, int) or not 1 <= x <= 65535 for x in ports):
            raise ValueError("ports")
        if not isinstance(scripts, list) or not 1 <= len(scripts) <= 8 or any(s not in SCRIPTS for s in scripts):
            raise ValueError("scripts")
        return {"ip": _ip(p.get("ip")), "ports": ports, "scripts": scripts, "udp": bool(p.get("udp"))}
    if kind == "http":
        url = str(p.get("url") or "")
        m = re.match(r"^(https?)://([0-9.]+|\[[0-9a-fA-F:]+\])(?::(\d{1,5}))?(/[^\s]{0,500})?$", url)
        if not m:
            raise ValueError("url (http(s)://IP[:port]/path only)")
        if p.get("method", "GET") not in ("GET", "HEAD"):
            raise ValueError("method")
        return {"url": url, "method": p.get("method", "GET")}
    if kind == "tls":
        port = p.get("port")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("port")
        return {"ip": _ip(p.get("ip")), "port": port}


def targets(kind, p):
    """Every address a job touches, for the collector's scope check."""
    if kind == "discover":
        return p["networks"]
    if kind == "scan":
        return p["hosts"]
    if kind == "http":
        m = re.match(r"^https?://(?:\[([0-9a-fA-F:]+)\]|([0-9.]+))", p["url"])
        return [m.group(1) or m.group(2)]
    return [p["ip"]]


def sign(key_path, collector_id, kind, params, ttl=None):
    """A signed job envelope: {"payload": base64(JSON), "sig": base64(Ed25519 signature over those exact bytes)}."""
    params = check_params(kind, params)
    now = int(time.time())
    job = {"v": 1, "id": "j_" + secrets.token_hex(8), "collector": collector_id, "type": kind, "params": params,
           "issued": now, "expires": now + (ttl or TTL[kind])}
    raw = json.dumps(job, separators=(",", ":"), sort_keys=True).encode()
    return job, {"payload": b64(raw), "sig": b64(_key(key_path).sign(raw))}


def verify(envelope, pubkey_b64, collector_id, now=None):
    """Collector side: returns the job dict, or raises ValueError. The signature is checked before anything is parsed."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "sig"}:
        raise ValueError("bad envelope")
    raw, sig = unb64(envelope["payload"]), unb64(envelope["sig"])
    if len(raw) > 20000:
        raise ValueError("job too large")
    try:
        Ed25519PublicKey.from_public_bytes(unb64(pubkey_b64)).verify(sig, raw)
    except InvalidSignature:
        raise ValueError("bad signature")
    job = json.loads(raw)
    now = now or time.time()
    if job.get("v") != 1 or not JOB_ID.match(str(job.get("id"))) or job.get("collector") != collector_id:
        raise ValueError("not for this collector")
    if not job.get("issued", 0) - 300 <= now <= job.get("expires", 0):
        raise ValueError("expired")
    job["params"] = check_params(job.get("type"), job.get("params"))
    return job


def pack(data: bytes):
    z = gzip.compress(data, 6)
    if len(z) > MAX_RESULT:
        raise ValueError("result too large")
    return b64(z)


def unpack(s):
    return gzip.decompress(unb64(s))


def submit(store, key_path, site_id, collector_id, kind, params, by, run=None):
    job, env = sign(key_path, collector_id, kind, params)
    store.add_job(job["id"], collector_id, site_id, kind, json.dumps(env), job["expires"], by, run)
    return job["id"]


def wait(store, job_id, timeout=600, poll=2.0):
    """Block until the job is done (returns its decoded result) or failed / expired / timed out (raises RuntimeError)."""
    end = time.time() + timeout
    while time.time() < end:
        j = store.job(job_id)
        if j and j["status"] == "done":
            return unpack(j["result"]) if j["result"] else b""
        if j and j["status"] in ("failed", "expired", "refused"):
            raise RuntimeError(f"the collector didn't run it: {j['error'] or j['status']}")
        time.sleep(poll)
    raise RuntimeError("no answer from the collector in time (offline or paused?)")
