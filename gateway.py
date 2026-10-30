#!/usr/bin/env python3
"""AI IT Guardian collector gateway: the only Guardian service meant to be reachable from outside.

It serves five routes under /c/v1/ to on-site collectors and nothing else. Every request except enrollment is signed
with the collector's Ed25519 key; the checks run in a fixed order and the body is parsed only after the signature is
valid. It runs as its own system user and can't read the vault, the Anthropic key, connector secrets or reports: it
shares only the small site database (guardian/sitestore.py) with the console.
"""
import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import os
import re
import resource
import sys
import time
from pathlib import Path
from typing import Literal, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import NameOID
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.routing import Route

from guardian import sitestore

BASE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("GUARDIAN_GATEWAY_DATA", BASE / "gateway"))
CERT, KEY = DATA / "tls-cert.pem", DATA / "tls-key.pem"
TRUSTED_PROXY = os.environ.get("GUARDIAN_GATEWAY_TRUSTED_PROXY", "")   # set only when a proxy/tunnel sits in front

MAX_BODY = 16 * 1024
CLOCK_SKEW = 120                     # seconds a signed request may be early or late
WAIT = 25                            # long-poll for jobs
ENROLL_FAILS, ENROLL_LOCK = 5, 3600  # failed enrollments per address before a one-hour lockout

log = logging.getLogger("gateway")
store = None

HEX_ID = re.compile(r"^gc_[0-9a-f]{16}$")
TS = re.compile(r"^\d{10}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{22,64}$")
SIG = re.compile(r"^[A-Za-z0-9_-]{86}$")
PUBKEY = r"^[A-Za-z0-9_-]{43}$"
HOST = r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$"
VERSION = r"^\d{1,3}\.\d{1,3}\.\d{1,3}$"
TEXT = r"^[^\x00-\x1f\x7f]{0,200}$"


# -- request bodies: fixed schemas, unknown fields rejected -------------------------------------------------------
class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EnrollBody(Strict):
    code: str = Field(max_length=14)
    pubkey: str = Field(pattern=PUBKEY)
    host: str = Field(pattern=HOST)
    version: str = Field(pattern=VERSION)
    scope: list[str] = Field(min_length=1, max_length=32)


class Stats(Strict):
    jobs_30d: int = Field(ge=0, le=10_000_000)
    refused_30d: int = Field(ge=0, le=10_000_000)


class HeartbeatBody(Strict):
    state: Literal["connected", "paused"]
    reason: Optional[str] = Field(default=None, pattern=TEXT)
    host: str = Field(pattern=HOST)
    version: str = Field(pattern=VERSION)
    scope: list[str] = Field(min_length=1, max_length=32)
    stats: Optional[Stats] = None


class DisconnectBody(Strict):
    reason: Optional[str] = Field(default=None, pattern=TEXT)


class Empty(Strict):
    pass


class ResultBody(Strict):
    job: str = Field(pattern=r"^j_[0-9a-f]{16}$")


# -- small helpers ------------------------------------------------------------------------------------------------
class Fail(Exception):
    def __init__(self, status):
        self.status = status


ERRORS = {400: "bad request", 401: "unauthorized", 404: "not found", 413: "too large", 429: "slow down", 503: "unavailable"}


def reply(status, body=None):
    return JSONResponse(body if body is not None else {"error": ERRORS.get(status, "error")}, status_code=status,
                        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


class Buckets:
    """Token buckets per key: `rate` requests per `per` seconds, bursts up to `rate`."""
    def __init__(self, rate, per):
        self.rate, self.per, self.b = rate, per, {}

    def take(self, key):
        now = time.monotonic()
        tokens, last = self.b.get(key, (self.rate, now))
        tokens = min(self.rate, tokens + (now - last) * self.rate / self.per)
        if len(self.b) > 50_000:
            self.b.clear()
        if tokens < 1:
            self.b[key] = (tokens, now)
            return False
        self.b[key] = (tokens - 1, now)
        return True


per_ip = Buckets(120, 60)
per_collector = Buckets(60, 60)
enroll_ip = Buckets(10, 3600)
enroll_fails = {}


def client_ip(request):
    peer = request.client.host if request.client else "0.0.0.0"
    if TRUSTED_PROXY and peer == TRUSTED_PROXY:
        fwd = request.headers.get("cf-connecting-ip") or request.headers.get("x-forwarded-for", "").split(",")[-1].strip()
        try:
            return str(ipaddress.ip_address(fwd))
        except ValueError:
            pass
    return peer


async def read_body(request):
    if request.url.query:
        raise Fail(404)
    cl = request.headers.get("content-length")
    if cl is not None and (not cl.isdigit() or int(cl) > MAX_BODY):
        raise Fail(413)
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY:
            raise Fail(413)
        chunks.append(chunk)
    return b"".join(chunks)


def _no_dupes(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def parse(model, body):
    try:
        data = json.loads(body or b"{}", object_pairs_hook=_no_dupes,
                          parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
        if not isinstance(data, dict):
            raise ValueError("not an object")
        return model.model_validate(data)
    except (ValueError, ValidationError, RecursionError):
        raise Fail(400)


def authenticate(request, body):
    """Signed request → active collector. Checks: headers well-formed, collector active, time, signature, one-time id."""
    h = request.headers
    cid, ts, nonce, sig = h.get("x-gc-id", ""), h.get("x-gc-time", ""), h.get("x-gc-nonce", ""), h.get("x-gc-sig", "")
    if not (HEX_ID.match(cid) and TS.match(ts) and NONCE.match(nonce) and SIG.match(sig)):
        raise Fail(401)
    c = store.collector(cid)
    if not c or c["status"] != "active" or not c["pubkey"]:
        raise Fail(401)
    if abs(time.time() - int(ts)) > CLOCK_SKEW:
        raise Fail(401)
    msg = "\n".join([request.method, request.url.path, cid, ts, nonce, hashlib.sha256(body).hexdigest()]).encode()
    try:
        Ed25519PublicKey.from_public_bytes(c["pubkey"]).verify(base64.urlsafe_b64decode(sig + "=="), msg)
    except (InvalidSignature, ValueError):
        raise Fail(401)
    if not store.use_nonce(cid, nonce, 2 * CLOCK_SKEW + 60):
        raise Fail(401)
    if not per_collector.take(cid):
        raise Fail(429)
    return c


def guarded(fn):
    async def endpoint(request):
        ip = client_ip(request)
        try:
            if not per_ip.take(ip):
                raise Fail(429)
            return await fn(request, ip)
        except Fail as f:
            return reply(f.status)
        except Exception:                                               # noqa: BLE001 - never leak details
            log.exception("gateway error")
            return reply(400)
    return endpoint


# -- routes -------------------------------------------------------------------------------------------------------
@guarded
async def enroll(request, ip):
    fails = [t for t in enroll_fails.get(ip, []) if t > time.time() - ENROLL_LOCK]
    enroll_fails[ip] = fails
    if len(fails) >= ENROLL_FAILS or not enroll_ip.take(ip):
        raise Fail(429)
    b = parse(EnrollBody, await read_body(request))
    job_key = store.meta("job_pubkey")
    if not job_key:
        raise Fail(503)
    try:
        scope = sitestore.scope_ok(b.scope)
        pub = base64.urlsafe_b64decode(b.pubkey + "=")
        Ed25519PublicKey.from_public_bytes(pub)
    except ValueError:
        raise Fail(400)
    got = store.enroll(b.code.upper(), pub, b.host, b.version, scope, ip)
    if not got:
        enroll_fails[ip] = fails + [time.time()]
        if len(enroll_fails) > 50_000:
            enroll_fails.clear()
        log.warning("enrollment refused from %s", ip)
        raise Fail(401)
    c, site = got
    log.info("collector %s enrolled for site %s from %s", c["id"], site["id"], ip)
    return reply(200, {"collector_id": c["id"], "site": {"id": site["id"], "name": site["name"]}, "job_key": job_key})


@guarded
async def heartbeat(request, ip):
    body = await read_body(request)
    c = authenticate(request, body)
    b = parse(HeartbeatBody, body)
    try:
        scope = sitestore.scope_ok(b.scope)
    except ValueError:
        raise Fail(400)
    store.heartbeat(c["id"], b.state, b.reason, b.host, b.version, scope, ip)
    return reply(200, {"ok": True, "time": int(time.time())})


@guarded
async def disconnect(request, ip):
    body = await read_body(request)
    c = authenticate(request, body)
    b = parse(DisconnectBody, body)
    store.heartbeat(c["id"], "disconnected", b.reason, c["host"], c["version"], json.loads(c["scope"] or "[]"), ip)
    return reply(200, {"ok": True})


@guarded
async def jobs(request, ip):
    body = await read_body(request)
    c = authenticate(request, body)
    parse(Empty, body)
    # Phase A has no job types yet: hold the request like a real long poll, then answer "nothing to do".
    end = time.monotonic() + WAIT
    while time.monotonic() < end and not await request.is_disconnected():
        await asyncio.sleep(1)
        cur = store.collector(c["id"])
        if not cur or cur["status"] != "active":
            raise Fail(401)
    return reply(200, {"jobs": []})


@guarded
async def result(request, ip):
    body = await read_body(request)
    authenticate(request, body)
    parse(ResultBody, body)
    raise Fail(404)                                                     # no jobs are issued before phase B


async def not_found(request, exc):
    return reply(404)


app = Starlette(routes=[Route(f"/c/v1/{name}", fn, methods=["POST"]) for name, fn in
                        (("enroll", enroll), ("heartbeat", heartbeat), ("disconnect", disconnect), ("jobs", jobs), ("result", result))],
                exception_handlers={HTTPException: not_found, 404: not_found, 405: not_found, Exception: not_found})


# -- startup ------------------------------------------------------------------------------------------------------
def ensure_cert():
    """A long-lived self-signed certificate; collectors pin its public key from the install command."""
    if CERT.exists() and KEY.exists():
        return
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AI IT Guardian gateway")])
    now = time.time()
    import datetime as dt
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.fromtimestamp(now - 3600, dt.timezone.utc))
            .not_valid_after(dt.datetime.fromtimestamp(now + 10 * 365 * 86400, dt.timezone.utc))
            .sign(key, hashes.SHA256()))
    fd = os.open(KEY, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def main():
    global store
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
    DATA.mkdir(mode=0o700, exist_ok=True)
    ensure_cert()
    store = sitestore.Store(DATA / "gateway.db")
    import uvicorn
    port = int(os.environ.get("GUARDIAN_GATEWAY_PORT", "8444"))
    log.info("gateway on port %s, certificate pin %s", port, sitestore.spki_pin(CERT))
    uvicorn.run(app, host=os.environ.get("GUARDIAN_GATEWAY_HOST", "0.0.0.0"), port=port,
                ssl_certfile=str(CERT), ssl_keyfile=str(KEY), server_header=False, date_header=False,
                proxy_headers=False, access_log=False, log_level="warning", limit_concurrency=256,
                timeout_keep_alive=5, h11_max_incomplete_event_size=16 * 1024)


if __name__ == "__main__":
    main()
