"""Sites and site collectors: the small database the console and the collector gateway share.

The console (root) creates sites and one-time enrollment codes and revokes collectors. The gateway (its own system
user, no vault access) enrolls collectors, checks their signed requests and records heartbeats. Nothing secret is
stored here: enrollment codes only as SHA-256 hashes, collectors only by their public keys.
"""
import base64
import hashlib
import ipaddress
import json
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

CODE_HOURS = 24
LOCAL_SITE = "local"
SITE_ID = re.compile(r"^(local|s_[0-9a-f]{12})$")
COLLECTOR_ID = re.compile(r"^gc_[0-9a-f]{16}$")
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"          # no 0/O, 1/I/L, U: easy to read out and type
CODE_RE = re.compile(r"^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$")
STATES = ("connected", "paused", "disconnected")

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sites (id TEXT PRIMARY KEY, name TEXT NOT NULL, customer TEXT NOT NULL DEFAULT '',
  created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS collectors (id TEXT PRIMARY KEY, site_id TEXT NOT NULL, status TEXT NOT NULL,
  pubkey BLOB, code_hash TEXT UNIQUE, code_expires REAL, created REAL NOT NULL, created_by TEXT NOT NULL DEFAULT '',
  enrolled_at REAL, host TEXT, version TEXT, scope TEXT, state TEXT, reason TEXT, last_seen REAL, last_ip TEXT);
CREATE TABLE IF NOT EXISTS nonces (collector_id TEXT NOT NULL, nonce TEXT NOT NULL, expires REAL NOT NULL,
  PRIMARY KEY (collector_id, nonce));
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, t REAL NOT NULL, site_id TEXT,
  collector_id TEXT, kind TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS events_site ON events (site_id, id);
CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, collector_id TEXT NOT NULL, site_id TEXT NOT NULL, type TEXT NOT NULL,
  envelope TEXT NOT NULL, status TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL, sent_at REAL, done_at REAL,
  result TEXT, error TEXT, by TEXT NOT NULL DEFAULT '', run TEXT);
CREATE INDEX IF NOT EXISTS jobs_queue ON jobs (collector_id, status, created);
"""


def code_hash(code):
    return hashlib.sha256(("guardian-enroll:" + code).encode()).hexdigest()


def new_code():
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(12))
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"


def spki_pin(cert_path):
    """sha256 of the certificate's public key, as collectors pin it."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "sha256:" + base64.urlsafe_b64encode(hashlib.sha256(spki).digest()).decode().rstrip("=")


def scope_ok(items):
    """Customer subnets: 1-32 networks, nothing broader than /16 (IPv4) or /48 (IPv6). Returns normalised strings."""
    if not isinstance(items, list) or not 1 <= len(items) <= 32:
        raise ValueError("scope must list 1 to 32 networks")
    out = []
    for c in items:
        if not isinstance(c, str) or len(c) > 43:
            raise ValueError("bad network")
        n = ipaddress.ip_network(c, strict=True)
        if n.prefixlen < (16 if n.version == 4 else 48):
            raise ValueError(f"{n} is too broad")
        if n.is_loopback or n.is_multicast or n.is_link_local or n.is_unspecified:
            raise ValueError(f"{n} can't be scanned")
        out.append(str(n))
    return sorted(set(out))


def locked(fn):
    @wraps(fn)
    def inner(self, *a, **k):
        with self.lock:
            return fn(self, *a, **k)
    return inner


class Store:
    def __init__(self, path):
        self.lock = threading.RLock()
        self.path = Path(path)
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)
        self.db.execute("INSERT OR IGNORE INTO sites (id, name, customer, created) VALUES (?, ?, '', ?)",
                        (LOCAL_SITE, "This network", time.time()))

    @contextmanager
    def tx(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        self.db.execute("COMMIT")

    # -- meta --------------------------------------------------------------------------------------------
    @locked
    def meta(self, key, default=None):
        r = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return r["value"] if r else default

    @locked
    def set_meta(self, key, value):
        self.db.execute("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (key, value))

    @locked
    def event(self, kind, site_id=None, collector_id=None, detail=""):
        self.db.execute("INSERT INTO events (t, site_id, collector_id, kind, detail) VALUES (?, ?, ?, ?, ?)",
                        (time.time(), site_id, collector_id, kind, str(detail)[:300]))

    @locked
    def events(self, site_id, limit=50):
        return [dict(r) for r in self.db.execute(
            "SELECT t, collector_id, kind, detail FROM events WHERE site_id=? ORDER BY id DESC LIMIT ?", (site_id, limit))]

    # -- sites (console) ---------------------------------------------------------------------------------
    @locked
    def sites(self):
        out = []
        for s in self.db.execute("SELECT * FROM sites ORDER BY id='local' DESC, name COLLATE NOCASE"):
            d = dict(s)
            d["collector"] = self._public(self.db.execute(
                "SELECT * FROM collectors WHERE site_id=? AND status='active' ORDER BY enrolled_at DESC LIMIT 1", (s["id"],)).fetchone())
            p = self.db.execute("SELECT code_expires, created_by FROM collectors WHERE site_id=? AND status='pending' "
                                "AND code_expires > ?", (s["id"], time.time())).fetchone()
            d["pending"] = dict(p) if p else None
            out.append(d)
        return out

    @locked
    def site(self, site_id):
        if not SITE_ID.match(site_id or ""):
            return None
        r = self.db.execute("SELECT * FROM sites WHERE id=?", (site_id,)).fetchone()
        return dict(r) if r else None

    @locked
    def add_site(self, name, customer):
        sid = "s_" + secrets.token_hex(6)
        self.db.execute("INSERT INTO sites (id, name, customer, created) VALUES (?, ?, ?, ?)", (sid, name, customer, time.time()))
        self.event("site-added", sid, detail=name)
        return sid

    @locked
    def rename_site(self, site_id, name, customer):
        self.db.execute("UPDATE sites SET name=?, customer=? WHERE id=?", (name, customer, site_id))
        self.event("site-renamed", site_id, detail=name)

    @locked
    def delete_site(self, site_id):
        with self.tx():
            self.db.execute("UPDATE collectors SET status='revoked', code_hash=NULL WHERE site_id=?", (site_id,))
            self.db.execute("DELETE FROM sites WHERE id=? AND id<>?", (site_id, LOCAL_SITE))

    @locked
    def create_code(self, site_id, by):
        """A new one-time enrollment code for the site; any earlier unused code for it stops working."""
        code = new_code()
        now = time.time()
        with self.tx():
            self.db.execute("DELETE FROM collectors WHERE site_id=? AND status='pending'", (site_id,))
            self.db.execute("INSERT INTO collectors (id, site_id, status, code_hash, code_expires, created, created_by) "
                            "VALUES (?, ?, 'pending', ?, ?, ?, ?)",
                            ("gc_" + secrets.token_hex(8), site_id, code_hash(code), now + CODE_HOURS * 3600, now, by))
        self.event("code-created", site_id, detail=f"by {by}")
        return code, now + CODE_HOURS * 3600

    @locked
    def cancel_code(self, site_id):
        self.db.execute("DELETE FROM collectors WHERE site_id=? AND status='pending'", (site_id,))
        self.event("code-cancelled", site_id)

    @locked
    def revoke(self, site_id):
        n = self.db.execute("UPDATE collectors SET status='revoked' WHERE site_id=? AND status='active'", (site_id,)).rowcount
        if n:
            self.event("revoked", site_id)
        return n

    # -- collectors (gateway) ----------------------------------------------------------------------------
    @locked
    def enroll(self, code, pubkey, host, version, scope, ip):
        """Use a code once. Returns (collector, site) or None. Older collectors of the site are revoked."""
        if not CODE_RE.match(code):
            return None
        h = code_hash(code)
        now = time.time()
        with self.tx():
            r = self.db.execute("SELECT * FROM collectors WHERE code_hash=? AND status='pending'", (h,)).fetchone()
            if not r or not secrets.compare_digest(r["code_hash"], h) or r["code_expires"] < now:
                return None
            self.db.execute("UPDATE collectors SET status='revoked' WHERE site_id=? AND status='active'", (r["site_id"],))
            self.db.execute("UPDATE collectors SET status='active', code_hash=NULL, code_expires=NULL, pubkey=?, enrolled_at=?, "
                            "host=?, version=?, scope=?, state='connected', last_seen=?, last_ip=? WHERE id=?",
                            (pubkey, now, host, version, json.dumps(scope), now, ip, r["id"]))
        self.event("enrolled", r["site_id"], r["id"], f"{host} {version} from {ip}")
        return self.collector(r["id"]), self.site(r["site_id"])

    @locked
    def collector(self, cid):
        if not COLLECTOR_ID.match(cid or ""):
            return None
        r = self.db.execute("SELECT * FROM collectors WHERE id=?", (cid,)).fetchone()
        return dict(r) if r else None

    @locked
    def use_nonce(self, cid, nonce, ttl):
        """True the first time a (collector, one-time id) pair is seen."""
        now = time.time()
        try:
            self.db.execute("INSERT INTO nonces (collector_id, nonce, expires) VALUES (?, ?, ?)", (cid, nonce, now + ttl))
        except sqlite3.IntegrityError:
            return False
        if secrets.randbelow(200) == 0:
            self.db.execute("DELETE FROM nonces WHERE expires < ?", (now,))
        return True

    @locked
    def heartbeat(self, cid, state, reason, host, version, scope, ip):
        old = self.collector(cid)
        self.db.execute("UPDATE collectors SET state=?, reason=?, host=?, version=?, scope=?, last_seen=?, last_ip=? WHERE id=?",
                        (state, reason, host, version, json.dumps(scope), time.time(), ip, cid))
        if old and (old["state"] != state or (old["reason"] or "") != (reason or "")):
            self.event(state, old["site_id"], cid, reason or "")
        if old and old["scope"] != json.dumps(scope):
            self.event("scope-changed", old["site_id"], cid, ", ".join(scope))

    # -- jobs (phase B): the console adds signed jobs, the gateway hands them out and stores results ----------------
    @locked
    def add_job(self, jid, cid, site_id, kind, envelope, expires, by, run=None):
        self.db.execute("INSERT INTO jobs (id, collector_id, site_id, type, envelope, status, created, expires, by, run) "
                        "VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?)", (jid, cid, site_id, kind, envelope, time.time(), expires, by, run))

    @locked
    def take_jobs(self, cid, limit=4):
        """Queued jobs for this collector, marked as sent. Expired ones are marked expired instead."""
        now = time.time()
        with self.tx():
            self.db.execute("UPDATE jobs SET status='expired' WHERE collector_id=? AND status IN ('queued', 'sent') AND expires < ?", (cid, now))
            rows = self.db.execute("SELECT id, envelope FROM jobs WHERE collector_id=? AND status='queued' ORDER BY created LIMIT ?",
                                   (cid, limit)).fetchall()
            for r in rows:
                self.db.execute("UPDATE jobs SET status='sent', sent_at=? WHERE id=?", (now, r["id"]))
        return [json.loads(r["envelope"]) for r in rows]

    @locked
    def finish_job(self, cid, jid, status, result=None, error=None):
        """Only a job that was sent to this very collector can be finished, and only once."""
        n = self.db.execute("UPDATE jobs SET status=?, result=?, error=?, done_at=? WHERE id=? AND collector_id=? AND status='sent'",
                            (status, result, (error or "")[:500] or None, time.time(), jid, cid)).rowcount
        return n == 1

    @locked
    def job(self, jid):
        r = self.db.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
        return dict(r) if r else None

    @locked
    def jobs_for_run(self, run):
        return [dict(r) for r in self.db.execute("SELECT id, type, status, error, created, done_at FROM jobs WHERE run=? ORDER BY created", (run,))]

    @locked
    def active_collector(self, site_id):
        r = self.db.execute("SELECT * FROM collectors WHERE site_id=? AND status='active' ORDER BY enrolled_at DESC LIMIT 1", (site_id,)).fetchone()
        return dict(r) if r else None

    @locked
    def purge_jobs(self, days=30):
        self.db.execute("DELETE FROM jobs WHERE created < ?", (time.time() - days * 86400,))

    @staticmethod
    def _public(r):
        if not r:
            return None
        d = {k: r[k] for k in ("id", "status", "enrolled_at", "host", "version", "state", "reason", "last_seen", "last_ip")}
        d["scope"] = json.loads(r["scope"] or "[]")
        d["key_fingerprint"] = ("SHA256:" + base64.b64encode(hashlib.sha256(r["pubkey"]).digest()).decode().rstrip("=")) if r["pubkey"] else None
        return d
