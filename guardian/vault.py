"""Guardian's encrypted store: users, passkeys, the vault key and connector secrets, in one SQLite file.

Key hierarchy
  passkey PRF output --HKDF--> credential KEK --AES-GCM--> user's X25519 private key
  user's X25519 key  --sealed box--> vault key (one copy per admin/operator, see vault_slots)
  recovery key       --HKDF--> recovery KEK --AES-GCM--> vault key (break-glass copy)
  vault key          --AES-GCM, AAD = record id--> each connector record

The vault key exists only in this process's memory while at least one admin/operator session has
unlocked it; it is zeroed when the last one signs out or goes idle. Nothing on disk can be decrypted
without a user's passkey or the recovery key.
"""
import base64
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROLES = ("viewer", "operator", "admin")
VAULT_ROLES = ("operator", "admin")
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, provider TEXT, subject TEXT,
  role TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', public_key BLOB,
  created REAL NOT NULL, last_login REAL);
CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL,
  public_key BLOB NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0, prf_salt BLOB NOT NULL,
  wrapped_private_key BLOB, created REAL NOT NULL, last_used REAL);
CREATE TABLE IF NOT EXISTS vault_slots (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, sealed_key BLOB NOT NULL,
  granted_by TEXT, granted REAL NOT NULL);
CREATE TABLE IF NOT EXISTS invites (
  token_hash TEXT PRIMARY KEY, email TEXT NOT NULL, role TEXT NOT NULL, created_by TEXT NOT NULL,
  created REAL NOT NULL, expires REAL NOT NULL, used REAL);
CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY, kind TEXT NOT NULL, blob BLOB NOT NULL, updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  detail TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL);
"""


# -- primitives ---------------------------------------------------------------------------
def _hkdf(material, salt, info, length=32):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(material)


def wrap(key, plaintext, aad=b""):
    nonce = os.urandom(12)
    return nonce + AESGCM(bytes(key)).encrypt(nonce, plaintext, aad)


def unwrap(key, blob, aad=b""):
    return AESGCM(bytes(key)).decrypt(blob[:12], blob[12:], aad)


def seal(public_raw, plaintext, aad=b""):
    """Encrypt to an X25519 public key (ephemeral key agreement + AES-GCM)."""
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(public_raw))
    key = _hkdf(shared, eph_pub + public_raw, b"guardian-seal-v1")
    return eph_pub + wrap(key, plaintext, aad)


def open_sealed(private_raw, blob, aad=b""):
    priv = X25519PrivateKey.from_private_bytes(bytes(private_raw))
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key = _hkdf(priv.exchange(X25519PublicKey.from_public_bytes(blob[:32])), blob[:32] + pub, b"guardian-seal-v1")
    return unwrap(key, blob[32:], aad)


def prf_kek(prf_output, credential_id):
    return _hkdf(prf_output, credential_id.encode(), b"guardian-passkey-kek-v1")


def recovery_kek(recovery_bytes, vault_id):
    return _hkdf(recovery_bytes, vault_id.encode(), b"guardian-recovery-kek-v1")


def format_recovery(raw):
    s = base64.b32encode(raw).decode().rstrip("=")
    return "-".join(s[i:i + 4] for i in range(0, len(s), 4))


def parse_recovery(text):
    s = "".join(ch for ch in text.upper() if ch.isalnum())
    s += "=" * (-len(s) % 8)
    return base64.b32decode(s)


def new_keypair():
    priv = X25519PrivateKey.generate()
    return (priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()),
            priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def _zero(buf):
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


class VaultLocked(Exception):
    pass


# -- store ------------------------------------------------------------------------------------
class _Rows(list):
    def fetchone(self):
        return self[0] if self else None

    def fetchall(self):
        return list(self)


class _LockedDB:
    """One SQLite connection shared by the console's request threads: every statement runs, and its rows are read,
    under the vault lock, so two requests never interleave on the connection."""
    def __init__(self, conn, lock):
        self._conn, self._lock = conn, lock

    def execute(self, sql, args=()):
        with self._lock:
            return _Rows(self._conn.execute(sql, args).fetchall())

    def executescript(self, sql):
        with self._lock:
            return self._conn.executescript(sql)


class Vault:
    def __init__(self, path):
        self.path = str(path)
        self.lock = threading.RLock()
        self._key = None                 # bytearray while unlocked
        self.holders = {}                # session id -> last activity
        self.unlocked_at = None
        self.unlocked_by = None
        new = not os.path.exists(self.path)
        if new:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        self.db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.execute("PRAGMA journal_mode = WAL")
        self.db.executescript(SCHEMA)
        os.chmod(self.path, 0o600)
        self.db = _LockedDB(self.db, self.lock)

    # meta
    def get(self, key, default=None):
        r = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(r["value"]) if r else default

    def put(self, key, value):
        with self.lock:
            self.db.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                            (key, json.dumps(value)))

    @property
    def initialized(self):
        return self.get("vault_id") is not None

    # -- audit log (hash chain) -----------------------------------------------------------
    def audit(self, actor, action, detail=""):
        with self.lock:
            last = self.db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            prev = last["hash"] if last else "0" * 64
            ts = time.time()
            h = hashlib.sha256(f"{prev}|{ts:.6f}|{actor}|{action}|{detail}".encode()).hexdigest()
            self.db.execute("INSERT INTO audit(ts,actor,action,detail,prev,hash) VALUES(?,?,?,?,?,?)",
                            (ts, actor, action, detail, prev, h))

    def audit_rows(self, limit=200):
        return [dict(r) for r in self.db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]

    def audit_verify(self):
        prev = "0" * 64
        n = 0
        for r in self.db.execute("SELECT * FROM audit ORDER BY id"):
            h = hashlib.sha256(f"{prev}|{r['ts']:.6f}|{r['actor']}|{r['action']}|{r['detail']}".encode()).hexdigest()
            if r["prev"] != prev or r["hash"] != h:
                return False, n, r["id"]
            prev, n = h, n + 1
        anchor = self.get("audit_anchor")
        if anchor and anchor.get("count", 0) > n:
            return False, n, None     # rows were deleted from the end
        return True, n, None

    def anchor_audit(self):
        r = self.db.execute("SELECT COUNT(*) c FROM audit").fetchone()
        self.put("audit_anchor", {"count": r["c"]})

    # -- users ------------------------------------------------------------------------------
    def users(self):
        rows = self.db.execute("""SELECT u.*, (SELECT COUNT(*) FROM credentials c WHERE c.user_id=u.id) passkeys,
                                  (SELECT group_concat(name, ', ') FROM credentials c WHERE c.user_id=u.id) passkey_names,
                                  EXISTS(SELECT 1 FROM vault_slots s WHERE s.user_id=u.id) vault
                                  FROM users u ORDER BY created""").fetchall()
        return [{k: r[k] for k in r.keys() if k != "public_key"} for r in rows]

    def user(self, uid=None, email=None):
        r = self.db.execute("SELECT * FROM users WHERE id=?" if uid else "SELECT * FROM users WHERE lower(email)=lower(?)",
                            (uid or email,)).fetchone()
        return dict(r) if r else None

    def create_user(self, email, name, role, provider=None, subject=None):
        uid = "u" + secrets.token_hex(6)
        with self.lock:
            self.db.execute("INSERT INTO users(id,email,name,provider,subject,role,created) VALUES(?,?,?,?,?,?,?)",
                            (uid, email.lower(), name or email, provider, subject, role, time.time()))
        return uid

    def update_user(self, uid, **fields):
        allowed = {"name", "role", "status", "provider", "subject", "last_login", "public_key"}
        sets = {k: v for k, v in fields.items() if k in allowed}
        if sets:
            with self.lock:
                self.db.execute(f"UPDATE users SET {', '.join(f'{k}=?' for k in sets)} WHERE id=?", (*sets.values(), uid))

    def delete_user(self, uid):
        with self.lock:
            self.db.execute("DELETE FROM users WHERE id=?", (uid,))

    def admins_with_vault(self):
        return self.db.execute("""SELECT COUNT(*) c FROM users u JOIN vault_slots s ON s.user_id=u.id
                                  WHERE u.role='admin' AND u.status='active'""").fetchone()["c"]

    # -- passkeys ---------------------------------------------------------------------------
    def credentials(self, uid=None):
        q = "SELECT * FROM credentials" + (" WHERE user_id=?" if uid else "")
        return [dict(r) for r in self.db.execute(q, (uid,) if uid else ())]

    def credential(self, cid):
        r = self.db.execute("SELECT * FROM credentials WHERE id=?", (cid,)).fetchone()
        return dict(r) if r else None

    def add_credential(self, uid, cid, name, public_key, sign_count):
        with self.lock:
            self.db.execute("INSERT INTO credentials(id,user_id,name,public_key,sign_count,prf_salt,created) VALUES(?,?,?,?,?,?,?)",
                            (cid, uid, name, public_key, sign_count, os.urandom(32), time.time()))

    def touch_credential(self, cid, sign_count):
        with self.lock:
            self.db.execute("UPDATE credentials SET sign_count=?, last_used=? WHERE id=?", (sign_count, time.time(), cid))

    def delete_credential(self, cid):
        with self.lock:
            self.db.execute("DELETE FROM credentials WHERE id=?", (cid,))

    def bind_credential(self, uid, cid, prf_output):
        """First PRF from a new passkey: protect the user's private key with it (creating the key pair if needed)."""
        user = self.user(uid)
        others = [c for c in self.credentials(uid) if c["wrapped_private_key"] and c["id"] != cid]
        if user["public_key"] and others:
            raise ValueError("Use an existing passkey once to add this one")     # private key is needed to re-wrap
        priv, pub = new_keypair()
        with self.lock:
            self.db.execute("UPDATE users SET public_key=? WHERE id=?", (pub, uid))
            self.db.execute("UPDATE credentials SET wrapped_private_key=? WHERE id=?",
                            (wrap(prf_kek(prf_output, cid), priv, cid.encode()), cid))
            self.db.execute("DELETE FROM vault_slots WHERE user_id=?", (uid,))   # old slot was sealed to an old key
        return bytearray(priv)

    def add_wrapped_credential(self, uid, cid, prf_output, private_raw):
        """Protect the user's existing private key with an additional passkey."""
        with self.lock:
            self.db.execute("UPDATE credentials SET wrapped_private_key=? WHERE id=? AND user_id=?",
                            (wrap(prf_kek(prf_output, cid), bytes(private_raw), cid.encode()), cid, uid))

    def private_key(self, cid, prf_output):
        c = self.credential(cid)
        if not c or not c["wrapped_private_key"]:
            return None
        return bytearray(unwrap(prf_kek(prf_output, cid), c["wrapped_private_key"], cid.encode()))

    # -- vault key ---------------------------------------------------------------------------
    @property
    def unlocked(self):
        return self._key is not None

    def initialize(self, uid, private_raw):
        """Create the vault key and the recovery key. Returns the recovery key text (shown once)."""
        if self.initialized:
            raise ValueError("Vault already exists")
        vault_id = "v" + secrets.token_hex(8)
        key = bytearray(os.urandom(32))
        rec = os.urandom(32)
        user = self.user(uid)
        with self.lock:
            self.put("vault_id", vault_id)
            self.put("recovery", {"wrapped": base64.b64encode(wrap(recovery_kek(rec, vault_id), bytes(key), b"recovery")).decode(),
                                  "created": time.time()})
            self.db.execute("INSERT INTO vault_slots(user_id,sealed_key,granted_by,granted) VALUES(?,?,?,?)",
                            (uid, seal(user["public_key"], bytes(key), uid.encode()), uid, time.time()))
            self._key = key
        return format_recovery(rec)

    def unlock_with_private_key(self, uid, private_raw, session_id, who):
        slot = self.db.execute("SELECT sealed_key FROM vault_slots WHERE user_id=?", (uid,)).fetchone()
        if not slot:
            return False
        key = bytearray(open_sealed(private_raw, slot["sealed_key"], uid.encode()))
        self._hold(key, session_id, who)
        return True

    def unlock_with_recovery(self, text, session_id, who):
        rec = self.get("recovery")
        key = bytearray(unwrap(recovery_kek(parse_recovery(text), self.get("vault_id")), base64.b64decode(rec["wrapped"]), b"recovery"))
        self._hold(key, session_id, who)

    def _hold(self, key, session_id, who):
        with self.lock:
            if self._key is None:
                self._key, self.unlocked_at, self.unlocked_by = key, time.time(), who
            else:
                _zero(key)
            self.holders[session_id] = time.time()

    def release(self, session_id):
        with self.lock:
            self.holders.pop(session_id, None)
            if not self.holders:
                self.lock_now()

    def lock_now(self):
        with self.lock:
            if self._key is not None:
                _zero(self._key)
            self._key, self.holders, self.unlocked_at, self.unlocked_by = None, {}, None, None

    def touch(self, session_id):
        if session_id in self.holders:
            self.holders[session_id] = time.time()

    def expire(self, idle_seconds, max_seconds):
        """Drop idle holders; lock if none remain or the vault has been open too long. Returns True if it locked."""
        with self.lock:
            if self._key is None:
                return False
            now = time.time()
            for sid, t in list(self.holders.items()):
                if now - t > idle_seconds:
                    self.holders.pop(sid)
            if not self.holders or (self.unlocked_at and now - self.unlocked_at > max_seconds):
                self.lock_now()
                return True
        return False

    def key(self):
        if self._key is None:
            raise VaultLocked()
        return self._key

    def grant(self, uid, granted_by):
        user = self.user(uid)
        if not user or not user["public_key"]:
            raise ValueError("That user hasn't set up a passkey yet")
        with self.lock:
            self.db.execute("INSERT INTO vault_slots(user_id,sealed_key,granted_by,granted) VALUES(?,?,?,?) "
                            "ON CONFLICT(user_id) DO UPDATE SET sealed_key=excluded.sealed_key, granted_by=excluded.granted_by, granted=excluded.granted",
                            (uid, seal(user["public_key"], bytes(self.key()), uid.encode()), granted_by, time.time()))

    def revoke(self, uid):
        with self.lock:
            self.db.execute("DELETE FROM vault_slots WHERE user_id=?", (uid,))

    def has_slot(self, uid):
        return self.db.execute("SELECT 1 FROM vault_slots WHERE user_id=?", (uid,)).fetchone() is not None

    def rotate_recovery(self):
        rec = os.urandom(32)
        self.put("recovery", {"wrapped": base64.b64encode(wrap(recovery_kek(rec, self.get("vault_id")), bytes(self.key()), b"recovery")).decode(),
                              "created": time.time()})
        return format_recovery(rec)

    # -- encrypted records (connectors) ----------------------------------------------------
    def save_record(self, rid, kind, data):
        blob = wrap(self.key(), json.dumps(data).encode(), f"{kind}:{rid}".encode())
        with self.lock:
            self.db.execute("INSERT INTO records(id,kind,blob,updated) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET blob=excluded.blob, updated=excluded.updated",
                            (rid, kind, blob, time.time()))

    def load_records(self, kind):
        key = self.key()
        return [json.loads(unwrap(key, r["blob"], f"{kind}:{r['id']}".encode()))
                for r in self.db.execute("SELECT * FROM records WHERE kind=? ORDER BY updated", (kind,))]

    def delete_record(self, rid):
        with self.lock:
            self.db.execute("DELETE FROM records WHERE id=?", (rid,))

    def record_count(self, kind):
        return self.db.execute("SELECT COUNT(*) c FROM records WHERE kind=?", (kind,)).fetchone()["c"]

    # -- invites ------------------------------------------------------------------------------
    def create_invite(self, email, role, created_by, days=7):
        token = secrets.token_urlsafe(24)
        with self.lock:
            self.db.execute("INSERT INTO invites(token_hash,email,role,created_by,created,expires) VALUES(?,?,?,?,?,?)",
                            (hashlib.sha256(token.encode()).hexdigest(), email.lower(), role, created_by, time.time(), time.time() + days * 86400))
        return token

    def invite(self, token):
        r = self.db.execute("SELECT * FROM invites WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if not r or r["used"] or r["expires"] < time.time():
            return None
        return dict(r)

    def use_invite(self, token):
        with self.lock:
            self.db.execute("UPDATE invites SET used=? WHERE token_hash=?", (time.time(), hashlib.sha256(token.encode()).hexdigest()))

    def invites(self):
        return [dict(r) for r in self.db.execute("SELECT * FROM invites WHERE used IS NULL AND expires>? ORDER BY created", (time.time(),))]

    def revoke_invite(self, token_hash):
        with self.lock:
            self.db.execute("DELETE FROM invites WHERE token_hash=?", (token_hash,))
