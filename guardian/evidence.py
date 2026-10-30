"""Compliance evidence: files the organisation provides for controls a technical assessment can't see.

Files are encrypted with the vault key (AES-GCM, bound to the evidence id) and stored as <id>.bin in the console's
state folder; their metadata (name, controls, validity) is an encrypted vault record. The type is decided from the
file's content, not its name, and only a short list of document and image types is accepted.
"""
import hashlib
import io
import os
import re
import secrets
import time
import zipfile
from pathlib import Path

from cryptography.exceptions import InvalidTag

from .vault import unwrap, wrap

MAX_BYTES = 10 * 1024 * 1024
KIND = "evidence"
OVERRIDE = "comp-override"
EXT = {"pdf": "application/pdf", "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "txt": "text/plain",
       "csv": "text/csv", "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
       "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
ID = re.compile(r"^ev_[0-9a-f]{16}$")
CONTROL = re.compile(r"^[a-z0-9_]{2,20}:[A-Za-z0-9.()\- ]{1,20}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
USER_STATUSES = ("met", "partial", "gap", "not_assessed")


class EvidenceError(ValueError):
    pass


def clean_name(name):
    name = os.path.basename((name or "").replace("\\", "/")).strip()
    name = re.sub(r"[^\w .()\-]", "_", name)[:120].strip(" .")
    if not name or "." not in name:
        raise EvidenceError("The file needs a name with an extension, e.g. policy.pdf")
    return name


def detect(name, data):
    """The file's real type from its content; it must match the extension. Returns the MIME type."""
    ext = name.rsplit(".", 1)[-1].lower()
    if ext not in EXT:
        raise EvidenceError("Accepted: PDF, PNG, JPG, TXT, CSV, DOCX, XLSX")
    if ext == "pdf":
        ok = data.startswith(b"%PDF-")
    elif ext == "png":
        ok = data.startswith(b"\x89PNG\r\n\x1a\n")
    elif ext in ("jpg", "jpeg"):
        ok = data.startswith(b"\xff\xd8\xff")
    elif ext in ("txt", "csv"):
        try:
            ok = b"\x00" not in data and bool(data.decode("utf-8-sig") or True)
        except UnicodeDecodeError:
            ok = False
    else:                                              # docx / xlsx: a zip with the right Office part, no macros
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names = z.namelist()
            need = "word/document.xml" if ext == "docx" else "xl/workbook.xml"
            ok = "[Content_Types].xml" in names and need in names and not any(n.lower().endswith("vbaproject.bin") for n in names)
        except (zipfile.BadZipFile, ValueError):
            ok = False
    if not ok:
        raise EvidenceError(f"The content doesn't look like a .{ext} file")
    return EXT[ext]


def check_controls(items, frameworks):
    out = []
    for c in items or []:
        c = str(c).strip()
        if not c:
            continue
        if not CONTROL.match(c):
            raise EvidenceError(f"Bad control reference: {c[:40]}")
        fw, ctl = c.split(":", 1)
        if fw not in frameworks or ctl not in {x for x, _ in frameworks[fw]["controls"]}:
            raise EvidenceError(f"Unknown control: {c}")
        out.append(c)
    if len(out) > 50:
        raise EvidenceError("At most 50 controls per file")
    return sorted(set(out))


def check_date(d):
    if d in (None, ""):
        return None
    if not DATE.match(d):
        raise EvidenceError("Dates look like 2026-12-31")
    time.strptime(d, "%Y-%m-%d")
    return d


def state(meta, today=None):
    today = today or time.strftime("%Y-%m-%d")
    v = meta.get("valid_until")
    if not v:
        return "valid"
    if v < today:
        return "expired"
    soon = time.strftime("%Y-%m-%d", time.localtime(time.time() + 30 * 86400))
    return "expiring" if v <= soon else "valid"


class Store:
    def __init__(self, vault, folder):
        self.vault = vault
        self.dir = Path(folder)

    def _path(self, eid):
        if not ID.match(eid or ""):
            raise EvidenceError("Unknown evidence")
        return self.dir / f"{eid}.bin"

    def list(self):
        return sorted(self.vault.load_records(KIND), key=lambda m: m["uploaded_at"], reverse=True)

    def get(self, eid):
        m = next((m for m in self.vault.load_records(KIND) if m["id"] == eid), None)
        if not m:
            raise EvidenceError("Unknown evidence")
        return m

    def add(self, name, data, by, controls, valid_until, note=""):
        name = clean_name(name)
        if not data:
            raise EvidenceError("The file is empty")
        if len(data) > MAX_BYTES:
            raise EvidenceError("Files are limited to 10 MB")
        mime = detect(name, data)
        eid = "ev_" + secrets.token_hex(8)
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self._path(eid), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(wrap(self.vault.key(), data, f"evidence-file:{eid}".encode()))
        meta = {"id": eid, "name": name, "mime": mime, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                "uploaded_by": by, "uploaded_at": time.time(), "valid_until": valid_until, "controls": controls,
                "note": (note or "")[:300]}
        self.vault.save_record(eid, KIND, meta)
        return meta

    def update(self, eid, **fields):
        m = self.get(eid)
        m.update({k: v for k, v in fields.items() if k in ("controls", "valid_until", "note")})
        self.vault.save_record(eid, KIND, m)
        return m

    def read(self, eid):
        m = self.get(eid)
        try:
            data = unwrap(self.vault.key(), self._path(eid).read_bytes(), f"evidence-file:{eid}".encode())
        except (InvalidTag, ValueError, FileNotFoundError):
            raise EvidenceError("The stored file is missing or was changed outside Guardian")
        if hashlib.sha256(data).hexdigest() != m["sha256"]:
            raise EvidenceError("The stored file doesn't match its fingerprint")
        return m, data

    def delete(self, eid):
        m = self.get(eid)
        try:
            self._path(eid).unlink()
        except FileNotFoundError:
            pass
        self.vault.delete_record(eid)
        return m

    # -- your own status / note per control (kept across assessments) ---------------------------------------
    def overrides(self):
        return {f'{o["framework"]}:{o["control"]}': o for o in self.vault.load_records(OVERRIDE)}

    def set_override(self, framework, control, status, note, by):
        rid = "co_" + hashlib.sha256(f"{framework}:{control}".encode()).hexdigest()[:20]
        if status is None and not note:
            self.vault.delete_record(rid)
            return None
        o = {"framework": framework, "control": control, "status": status, "note": (note or "")[:500], "by": by, "at": time.time()}
        self.vault.save_record(rid, OVERRIDE, o)
        return o


def merge(fw_key, controls, overrides, evidence, open_findings):
    """Add the organisation's status, notes and evidence to the agent's view of one framework.

    A control the agent marked gap / partial because of findings that are still open keeps that status: evidence
    and notes are added, but "met" can't hide an open finding."""
    by_ctl = {}
    for e in evidence:
        for ref in e.get("controls", []):
            if ref.startswith(fw_key + ":"):
                by_ctl.setdefault(ref.split(":", 1)[1], []).append(e)
    out = []
    for c in controls:
        c = dict(c)
        c["agent_status"] = c["status"]
        ev = [{k: e[k] for k in ("id", "name", "size", "sha256", "uploaded_by", "uploaded_at", "valid_until")} | {"state": state(e)}
              for e in by_ctl.get(c["id"], [])]
        c["evidence"] = ev
        o = overrides.get(f"{fw_key}:{c['id']}")
        c["override"] = o
        blocking = [f for f in c.get("findings", []) if f in open_findings]
        if o and o.get("status"):
            if o["status"] in ("met", "not_assessed") and c["status"] in ("gap", "partial") and blocking:
                c["blocked"] = blocking
            else:
                c["status"] = o["status"]
                c["source"] = "organisation"
        elif ev and c["status"] == "not_assessed" and any(e["state"] != "expired" for e in ev):
            c["status"], c["source"] = "partial", "evidence"      # evidence without a decision counts as partial
        out.append(c)
    return out
