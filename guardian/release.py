"""Signed collector releases (phase D): the console signs the collector's files with its job key; the gateway hands the
release out; the collector and its launcher accept it only with a valid signature and matching file hashes."""
import base64
import gzip
import hashlib
import json
import re
from pathlib import Path

FILES = ["guardian_collector.py", "launch.py", "guardian/__init__.py", "guardian/jobs.py", "guardian/access.py",
         "guardian/connectors.py", "guardian/codescan.py", "guardian/release.py"]
VERSION_RX = re.compile(r'^VERSION = "(\d+\.\d+\.\d+)"', re.M)


def canonical(manifest):
    return json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode()


def build(repo, key_path):
    """{"manifest": {version, files: {path: sha256}}, "sig": ..., "files": {path: base64(gzip)}} from the repository."""
    from cryptography.hazmat.primitives import serialization
    repo = Path(repo)
    src = {"guardian_collector.py": repo / "collector" / "guardian_collector.py", "launch.py": repo / "collector" / "launch.py",
           **{p: repo / p for p in FILES if p.startswith("guardian/")}}
    data = {p: src[p].read_bytes() for p in FILES}
    version = VERSION_RX.search(data["guardian_collector.py"].decode()).group(1)
    manifest = {"version": version, "files": {p: hashlib.sha256(b).hexdigest() for p, b in data.items()}}
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), None)
    return {"manifest": manifest, "sig": base64.urlsafe_b64encode(key.sign(canonical(manifest))).decode().rstrip("="),
            "files": {p: base64.b64encode(gzip.compress(b, 9)).decode() for p, b in data.items()}}


def verify(manifest, sig, pubkey_b64):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pad = lambda s: s + "=" * (-len(s) % 4)
    Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(pad(pubkey_b64))).verify(base64.urlsafe_b64decode(pad(sig)), canonical(manifest))
    if not re.fullmatch(r"\d+\.\d+\.\d+", manifest.get("version", "")) or set(manifest.get("files", {})) != set(FILES):
        raise ValueError("bad manifest")


def newer(a, b):
    return tuple(int(x) for x in a.split(".")) > tuple(int(x) for x in b.split("."))
