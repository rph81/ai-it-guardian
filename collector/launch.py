#!/usr/bin/env python3
"""Starts the newest collector release whose signature (Guardian's job key, pinned at enrollment) and file hashes check
out; otherwise the version installed from the package. Runs at every service start."""
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

DATA = Path(os.environ.get("GUARDIAN_COLLECTOR_DATA", "/var/lib/guardian-collector"))
HERE = Path(__file__).resolve().parent


def pick():
    try:
        cur = (DATA / "release" / "current").read_text().strip()
        rel = DATA / "release" / cur
        meta = json.loads((rel / "release.json").read_text())
        key = json.loads((DATA / "state.json").read_text())["job_key"]
        if json.loads((DATA / "state.json").read_text()).get("updates", "auto") != "auto":
            return HERE
        sys.path.insert(0, str(rel))
        from guardian import release
        release.verify(meta["manifest"], meta["sig"], key)
        for p, h in meta["manifest"]["files"].items():
            if hashlib.sha256((rel / p).read_bytes()).hexdigest() != h:
                raise ValueError(f"{p} changed")
        sys.path.pop(0)
        return rel
    except Exception as e:                                   # noqa: BLE001 - any doubt: the installed version
        if (DATA / "release" / "current").exists():
            print(f"launcher: staying on the installed version ({e})", file=sys.stderr, flush=True)
        return HERE


if __name__ == "__main__":
    base = pick()
    os.execv(sys.executable, [sys.executable, str(base / "guardian_collector.py"), *sys.argv[1:]])
