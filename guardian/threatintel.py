"""Attacker groups from MITRE ATT&CK's public data, to say which known groups use the techniques of an attack path.

The enterprise ATT&CK bundle (STIX, about 50 MB) is downloaded from MITRE's GitHub at most once a week and reduced to
a small file: group ID, name, aliases and the techniques MITRE has seen the group use. Nothing about the customer is
sent anywhere; matching happens locally.
"""
import json
import os
import re
import threading
import time
import urllib.request
from pathlib import Path

URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
MAX_AGE = 7 * 86400
TECH = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_groups = None
_lock = threading.Lock()


def cache_path():
    base = Path(__file__).resolve().parent.parent
    return Path(os.environ.get("GUARDIAN_STATE_DIR", base / "console")) / "attack-groups.json"


def compact(bundle):
    """STIX bundle -> {group_id: {"name", "aliases", "techniques"}} (revoked and deprecated objects skipped)."""
    def ext_id(o):
        return next((r.get("external_id") for r in o.get("external_references") or [] if r.get("source_name") == "mitre-attack"), None)
    live = [o for o in bundle.get("objects") or [] if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    techs = {o["id"]: ext_id(o) for o in live if o.get("type") == "attack-pattern"}
    groups = {o["id"]: {"id": ext_id(o), "name": o.get("name"), "aliases": [a for a in o.get("aliases") or [] if a != o.get("name")][:8],
                        "techniques": set()} for o in live if o.get("type") == "intrusion-set"}
    for r in live:
        if r.get("type") == "relationship" and r.get("relationship_type") == "uses" and r.get("source_ref") in groups:
            t = techs.get(r.get("target_ref"))
            if t and TECH.match(t):
                groups[r["source_ref"]]["techniques"].add(t)
    return {g["id"]: {"name": g["name"], "aliases": g["aliases"], "techniques": sorted(g["techniques"])}
            for g in groups.values() if g["id"] and g["techniques"]}


def load(fetch=None):
    """The compact group table, from the cache or freshly built. {} when it can't be had (no network, no cache)."""
    global _groups
    with _lock:
        if _groups is not None:
            return _groups
        p = cache_path()
        fresh = p.exists() and time.time() - p.stat().st_mtime < MAX_AGE
        if not fresh:
            try:
                raw = fetch() if fetch else urllib.request.urlopen(
                    urllib.request.Request(URL, headers={"User-Agent": "ai-guardian"}), timeout=120).read(120 * 2**20)
                table = compact(json.loads(raw))
                if len(table) > 20 or fetch:
                    p.parent.mkdir(parents=True, exist_ok=True)
                    tmp = p.with_suffix(".tmp")
                    tmp.write_text(json.dumps({"fetched": int(time.time()), "groups": table}))
                    os.replace(tmp, p)
            except Exception:                                    # noqa: BLE001 - an old cache is better than nothing
                pass
        try:
            _groups = json.loads(p.read_text())["groups"]
        except (OSError, ValueError, KeyError):
            _groups = {}
        return _groups


def match(techniques, top=5, minimum=2):
    """Groups that use the most of these techniques. A sub-technique also counts for its parent and the other way round."""
    want = {t for t in techniques if TECH.match(t or "")}
    if not want:
        return []
    out = []
    for gid, g in load().items():
        have = set(g["techniques"])
        have_parents = {t.split(".")[0] for t in have}
        hit = sorted(t for t in want if t in have or t.split(".")[0] in have_parents)
        if len(hit) >= minimum:
            out.append({"group": g["name"], "id": gid, "aliases": g["aliases"][:4], "matched": hit, "of": len(want)})
    out.sort(key=lambda x: (-len(x["matched"]), x["group"]))
    return out[:top]
