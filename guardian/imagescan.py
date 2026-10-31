"""Container image check: what's inside an image, without running it.

The image is read straight from its registry (Registry HTTP API v2, anonymous or with a pull token you give). Layers
are streamed and decompressed in memory; only package lists are kept: Debian/Ubuntu (dpkg), Alpine (apk), Python
(dist-info) and npm (package.json). Packages are checked against OSV; the image config is checked for root, secrets in
environment variables and an out-of-support base OS. Nothing is written to disk and nothing is executed.
"""
import base64
import io
import json
import re
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "AI-IT-Guardian-imagecheck/1.0"
MAX_TOTAL = 1536 * 2**20            # compressed bytes read across all layers
MAX_FILE = 8 * 2**20
REF = re.compile(r"^(?:(?P<reg>[a-z0-9.-]+(?::\d+)?)/)?(?P<repo>[a-z0-9]+(?:[._/-][a-z0-9]+)*)(?::(?P<tag>[\w][\w.-]{0,127}))?(?:@(?P<digest>sha256:[0-9a-f]{64}))?$")
ACCEPT = ", ".join(["application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"])
EOL = {("debian", "9"), ("debian", "10"), ("ubuntu", "14.04"), ("ubuntu", "16.04"), ("ubuntu", "18.04"), ("ubuntu", "20.04"),
       ("alpine", "3.15"), ("alpine", "3.16"), ("alpine", "3.17"), ("alpine", "3.18"), ("centos", "7"), ("centos", "8")}
SECRET_ENV = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)", re.I)


class ImageError(Exception):
    pass


def parse_ref(ref):
    m = REF.match((ref or "").strip().lower())
    if not m:
        raise ImageError("Give an image like nginx:1.27, ghcr.io/org/app:2.1 or registry.example.com/team/api@sha256:…")
    reg, repo = m["reg"], m["repo"]
    if not reg or "." not in reg and ":" not in reg and reg != "localhost":
        repo = f"{reg}/{repo}" if reg else repo
        reg = "registry-1.docker.io"
        if "/" not in repo:
            repo = "library/" + repo
    return reg, repo, m["digest"] or m["tag"] or "latest"


class Registry:
    def __init__(self, reg, repo, user=None, token=None):
        self.reg, self.repo, self.auth, self.bearer = reg, repo, (user, token) if token else None, None
        self.read = 0

    def _open(self, url, accept=None):
        for attempt in (0, 1):
            req = urllib.request.Request(url, headers={"User-Agent": UA, **({"Accept": accept} if accept else {})})
            if self.bearer:
                req.add_unredirected_header("Authorization", f"Bearer {self.bearer}")   # never sent on to a CDN redirect
            try:
                return urllib.request.urlopen(req, timeout=60)
            except urllib.error.HTTPError as e:
                if e.code == 401 and attempt == 0:
                    self._login(e.headers.get("www-authenticate") or "")
                    continue
                if e.code in (401, 403):
                    raise ImageError("The registry refused access: private image? Give a pull token.")
                if e.code == 404:
                    raise ImageError("Image or tag not found")
                raise ImageError(f"Registry error {e.code}")
            except (urllib.error.URLError, OSError) as e:
                raise ImageError(f"Registry unreachable: {getattr(e, 'reason', e)}")

    def _login(self, challenge):
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = params.get("realm", "")
        if not challenge.lower().startswith("bearer") or not realm.startswith("https://"):
            raise ImageError("The registry asks for a sign-in Guardian doesn't support")
        q = {"service": params.get("service", ""), "scope": params.get("scope") or f"repository:{self.repo}:pull"}
        req = urllib.request.Request(realm + "?" + urllib.parse.urlencode(q), headers={"User-Agent": UA})
        if self.auth:
            req.add_header("Authorization", "Basic " + base64.b64encode(f"{self.auth[0] or 'token'}:{self.auth[1]}".encode()).decode())
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                d = json.loads(r.read(200000))
        except (urllib.error.URLError, OSError, ValueError):
            raise ImageError("The registry's token service refused the sign-in")
        self.bearer = d.get("token") or d.get("access_token")
        if not self.bearer:
            raise ImageError("No pull token from the registry")

    def json(self, path, accept=None):
        with self._open(f"https://{self.reg}/v2/{self.repo}/{path}", accept) as r:
            return json.loads(r.read(4 * 2**20)), r.headers.get("content-type", "")

    def blob(self, digest):
        return self._open(f"https://{self.reg}/v2/{self.repo}/blobs/{digest}")


class _Counted(io.RawIOBase):
    def __init__(self, resp, reg):
        self.resp, self.reg = resp, reg

    def readable(self):
        return True

    def readinto(self, b):
        n = self.resp.readinto(b)
        self.reg.read += n or 0
        if self.reg.read > MAX_TOTAL:
            raise ImageError("The image is larger than 1.5 GB compressed; not checked")
        return n


def _wanted(name):
    n = name.lstrip("./")
    return (n in ("etc/os-release", "usr/lib/os-release", "var/lib/dpkg/status", "lib/apk/db/installed")
            or n.startswith("var/lib/dpkg/status.d/")
            or (n.endswith(".dist-info/METADATA") and "site-packages/" in n)
            or re.search(r"(^|/)node_modules/(@[^/]+/)?[^/]+/package\.json$", n) is not None)


def _dpkg(text):
    out = []
    for block in text.split("\n\n"):
        f = dict(re.findall(r"^([A-Za-z-]+): ?(.*)$", block, re.M))
        if not f.get("Package") or "installed" not in f.get("Status", "install ok installed"):
            continue
        src = (f.get("Source") or f["Package"]).split(" ")[0]
        m = re.search(r"\(([^)]+)\)", f.get("Source", ""))
        out.append((src, m.group(1) if m else f.get("Version", ""), f["Package"]))
    return out


def _apk(text):
    out = []
    for block in text.split("\n\n"):
        f = dict(re.findall(r"^([A-Za-z]):(.*)$", block, re.M))
        if f.get("P"):
            out.append((f.get("o") or f["P"], f.get("V", ""), f["P"]))
    return out


def scan(ref, user=None, token=None, progress=None, osv=None):
    """Returns {image, digest, os, packages, findings}. osv(queries) -> list of vuln-id lists (injected for tests)."""
    progress = progress or (lambda **k: None)
    reg, repo, tag = parse_ref(ref)
    r = Registry(reg, repo, user, token)
    progress(stage="manifest")
    man, ctype = r.json(f"manifests/{tag}", ACCEPT)
    if "manifests" in man:
        pick = next((m for m in man["manifests"] if (m.get("platform") or {}).get("os") == "linux"
                     and (m.get("platform") or {}).get("architecture") == "amd64"), None) or \
               next((m for m in man["manifests"] if (m.get("platform") or {}).get("os") == "linux"), None)
        if not pick:
            raise ImageError("No Linux image in this manifest list")
        digest = pick["digest"]
        man, _ = r.json(f"manifests/{digest}", ACCEPT)
    else:
        digest = tag if tag.startswith("sha256:") else None
    if "layers" not in man or "config" not in man:
        raise ImageError("Unsupported manifest format")
    cfg_resp = r.blob(man["config"]["digest"])
    cfg = json.loads(cfg_resp.read(4 * 2**20))
    files = {}
    for i, layer in enumerate(man["layers"], 1):
        progress(stage="layers", layer=i, layers=len(man["layers"]), mb=round(r.read / 2**20))
        resp = r.blob(layer["digest"])
        if "zstd" in layer.get("mediaType", ""):
            resp.close()
            raise ImageError(f"Layer {i} is zstd-compressed; not supported yet")
        try:
            with tarfile.open(fileobj=io.BufferedReader(_Counted(resp, r), 1 << 20), mode="r|*") as tar:
                for m in tar:
                    name = m.name.lstrip("./")
                    base = name.rsplit("/", 1)[-1]
                    if base.startswith(".wh."):
                        files.pop(name.rsplit("/", 1)[0] + "/" + base[4:], None)
                        continue
                    if m.isreg() and m.size <= MAX_FILE and _wanted(name):
                        f = tar.extractfile(m)
                        files[name] = f.read().decode("utf-8", "replace") if f else ""
        except tarfile.ReadError:
            raise ImageError(f"Layer {i} isn't a readable tar archive (zstd layers aren't supported yet)")
        finally:
            resp.close()
    progress(stage="packages")
    osr = dict(re.findall(r'^(\w+)="?([^"\n]*)"?$', files.get("etc/os-release") or files.get("usr/lib/os-release") or "", re.M))
    os_id, os_ver = osr.get("ID", "").lower(), osr.get("VERSION_ID", "")
    eco = None
    if os_id == "debian" and os_ver:
        eco = f"Debian:{os_ver.split('.')[0]}"
    elif os_id == "ubuntu" and os_ver:
        eco = f"Ubuntu:{os_ver}" + (":LTS" if os_ver.endswith(".04") and int(os_ver.split(".")[0]) % 2 == 0 else "")
    elif os_id == "alpine" and os_ver:
        eco = "Alpine:v" + ".".join(os_ver.split(".")[:2])
    pkgs = []
    for name, text in files.items():
        if name == "var/lib/dpkg/status" or name.startswith("var/lib/dpkg/status.d/"):
            pkgs += [(eco, s, v, p) for s, v, p in _dpkg(text)]
        elif name == "lib/apk/db/installed":
            pkgs += [(eco, s, v, p) for s, v, p in _apk(text)]
        elif name.endswith("METADATA"):
            n, v = re.search(r"^Name: (.+)$", text, re.M), re.search(r"^Version: (.+)$", text, re.M)
            if n and v:
                pkgs.append(("PyPI", n.group(1).strip(), v.group(1).strip(), n.group(1).strip()))
        else:
            try:
                pj = json.loads(text)
                if pj.get("name") and pj.get("version"):
                    pkgs.append(("npm", pj["name"], pj["version"], pj["name"]))
            except ValueError:
                pass
    pkgs = sorted({p for p in pkgs if p[0] and p[2]})
    findings = []
    conf = cfg.get("config") or {}
    user_ = (conf.get("User") or "").split(":")[0]
    if user_ in ("", "root", "0"):
        findings.append({"title": "Container runs as root", "severity": "medium", "urls": [], "evidence": f"Image config User: {conf.get('User') or '(not set)'}",
                         "recommendation": "Build the image with a non-root USER, or set runAsNonRoot in Kubernetes."})
    secrets_ = [e.split("=", 1)[0] for e in conf.get("Env") or [] if SECRET_ENV.search(e.split("=", 1)[0]) and len(e.split("=", 1)[-1]) >= 4]
    if secrets_:
        findings.append({"title": "Secrets baked into the image's environment", "severity": "high", "urls": [],
                         "evidence": "Variables: " + ", ".join(secrets_[:10]) + " (values not shown)",
                         "recommendation": "Remove secrets from the image; pass them at run time and rotate the ones that were shipped."})
    if (os_id, os_ver.split(".")[0] if os_id in ("debian", "centos") else ".".join(os_ver.split(".")[:2])) in EOL:
        findings.append({"title": f"Base OS out of support ({osr.get('PRETTY_NAME', os_id + ' ' + os_ver)})", "severity": "high", "urls": [],
                         "evidence": "The base image's OS no longer receives security updates.", "recommendation": "Rebuild on a supported base image."})
    created = cfg.get("created") or ""
    if created[:4].isdigit() and time.time() - time.mktime(time.strptime(created[:10], "%Y-%m-%d")) > 365 * 86400:
        findings.append({"title": "Image is more than a year old", "severity": "low", "urls": [], "evidence": f"Built {created[:10]}",
                         "recommendation": "Rebuild regularly so base-image security updates get in."})
    if pkgs and osv:
        progress(stage="osv", packages=len(pkgs))
        vulns = osv([{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v, _ in pkgs])
        hit = sorted(((len(ids), p, ids) for p, ids in zip(pkgs, vulns) if ids), key=lambda x: -x[0])
        mal = [(p, ids) for _, p, ids in hit if any(i.startswith("MAL-") for i in ids)]
        for p, ids in mal:
            findings.append({"title": f"Known malicious package {p[1]} {p[2]}", "severity": "critical", "urls": [],
                             "evidence": ", ".join(ids[:5]), "recommendation": "Remove the package, rebuild, and treat systems that ran it as compromised."})
        for n, p, ids in hit[:40]:
            if any(i.startswith("MAL-") for i in ids):
                continue
            findings.append({"title": f"{p[1]} {p[2]} has {n} known vulnerabilit{'y' if n == 1 else 'ies'}", "severity": "high" if n >= 5 else "medium",
                             "urls": [], "evidence": f"{p[0]} package {p[3]}: " + ", ".join(ids[:12]) + (" …" if n > 12 else ""),
                             "recommendation": "Rebuild on an updated base image or upgrade the package."})
        if len(hit) > 40:
            findings.append({"title": f"{len(hit) - 40} more packages with known vulnerabilities", "severity": "low", "urls": [], "evidence": "",
                             "recommendation": "Rebuild on a current base image; most go away with an update."})
    order = ["critical", "high", "medium", "low", "info"]
    findings.sort(key=lambda f: order.index(f["severity"]))
    return {"image": f"{reg}/{repo}:{tag}" if not tag.startswith("sha256:") else f"{reg}/{repo}@{tag}", "digest": digest,
            "os": osr.get("PRETTY_NAME") or (f"{os_id} {os_ver}".strip() or "unknown"), "packages": len(pkgs), "user": conf.get("User") or "",
            "layers": len(man["layers"]), "mb": round(r.read / 2**20, 1), "findings": findings,
            "counts": {s: sum(1 for f in findings if f["severity"] == s) for s in order}}


def osv_batch(queries):
    """OSV querybatch in chunks; returns one list of vulnerability IDs per query."""
    out = []
    for i in range(0, len(queries), 500):
        chunk = queries[i:i + 500]
        req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=json.dumps({"queries": chunk}).encode(),
                                     headers={"Content-Type": "application/json", "User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                res = json.loads(r.read(32 * 2**20)).get("results") or []
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise ImageError(f"OSV unreachable: {getattr(e, 'reason', e)}")
        out += [[v["id"] for v in (x.get("vulns") or [])] for x in res] + [[]] * (len(chunk) - len(res))
    return out
