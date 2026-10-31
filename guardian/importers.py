"""Import findings from other scanners: Nessus, OpenVAS / Greenbone, Qualys, Rapid7 InsightVM and a generic CSV.

Every format is turned into the same plain finding (ip, port, title, severity, CVEs, evidence, fix). XML files are
refused when they declare a DTD or entities (the classic XXE and "billion laughs" attacks), and sizes are capped.
"""
import csv
import io
import ipaddress
import re
import urllib.request
import xml.etree.ElementTree as ET

MAX_BYTES = 50 * 1024 * 1024
MAX_FINDINGS = 20000
CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SEVERITIES = ("critical", "high", "medium", "low", "info")
FORMATS = {"nessus": "Nessus", "openvas": "OpenVAS / Greenbone", "qualys": "Qualys", "rapid7": "Rapid7 InsightVM", "csv": "CSV"}


class ImportError_(ValueError):
    pass


def _xml(data):
    head = data[:4096].decode("utf-8", "replace").lower()
    if "<!doctype" in head or "<!entity" in data.decode("utf-8", "replace").lower():
        raise ImportError_("XML files with a DTD or entities are refused")
    try:
        return ET.fromstring(data)
    except ET.ParseError as e:
        raise ImportError_(f"Not valid XML: {e}")


def _ip(text):
    try:
        return str(ipaddress.ip_address((text or "").strip()))
    except ValueError:
        return None


def _t(el, path):
    x = el.find(path)
    return (x.text or "").strip() if x is not None and x.text else ""


def _sev_cvss(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low" if s > 0 else "info"


def _finding(ip, port, title, severity, cves, evidence, fix, ref, source):
    return {"ip": ip, "port": port, "title": (title or "Untitled finding")[:200], "severity": severity if severity in SEVERITIES else "medium",
            "cves": sorted({c.upper() for c in cves})[:30], "evidence": (evidence or "")[:3000], "recommendation": (fix or "")[:1500],
            "ref": str(ref or "")[:60], "source": source}


def nessus(root):
    out = []
    for host in root.iter("ReportHost"):
        ip = _ip(next((t.text for t in host.iter("tag") if t.get("name") == "host-ip"), None) or host.get("name"))
        for it in host.iter("ReportItem"):
            sev = {"4": "critical", "3": "high", "2": "medium", "1": "low", "0": "info"}.get(it.get("severity", "0"), "info")
            if sev == "info":
                continue
            port = f'{it.get("port")}/{it.get("protocol")}' if it.get("port") not in (None, "0") else None
            cves = [c.text for c in it.findall("cve") if c.text]
            ev = " ".join(x for x in (_t(it, "synopsis"), _t(it, "plugin_output")[:1500]) if x)
            out.append(_finding(ip, port, it.get("pluginName"), sev, cves, ev, _t(it, "solution"), f'Nessus {it.get("pluginID")}', "Nessus"))
    return out


def openvas(root):
    out = []
    for r in root.iter("result"):
        nvt = r.find("nvt")
        if nvt is None:
            continue
        threat = _t(r, "threat").lower()
        sev = {"high": "high", "medium": "medium", "low": "low", "log": "info", "critical": "critical"}.get(threat) or _sev_cvss(_t(r, "severity")) or "medium"
        if _sev_cvss(_t(r, "severity")) == "critical":
            sev = "critical"
        if sev == "info":
            continue
        cves = [ref.get("id") for ref in nvt.iter("ref") if (ref.get("type") or "").lower() == "cve"] + CVE.findall(_t(nvt, "cve"))
        out.append(_finding(_ip(_t(r, "host").split()[0] if _t(r, "host") else ""), _t(r, "port") or None, _t(nvt, "name") or _t(r, "name"), sev,
                            cves, _t(r, "description"), _t(nvt, "solution"), f'OpenVAS {nvt.get("oid")}', "OpenVAS"))
    return out


def qualys(root):
    out = []
    for ipel in root.iter("IP"):
        ip = _ip(ipel.get("value"))
        for section in ("VULNS", "PRACTICES"):
            for cat in ipel.findall(f"{section}/CAT"):
                port = f'{cat.get("port")}/{cat.get("protocol")}' if cat.get("port") else None
                for v in cat.findall("VULN"):
                    sev = {"5": "critical", "4": "high", "3": "medium", "2": "low", "1": "low"}.get(v.get("severity", "3"), "medium")
                    cves = [c.text for c in v.iter("ID") if c.text and CVE.match(c.text)]
                    out.append(_finding(ip, port, _t(v, "TITLE"), sev, cves, " ".join(x for x in (_t(v, "DIAGNOSIS"), _t(v, "RESULT")[:1500]) if x),
                                        _t(v, "SOLUTION"), f'Qualys QID {v.get("number")}', "Qualys"))
    return out


def rapid7(root):
    defs = {}
    for v in root.iter("vulnerability"):
        cves = [r.text for r in v.iter("reference") if (r.get("source") or "").upper() == "CVE" and r.text]
        level = int(v.get("severity", "0") or 0)                  # Rapid7: 1-3 moderate, 4-7 severe, 8-10 critical
        sev = _sev_cvss(v.get("cvssScore")) or ("critical" if level >= 8 else "high" if level >= 4 else "medium")
        text = lambda tag: " ".join(" ".join(" ".join(x.itertext()).split()) for x in v.findall(tag))[:2000]
        defs[(v.get("id") or "").lower()] = (v.get("title"), sev, cves, text("description"), text("solution"))
    out = []
    for node in root.iter("node"):
        ip = _ip(node.get("address"))
        tests = [(None, t) for t in node.findall("tests/test")]
        for ep in node.iter("endpoint"):
            tests += [(f'{ep.get("port")}/{ep.get("protocol")}', t) for t in ep.iter("test")]
        for port, t in tests:
            if not (t.get("status") or "").startswith("vulnerable"):
                continue
            title, sev, cves, desc, fix = defs.get((t.get("id") or "").lower(), (t.get("id"), "medium", [], "", ""))
            out.append(_finding(ip, port, title, sev, cves, desc + (" (exploited)" if "exploited" in t.get("status", "") else ""), fix,
                                f'Rapid7 {t.get("id")}', "Rapid7"))
    return out


CSV_COLS = {"ip": ("ip", "ip address", "host", "asset", "address", "host ip"), "title": ("title", "name", "vulnerability", "finding", "plugin name"),
            "severity": ("severity", "risk", "risk level"), "cve": ("cve", "cves", "cve id"), "port": ("port",),
            "evidence": ("description", "evidence", "details", "synopsis", "output"), "fix": ("solution", "fix", "remediation", "recommendation")}


def from_csv(data):
    text = data.decode("utf-8-sig", "replace")
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        raise ImportError_("The CSV is empty")
    head = [h.strip().lower() for h in rows[0]]
    col = {k: next((i for i, h in enumerate(head) if h in names), None) for k, names in CSV_COLS.items()}
    if col["ip"] is None or col["title"] is None:
        raise ImportError_("The CSV needs at least an IP column (ip / host / asset) and a title column (title / name / vulnerability)")
    get = lambda r, k: r[col[k]].strip() if col[k] is not None and col[k] < len(r) else ""
    out = []
    for r in rows[1:]:
        if not any(x.strip() for x in r):
            continue
        sev = get(r, "severity").lower()
        sev = sev if sev in SEVERITIES else (_sev_cvss(sev) or {"moderate": "medium", "severe": "high", "important": "high", "none": "info"}.get(sev, "medium"))
        if sev == "info":
            continue
        out.append(_finding(_ip(get(r, "ip")), get(r, "port") or None, get(r, "title"), sev, CVE.findall(get(r, "cve") + " " + get(r, "evidence")),
                            get(r, "evidence"), get(r, "fix"), "CSV", "CSV"))
    return out


def parse(name, data):
    """Returns (format, findings). The format is decided by the content, not the file name."""
    if not data:
        raise ImportError_("The file is empty")
    if len(data) > MAX_BYTES:
        raise ImportError_("Files are limited to 50 MB")
    head = data[:2048].lstrip()
    if head.startswith(b"<"):
        root = _xml(data)
        tag = root.tag.split("}")[-1]
        if tag == "NessusClientData_v2":
            fmt, rows = "nessus", nessus(root)
        elif tag == "NexposeReport":
            fmt, rows = "rapid7", rapid7(root)
        elif tag in ("SCAN", "ASSET_DATA_REPORT") or root.find(".//IP") is not None:
            fmt, rows = "qualys", qualys(root)
        elif root.find(".//result/nvt") is not None or tag in ("report", "get_reports_response"):
            fmt, rows = "openvas", openvas(root)
        else:
            raise ImportError_("Unknown XML report: Guardian reads Nessus (.nessus), OpenVAS / Greenbone, Qualys and Rapid7 XML")
    elif name.lower().endswith(".csv") or b"," in head.split(b"\n", 1)[0]:
        fmt, rows = "csv", from_csv(data)
    else:
        raise ImportError_("Unknown file: use a Nessus, OpenVAS, Qualys or Rapid7 XML export, or a CSV")
    if len(rows) > MAX_FINDINGS:
        raise ImportError_(f"More than {MAX_FINDINGS} findings: export a smaller scope")
    return fmt, rows


# -- pulling from a scanner's API through a connector (Tenable, Qualys, Rapid7 InsightVM) ------------------------------
PULL_TYPES = {"tenable": "Tenable Vulnerability Management", "qualys": "Qualys VMDR", "rapid7": "Rapid7 InsightVM"}
FORMATS.update({"tenable": "Tenable (API)", "qualys_api": "Qualys (API)", "rapid7_api": "Rapid7 InsightVM (API)"})
TENABLE = "https://cloud.tenable.com"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def _api(method, url, headers=None, body=None, ctx=None, timeout=60, limit=60 * 2**20):
    import json
    import ssl
    import urllib.error
    h = {"User-Agent": "ai-guardian", **(headers or {})}
    data = None
    if body is not None:
        data, h["Content-Type"] = json.dumps(body).encode(), "application/json"
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx or ssl.create_default_context()))
    try:
        with opener.open(urllib.request.Request(url, data=data, headers=h, method=method), timeout=timeout) as r:
            raw = r.read(limit + 1)
            if len(raw) > limit:
                raise ImportError_("The scanner's answer is too large: limit the user to fewer assets")
            return r.status, raw
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise ImportError_("The scanner refused the credentials (check the user, its role and API access)")
        raise ImportError_(f"The scanner answered {e.code}")
    except (urllib.error.URLError, OSError) as e:
        raise ImportError_(f"Can't reach the scanner: {getattr(e, 'reason', e)}")


def _json(raw):
    import json
    try:
        return json.loads(raw.decode() or "null")
    except ValueError:
        raise ImportError_("The scanner returned something that isn't JSON")


def _xml_api(raw):
    """Qualys answers carry an external DOCTYPE line (no internal subset): drop it; anything with entities is still refused."""
    text = raw.decode("utf-8", "replace")
    if "<!entity" in text.lower() or re.search(r"<!DOCTYPE[^>]*\[", text, re.I):
        raise ImportError_("XML with a DTD subset or entities is refused")
    return _xml(re.sub(r"<!DOCTYPE[^>\[]*>", "", text, count=1).encode())


def pull_tenable(f, wait=300, sleep=5):
    import time
    h = {"X-ApiKeys": f"accessKey={f['access_key']};secretKey={f['secret_key']}", "Accept": "application/json"}
    _, raw = _api("POST", f"{TENABLE}/vulns/export", h, {"num_assets": 500, "filters": {
        "severity": ["medium", "high", "critical"], "state": ["OPEN", "REOPENED"]}})
    uuid = (_json(raw) or {}).get("export_uuid", "")
    if not re.fullmatch(r"[0-9a-fA-F-]{20,64}", uuid):
        raise ImportError_("Tenable didn't start the export")
    end = time.time() + wait
    while True:
        st = _json(_api("GET", f"{TENABLE}/vulns/export/{uuid}/status", h)[1]) or {}
        if st.get("status") == "FINISHED":
            break
        if st.get("status") in ("ERROR", "CANCELLED") or time.time() > end:
            raise ImportError_(f"Tenable's export didn't finish ({st.get('status') or 'timed out'})")
        time.sleep(sleep)
    out = []
    for chunk in (st.get("chunks_available") or [])[:200]:
        for v in _json(_api("GET", f"{TENABLE}/vulns/export/{uuid}/chunks/{int(chunk)}", h)[1]) or []:
            a, p, pl = v.get("asset") or {}, v.get("port") or {}, v.get("plugin") or {}
            port = f"{p['port']}/{p.get('protocol', 'tcp').lower()}" if p.get("port") else None
            sev = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(str(v.get("severity")).lower(), "medium")
            out.append(_finding(_ip(a.get("ipv4") or (a.get("ipv4s") or [None])[0]), port, pl.get("name"), sev, pl.get("cve") or [],
                                " ".join(x for x in (pl.get("synopsis") or "", (v.get("output") or "")[:1500]) if x),
                                pl.get("solution"), f"Tenable {pl.get('id')}", "Tenable"))
            if len(out) >= MAX_FINDINGS:
                return out
    return out


def pull_qualys(f):
    import base64
    import urllib.parse
    server = (f.get("api_server") or "").strip().removeprefix("https://").rstrip("/")
    if not re.fullmatch(r"qualysapi\.[a-z0-9.-]+\.(?:com|eu|ae|in|ca|au|uk|net)|[a-z0-9.-]+\.qualys\.(?:com|eu)", server):
        raise ImportError_("The API server must be your Qualys API address, e.g. qualysapi.qg2.apps.qualys.eu")
    h = {"X-Requested-With": "ai-guardian", "Authorization": "Basic " + base64.b64encode(f"{f['username']}:{f['password']}".encode()).decode()}
    url = (f"https://{server}/api/2.0/fo/asset/host/vm/detection/?action=list&show_results=1&severities=3-5"
           "&status=New,Active,Re-Opened&truncation_limit=1000")
    dets = []
    for _ in range(10):
        root = _xml_api(_api("GET", url, h)[1])
        for host in root.iter("HOST"):
            ip = _ip(_t(host, "IP"))
            for d in host.iter("DETECTION"):
                if (_t(d, "TYPE") or "Confirmed") != "Confirmed":
                    continue
                dets.append((ip, _t(d, "QID"), _t(d, "SEVERITY"), _t(d, "PORT"), _t(d, "PROTOCOL"), _t(d, "RESULTS")))
        nxt = root.find(".//WARNING/URL")
        if nxt is None or not nxt.text or len(dets) >= MAX_FINDINGS:
            break
        url = nxt.text.strip()
        if urllib.parse.urlsplit(url).hostname != server:
            break
    kb = {}
    qids = sorted({q for _, q, *_ in dets if q and q.isdigit()})
    for i in range(0, len(qids), 300):
        root = _xml_api(_api("GET", f"https://{server}/api/2.0/fo/knowledge_base/vuln/?action=list&ids={','.join(qids[i:i + 300])}", h)[1])
        for v in root.iter("VULN"):
            kb[_t(v, "QID")] = (_t(v, "TITLE"), [c.text for c in v.iter("ID") if c.text and CVE.match(c.text)], _t(v, "SOLUTION"))
    out = []
    for ip, qid, sev, port, proto, res in dets[:MAX_FINDINGS]:
        title, cves, fix = kb.get(qid, (f"Qualys QID {qid}", [], ""))
        out.append(_finding(ip, f"{port}/{(proto or 'tcp').lower()}" if port else None, title,
                            {"5": "critical", "4": "high", "3": "medium"}.get(sev, "medium"), cves, (res or "")[:1500],
                            re.sub(r"<[^>]+>", " ", fix or "")[:1500], f"Qualys QID {qid}", "Qualys"))
    return out


def pull_rapid7(f, ctx):
    import base64
    base = f"https://{f['host']}:{int(f.get('port') or 3780)}/api/3"
    h = {"Accept": "application/json", "Authorization": "Basic " + base64.b64encode(f"{f['username']}:{f['password']}".encode()).decode()}
    assets, page = [], 0
    while page < 10:
        d = _json(_api("GET", f"{base}/assets?page={page}&size=500", h, ctx=ctx)[1]) or {}
        assets += d.get("resources") or []
        page += 1
        if page >= ((d.get("page") or {}).get("totalPages") or 0):
            break
    details, out = {}, []
    for a in assets[:1000]:
        ip = _ip(a.get("ip"))
        vd = _json(_api("GET", f"{base}/assets/{int(a['id'])}/vulnerabilities?size=500", h, ctx=ctx)[1]) or {}
        for v in vd.get("resources") or []:
            vid = str(v.get("id") or "")
            if not re.fullmatch(r"[\w.-]{1,200}", vid):
                continue
            if vid not in details and len(details) < 3000:
                x = _json(_api("GET", f"{base}/vulnerabilities/{vid}", h, ctx=ctx)[1]) or {}
                score = ((x.get("cvss") or {}).get("v3") or {}).get("score") or ((x.get("cvss") or {}).get("v2") or {}).get("score")
                details[vid] = (x.get("title") or vid, _sev_cvss(score) or {"Critical": "critical", "Severe": "high", "Moderate": "medium"}.get(x.get("severity"), "medium"),
                                x.get("cves") or [], ((x.get("description") or {}).get("text") or "")[:800])
            title, sev, cves, desc = details.get(vid, (vid, "medium", [], ""))
            if sev in ("low", "info"):
                continue
            res = (v.get("results") or [{}])[0]
            port = f"{res['port']}/{res.get('protocol', 'tcp')}" if res.get("port") else None
            proof = re.sub(r"<[^>]+>", " ", res.get("proof") or "")[:1200]
            out.append(_finding(ip, port, title, sev, cves, " ".join(x for x in (desc, proof) if x),
                                f"See the solution for {vid} in InsightVM.", f"Rapid7 {vid}", "Rapid7 InsightVM"))
            if len(out) >= MAX_FINDINGS:
                return out
    return out


def pull(ctype, fields, ctx=None):
    """Returns (format, findings) read from a scanner connector."""
    if ctype == "tenable":
        return "tenable", pull_tenable(fields)
    if ctype == "qualys":
        return "qualys_api", pull_qualys(fields)
    if ctype == "rapid7":
        return "rapid7_api", pull_rapid7(fields, ctx)
    raise ImportError_("Not a scanner connector")


def test_scanner(ctype, fields, ctx=None):
    """A light read that proves the credentials work. Returns (level, message, details)."""
    import base64
    if ctype == "tenable":
        h = {"X-ApiKeys": f"accessKey={fields['access_key']};secretKey={fields['secret_key']}", "Accept": "application/json"}
        me = _json(_api("GET", f"{TENABLE}/session", h)[1]) or {}
        perm = int(me.get("permissions") or 0)
        det = [f"Signed in as {me.get('username', '?')}"]
        if perm > 24:
            det.append("This user can change things in Tenable (role above Scan Operator): use a Basic user.")
            return "warn", "Connected, with a warning", det
        return "ok", "Connected", det + ["Read-only role"]
    if ctype == "qualys":
        server = (fields.get("api_server") or "").strip().removeprefix("https://").rstrip("/")
        h = {"X-Requested-With": "ai-guardian", "Authorization": "Basic " + base64.b64encode(f"{fields['username']}:{fields['password']}".encode()).decode()}
        if not re.fullmatch(r"qualysapi\.[a-z0-9.-]+\.(?:com|eu|ae|in|ca|au|uk|net)|[a-z0-9.-]+\.qualys\.(?:com|eu)", server):
            raise ImportError_("The API server must be your Qualys API address, e.g. qualysapi.qg2.apps.qualys.eu")
        root = _xml_api(_api("GET", f"https://{server}/api/2.0/fo/asset/host/?action=list&truncation_limit=1", h)[1])
        return "ok", "Connected", [f"Host list readable ({len(list(root.iter('HOST')))} shown of the first page)",
                                   "Give the user the Reader role so it can't change scans or settings"]
    h = {"Accept": "application/json", "Authorization": "Basic " + base64.b64encode(f"{fields['username']}:{fields['password']}".encode()).decode()}
    d = _json(_api("GET", f"https://{fields['host']}:{int(fields.get('port') or 3780)}/api/3/assets?size=1", h, ctx=ctx)[1]) or {}
    return "ok", "Connected", [f"{(d.get('page') or {}).get('totalResources', '?')} assets readable",
                               "Use a role that can only view site and asset data"]
