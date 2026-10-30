"""Import findings from other scanners: Nessus, OpenVAS / Greenbone, Qualys, Rapid7 InsightVM and a generic CSV.

Every format is turned into the same plain finding (ip, port, title, severity, CVEs, evidence, fix). XML files are
refused when they declare a DTD or entities (the classic XXE and "billion laughs" attacks), and sizes are capped.
"""
import csv
import io
import ipaddress
import re
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
