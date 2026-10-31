"""SIEM output: findings as events to Microsoft Sentinel, Splunk or syslog after each run.

Like the alert channels, the destinations' secrets are needed after scheduled runs when nobody is signed in, so they
are protected by the server's file permissions (console state), not the vault. Every destination is send-only: Guardian
never reads anything back from the SIEM.
"""
import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from .graph import is_open

DESTS = ("sentinel", "splunk", "syslog")
SECRET = {"sentinel": "client_secret", "splunk": "token", "syslog": None}
MAX_EVENTS = 5000


def events(graph_data, run_id, site_id, site_name, only_new=True):
    """One event per open finding (or per new finding when the run has a comparison), plus one run summary."""
    s = graph_data.get("summary") or {}
    ch = (graph_data.get("changes") or {}).get("findings")
    new_ids = {f.get("id") for f in (ch or {}).get("new", [])} if ch else None
    from . import attack
    out = [{"type": "run", "run": run_id, "site": site_id, "site_name": site_name, "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "score": s.get("score"), "grade": s.get("grade"),
            "open_findings": sum(1 for f in graph_data.get("findings") or [] if is_open(f))}]
    for f in graph_data.get("findings") or []:
        if not is_open(f) or (only_new and new_ids is not None and f.get("id") not in new_ids):
            continue
        r = f.get("risk") or {}
        out.append({"type": "finding", "run": run_id, "site": site_id, "site_name": site_name, "id": f.get("id"),
                    "title": f.get("title"), "severity": f.get("severity"), "priority": r.get("priority"),
                    "asset": f.get("asset"), "layer": f.get("layer"), "kev": bool(r.get("kev")), "epss": r.get("epss"),
                    "exposure": r.get("exposure"), "cves": f.get("cves") or r.get("cves") or [],
                    "attack": attack.techniques(f), "recommendation": (f.get("recommendation") or "")[:1000],
                    "first_seen": f.get("first_seen"), "source": f.get("source") or "guardian"})
        if len(out) > MAX_EVENTS:
            break
    return out


def _https(url):
    u = urllib.parse.urlsplit(url or "")
    if u.scheme != "https" or not u.hostname:
        raise ValueError("Addresses must start with https://")
    return url.rstrip("/")


def _post(url, body, headers, timeout=20):
    req = urllib.request.Request(url, data=body, method="POST", headers={"User-Agent": "AI-IT-Guardian", **headers})
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=timeout) as r:
            return r.status, r.read(2000)
    except urllib.error.HTTPError as e:
        return e.code, e.read(2000)
    except (urllib.error.URLError, OSError) as e:
        raise ValueError(f"unreachable: {getattr(e, 'reason', e)}")


def send_splunk(c, secret, evs):
    url = _https(c["url"]) + "/services/collector/event"
    body = "\n".join(json.dumps({"event": e, "sourcetype": f"guardian:{e['type']}", "source": "ai-it-guardian",
                                 **({"index": c["index"]} if c.get("index") else {})}) for e in evs).encode()
    st, data = _post(url, body, {"Authorization": f"Splunk {secret}", "Content-Type": "application/json"})
    if st != 200:
        raise ValueError(f"Splunk HEC answered {st}: {data[:200].decode(errors='replace')}")
    return len(evs)


def send_sentinel(c, secret, evs):
    """Azure Monitor Logs ingestion API (data collection endpoint + rule), the current way to feed Sentinel."""
    tok_body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": c["client_id"], "client_secret": secret,
                                       "scope": "https://monitor.azure.com/.default"}).encode()
    st, data = _post(f"https://login.microsoftonline.com/{urllib.parse.quote(c['tenant_id'])}/oauth2/v2.0/token", tok_body,
                     {"Content-Type": "application/x-www-form-urlencoded"})
    try:
        token = json.loads(data.decode())["access_token"] if st == 200 else None
    except (ValueError, KeyError):
        token = None
    if not token:
        raise ValueError(f"Entra sign-in refused ({st})")
    url = (_https(c["endpoint"]) + f"/dataCollectionRules/{urllib.parse.quote(c['dcr_id'])}/streams/{urllib.parse.quote(c['stream'])}"
           "?api-version=2023-01-01")
    rows = [{"TimeGenerated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **{k: (json.dumps(v) if isinstance(v, (list, dict)) else v)
                                                                                     for k, v in e.items()}} for e in evs]
    sent, batch = 0, []
    for row in rows + [None]:
        if row is not None:
            batch.append(row)
        if batch and (row is None or len(json.dumps(batch)) > 900_000):
            st, data = _post(url, json.dumps(batch).encode(), {"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
            if st not in (200, 204):
                raise ValueError(f"Sentinel ingestion answered {st}: {data[:200].decode(errors='replace')}")
            sent += len(batch)
            batch = []
    return sent


def send_syslog(c, _secret, evs):
    """RFC 5424 over TCP with TLS (default), plain TCP or UDP; one line per event, the event as JSON."""
    host, port, proto = c["host"], int(c.get("port") or (6514 if c.get("proto", "tls") == "tls" else 514)), c.get("proto", "tls")
    hostname = socket.gethostname()
    lines = [f"<{(13 << 3) | (3 if e.get('priority') == 1 else 4 if e.get('priority') == 2 else 5)}>1 "
             f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {hostname} ai-it-guardian - {e['type']} - {json.dumps(e)}"
             for e in evs]
    if proto == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for ln in lines:
                s.sendto(ln.encode()[:8000], (host, port))
        return len(lines)
    with socket.create_connection((host, port), timeout=10) as raw:
        s = ssl.create_default_context().wrap_socket(raw, server_hostname=host) if proto == "tls" else raw
        for ln in lines:
            b = ln.encode()
            s.sendall(f"{len(b)} ".encode() + b)          # octet counting (RFC 6587)
    return len(lines)


SENDERS = {"sentinel": send_sentinel, "splunk": send_splunk, "syslog": send_syslog}


def send(cfg, secrets_, evs):
    """Send to every destination that is on. Returns {destination: "ok N" | error text}."""
    out = {}
    for d in DESTS:
        c = cfg.get(d) or {}
        if not c.get("on"):
            continue
        try:
            out[d] = f"ok {SENDERS[d](c, secrets_.get(d), evs)}"
        except Exception as e:                                       # noqa: BLE001 - reported per destination
            out[d] = str(e)[:300]
    return out
