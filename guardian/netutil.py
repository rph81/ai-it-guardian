"""Small read-only network helpers shared by the collector and agent tools."""
import ipaddress
import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.request


def in_scope(host, network):
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(network)
    except (ValueError, TypeError):
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
_opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=_ctx))


def http_fetch(url, method="GET", max_bytes=8000):
    """GET/HEAD only, no redirects followed, no credentials sent."""
    req = urllib.request.Request(url, method=method, headers={"User-Agent": "ai-guardian-assessment/0.1"})
    try:
        r = _opener.open(req, timeout=6)
        status, headers, body = r.status, dict(r.headers), r.read(max_bytes)
    except urllib.error.HTTPError as e:
        status, headers, body = e.code, dict(e.headers or {}), (e.read(max_bytes) if e.fp else b"")
    except Exception as e:
        return {"url": url, "error": str(e)[:200]}
    text = body.decode("utf-8", errors="replace")
    title = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", "", text)
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text)).strip()
    return {"url": url, "status": status, "headers": headers,
            "title": title.group(1).strip()[:200] if title else None,
            "text_excerpt": text[:1500]}


def tls_inspect(host, port):
    out = {"port": port}
    try:
        with socket.create_connection((host, port), timeout=6) as s:
            with _ctx.wrap_socket(s, server_hostname=host) as t:
                out["protocol"] = t.version()
                out["cipher"] = t.cipher()[0]
                der = t.getpeercert(binary_form=True)
    except Exception as e:
        out["error"] = str(e)[:200]
        return out
    pem = ssl.DER_cert_to_PEM_cert(der)
    txt = subprocess.run(["openssl", "x509", "-noout", "-subject", "-issuer", "-enddate", "-startdate",
                          "-ext", "subjectAltName", "-text"],
                         input=pem, capture_output=True, text=True).stdout
    for key, pat in (("subject", r"subject=(.*)"), ("issuer", r"issuer=(.*)"),
                     ("not_after", r"notAfter=(.*)"), ("not_before", r"notBefore=(.*)"),
                     ("key", r"Public-Key: \((\d+ bit)\)"), ("sig_alg", r"Signature Algorithm: (\S+)")):
        m = re.search(pat, txt)
        if m:
            out[key] = m.group(1).strip()
    san = re.search(r"Subject Alternative Name:.*?\n\s*(.*)", txt)
    if san:
        out["san"] = san.group(1).strip()[:300]
    out["self_signed"] = out.get("subject") == out.get("issuer")
    return out
