"""Safe web application check: a polite, read-only crawl of one web app, optionally signed in with a test account.

Rules: GET and HEAD only, the target's origin only (redirects elsewhere are not followed), at most 2 requests a second
and a page cap, URLs that look like actions (logout, delete, reset...) are skipped, forms are never submitted. The
sign-in header or cookie stays in memory for the scan and is never written to the result. Modelled on the passive
checks of Tenable WAS, Qualys WAS and OWASP ZAP's baseline scan.
"""
import html.parser
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "AI-IT-Guardian-WebCheck/1.0 (read-only)"
SKIP = re.compile(r"(log-?out|sign-?out|delete|remove|destroy|reset|unsubscribe|cancel|disable|revoke|/purge|/drop|action=)", re.I)
MAX_BODY = 2 * 1024 * 1024
ERRORS = [(r"Traceback \(most recent call last\)", "Python traceback"), (r"at [a-z]+\.[a-z]+\.[A-Za-z$]+\([A-Za-z]+\.java:\d+\)", "Java stack trace"),
          (r"(Fatal error|Warning|Parse error)</b>:\s.+ on line <b>\d+", "PHP error"), (r"SQLSTATE\[\w+\]|ORA-\d{5}|You have an error in your SQL syntax", "Database error"),
          (r"Microsoft OLE DB Provider|Server Error in '/' Application", "ASP.NET error page"), (r"Whitelabel Error Page", "Spring error page")]
PROBES = [  # path, signature (regex on body, or None = any 200), title, severity, recommendation
    ("/.git/HEAD", r"^ref: refs/", "Git repository exposed", "high", "Block /.git on the web server; the whole source code (and often secrets) can be downloaded."),
    ("/.env", r"^[A-Z_]{3,}=", "Environment file exposed", "critical", "Remove .env from the web root and rotate every secret in it."),
    ("/.DS_Store", r"Bud1", "macOS folder index exposed", "low", "Remove .DS_Store files; they list file names."),
    ("/server-status", r"Apache Server Status", "Apache server-status page public", "medium", "Limit /server-status to localhost or admins."),
    ("/phpinfo.php", r"phpinfo\(\)|PHP Version", "phpinfo page public", "medium", "Remove phpinfo pages from production."),
    ("/web.config", r"<configuration", "web.config readable", "high", "Block .config files; they may hold connection strings."),
    ("/actuator/env", r"propertySources|activeProfiles", "Spring Boot actuator /env public", "high", "Limit actuator endpoints to admins; /env can expose secrets."),
    ("/actuator/heapdump", None, "Spring Boot heap dump downloadable", "critical", "Disable the heapdump endpoint; memory dumps contain passwords and tokens."),
    ("/wp-json/wp/v2/users", r'"slug"\s*:', "WordPress user list public", "medium", "Block the users REST endpoint for anonymous visitors (user enumeration)."),
    ("/backup.zip", None, "Backup archive downloadable", "high", "Remove backups from the web root."),
    ("/swagger.json", r'"swagger"|"openapi"', "API description public", "info", "Fine if intended; otherwise limit it to developers."),
    ("/openapi.json", r'"openapi"', "API description public", "info", "Fine if intended; otherwise limit it to developers."),
]
HEADERS = [("strict-transport-security", "HSTS (Strict-Transport-Security)", "medium", "Send Strict-Transport-Security: max-age=31536000 on every HTTPS response.", True),
           ("content-security-policy", "Content-Security-Policy", "medium", "Add a Content-Security-Policy that limits scripts to your own origin.", False),
           ("x-content-type-options", "X-Content-Type-Options", "low", "Send X-Content-Type-Options: nosniff.", False),
           ("referrer-policy", "Referrer-Policy", "low", "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).", False)]


class _Links(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.scripts_http, self.password_fields, self.forms_http = [], [], 0, []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        if tag in ("script", "iframe") and (a.get("src") or "").lower().startswith("http://"):
            self.scripts_http.append(a["src"])
        if tag == "input" and (a.get("type") or "").lower() == "password":
            self.password_fields += 1
        if tag == "form" and (a.get("action") or "").lower().startswith("http://"):
            self.forms_http.append(a["action"])


class _SameOrigin(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin):
        self.origin = origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _origin(newurl) != self.origin:
            return None                                  # never follow to another site
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _origin(url):
    u = urllib.parse.urlsplit(url)
    return f"{u.scheme}://{u.hostname}:{u.port or (443 if u.scheme == 'https' else 80)}".lower()


class Scan:
    def __init__(self, target, auth=None, max_pages=150, rate=2.0, verify_tls=True, progress=None):
        u = urllib.parse.urlsplit(target.strip())
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError("Give the app's address, e.g. https://app.example.com")
        self.base = f"{u.scheme}://{u.netloc}"
        self.start = urllib.parse.urlunsplit((u.scheme, u.netloc, u.path or "/", u.query, ""))
        self.origin, self.auth, self.max_pages, self.gap = _origin(self.start), auth, max(1, min(max_pages, 500)), 1.0 / rate
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        self.opener = urllib.request.build_opener(_SameOrigin(self.origin), urllib.request.HTTPSHandler(context=ctx))
        self.progress = progress or (lambda **k: None)
        self.last, self.requests, self.stop = 0.0, 0, False
        self.pages, self.findings = {}, {}

    # -- http ----------------------------------------------------------------------------------------------
    def get(self, url, signed_in=True, method="GET", extra=None):
        wait = self.last + self.gap - time.time()
        if wait > 0:
            time.sleep(wait)
        self.last = time.time()
        self.requests += 1
        h = {"User-Agent": UA, "Accept": "text/html,application/json;q=0.9,*/*;q=0.5", **(extra or {})}
        if signed_in and self.auth:
            h[self.auth[0]] = self.auth[1]
        req = urllib.request.Request(url, method=method, headers=h)
        try:
            with self.opener.open(req, timeout=20) as r:
                body = r.read(MAX_BODY) if method == "GET" else b""
                return r.status, r.headers, body, r.geturl()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read(200000), url
        except (urllib.error.URLError, OSError, ValueError):
            return None, {}, b"", url

    # -- findings ---------------------------------------------------------------------------------------------
    def add(self, key, title, severity, url, evidence, recommendation, cwe=None):
        f = self.findings.setdefault(key, {"title": title, "severity": severity, "urls": [], "evidence": evidence[:600],
                                           "recommendation": recommendation, "cwe": cwe})
        if url and url not in f["urls"] and len(f["urls"]) < 20:
            f["urls"].append(url)
        f["count"] = f.get("count", 0) + 1

    def check_page(self, url, status, headers, body):
        ct = (headers.get("content-type") or "").lower()
        text = body.decode("utf-8", "replace") if "html" in ct or "json" in ct or "text" in ct else ""
        for name, label, sev, fix, https_only in HEADERS:
            if "html" in ct and status == 200 and not headers.get(name) and (not https_only or self.base.startswith("https")):
                self.add(f"hdr:{name}", f"Missing security header: {label}", sev, url, f"No {label} header on HTML responses.", fix, "CWE-693")
        if "html" in ct and status == 200 and not headers.get("x-frame-options") and "frame-ancestors" not in (headers.get("content-security-policy") or ""):
            self.add("hdr:frame", "Pages can be framed by other sites (clickjacking)", "low", url, "No X-Frame-Options and no CSP frame-ancestors.",
                     "Send X-Frame-Options: DENY or CSP frame-ancestors 'self'.", "CWE-1021")
        cookies = (headers.get_all("set-cookie") or []) if hasattr(headers, "get_all") else []
        for c in cookies:
            name, low = c.split("=", 1)[0].strip(), c.lower()
            miss = [x for x, ok in (("Secure", "; secure" in low or not self.base.startswith("https")), ("HttpOnly", "httponly" in low),
                                    ("SameSite", "samesite" in low)) if not ok]
            if miss:
                self.add(f"cookie:{name}", f"Cookie {name} without {', '.join(miss)}", "medium" if "Secure" in miss or "HttpOnly" in miss else "low",
                         url, f"Set-Cookie: {name}=… lacks {', '.join(miss)}.", "Set Secure, HttpOnly and SameSite=Lax (or Strict) on session cookies.", "CWE-614")
        for hdr in ("server", "x-powered-by", "x-aspnet-version"):
            v = headers.get(hdr) or ""
            if re.search(r"\d+\.\d+", v):
                self.add(f"ver:{hdr}", "Server software version disclosed", "low", url, f"{hdr}: {v[:100]}",
                         "Hide version numbers in Server / X-Powered-By headers.", "CWE-200")
        for rx, label in ERRORS:
            m = re.search(rx, text)
            if m:
                self.add(f"err:{label}", f"{label} shown to visitors", "medium", url, text[max(0, m.start() - 80):m.end() + 160],
                         "Show a generic error page in production and log the details on the server.", "CWE-209")
        if "<title>Index of /" in text:
            self.add("dirlist", "Directory listing enabled", "medium", url, "The server lists folder contents.", "Turn off directory listing.", "CWE-548")
        if "html" not in ct or status != 200:
            return []
        p = _Links()
        try:
            p.feed(text)
        except Exception:                                          # noqa: BLE001 - broken HTML is still crawled as far as possible
            pass
        if p.scripts_http and self.base.startswith("https"):
            self.add("mixed", "HTTPS pages load scripts over plain HTTP", "medium", url, ", ".join(p.scripts_http[:5]),
                     "Load every script and frame over HTTPS.", "CWE-319")
        if p.password_fields and self.base.startswith("http:"):
            self.add("pw-http", "Password field on a page served over plain HTTP", "high", url, "A password form is served without TLS.",
                     "Serve the app over HTTPS only and redirect HTTP to HTTPS.", "CWE-319")
        if p.forms_http:
            self.add("form-http", "Form sends data over plain HTTP", "high", url, ", ".join(p.forms_http[:3]), "Post forms to HTTPS addresses only.", "CWE-319")
        return p.links

    # -- run ----------------------------------------------------------------------------------------------------
    def run(self):
        queue, seen = [(self.start, 0)], {self.start}
        while queue and len(self.pages) < self.max_pages and not self.stop:
            url, depth = queue.pop(0)
            status, headers, body, final = self.get(url)
            self.pages[url] = {"status": status, "len": len(body), "type": (headers.get("content-type") or "")[:60] if headers else ""}
            self.progress(stage="crawl", pages=len(self.pages), requests=self.requests)
            if status is None:
                continue
            for href in self.check_page(url, status, headers, body):
                nxt = urllib.parse.urljoin(final, href.split("#")[0])
                if _origin(nxt) != self.origin or nxt in seen or SKIP.search(nxt) or depth >= 4:
                    continue
                if re.search(r"\.(png|jpe?g|gif|svg|ico|css|js|woff2?|pdf|zip|mp4|webp)(\?|$)", nxt, re.I):
                    continue
                seen.add(nxt)
                queue.append((nxt, depth + 1))
        if not self.stop:
            self.probe_files()
            self.check_cors()
            if self.auth:
                self.check_access()
            if not self.base.startswith("https"):
                self.add("nohttps", "The app is served over plain HTTP", "high", self.start, "No TLS on the target address.",
                         "Serve the app over HTTPS with a valid certificate and HSTS.", "CWE-319")
        return self.result()

    def probe_files(self):
        for path, sig, title, sev, fix in PROBES:
            if self.stop:
                return
            url = self.base + path
            status, headers, body, final = self.get(url, signed_in=False, method="GET")
            if status != 200 or final != url:
                continue
            text = body[:4000].decode("utf-8", "replace")
            ctype = (headers.get("content-type") or "").lower()
            if sig is None and ("html" in ctype or len(body) < 64):
                continue                                      # soft 404 pages
            if sig is not None and not re.search(sig, text, re.M):
                continue
            self.add(f"probe:{path}", title, sev, url, f"GET {path} → 200 ({len(body)} bytes, {ctype[:40]})", fix, "CWE-538")
        status, _, _, final = self.get(self.base + "/.well-known/security.txt", signed_in=False)
        if status != 200:
            self.add("sectxt", "No security.txt", "info", self.base + "/.well-known/security.txt", "There's no /.well-known/security.txt.",
                     "Publish a security.txt (Guardian's disclosure page can generate one).", None)

    def check_cors(self):
        evil = "https://guardian-cors-check.invalid"
        status, headers, _, _ = self.get(self.start, extra={"Origin": evil})
        if not headers:
            return
        acao, acac = headers.get("access-control-allow-origin") or "", (headers.get("access-control-allow-credentials") or "").lower()
        if acao == evil and acac == "true":
            self.add("cors", "Any website can read signed-in users' data (CORS)", "high", self.start,
                     f"Origin {evil} is reflected with Access-Control-Allow-Credentials: true.",
                     "Allow only your own origins in CORS, never reflect the Origin header with credentials.", "CWE-942")
        elif acao == "*" and self.auth:
            self.add("cors-star", "CORS allows every origin on a signed-in page", "medium", self.start, "Access-Control-Allow-Origin: *",
                     "Limit CORS to the origins that need it.", "CWE-942")

    def check_access(self):
        """Pages that loaded signed in and also load, with the same content, without signing in."""
        s0, _, b0, _ = self.get(self.start, signed_in=False)
        s1, _, b1, _ = self.get(self.start, signed_in=True)
        if s0 == s1 and b0 == b1:
            return                                             # the sign-in makes no visible difference: nothing to compare
        checked = 0
        for url, p in list(self.pages.items()):
            if self.stop or checked >= 40 or p["status"] != 200 or "html" not in p["type"] or url == self.start:
                continue
            checked += 1
            status, _, body, final = self.get(url, signed_in=False)
            text = body.decode("utf-8", "replace").lower()
            if status == 200 and final == url and abs(len(body) - p["len"]) <= max(200, p["len"] * 0.05) and 'type="password"' not in text:
                self.add("authz", "Pages for signed-in users also load without signing in", "high", url,
                         "The same page came back without the test account's sign-in.",
                         "Check access control on the server for every page and API, not only in the menu.", "CWE-862")

    def result(self):
        order = ["critical", "high", "medium", "low", "info"]
        fs = sorted(self.findings.values(), key=lambda f: order.index(f["severity"]))
        return {"target": self.start, "signed_in": bool(self.auth), "pages": len(self.pages), "requests": self.requests,
                "findings": fs, "counts": {s: sum(1 for f in fs if f["severity"] == s) for s in order}}
