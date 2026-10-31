"""Google Workspace and Google Cloud, read-only, for the Google agent.

Signs in with a service account key (a signed JWT, no Google SDK). Workspace reads act as a read-only admin through
domain-wide delegation with read-only scopes only; Google Cloud reads use the cloud-platform.read-only scope and the
Viewer / Security Reviewer roles. Every read is a fixed, named query; only Google's API hosts are contacted.
"""
import base64
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

TOKEN_URL = "https://oauth2.googleapis.com/token"
HOSTS = {"oauth2.googleapis.com", "admin.googleapis.com", "alertcenter.googleapis.com", "cloudresourcemanager.googleapis.com",
         "compute.googleapis.com", "storage.googleapis.com", "sqladmin.googleapis.com", "iam.googleapis.com", "logging.googleapis.com"}
WS_SCOPES = ["https://www.googleapis.com/auth/admin.directory.user.readonly",
             "https://www.googleapis.com/auth/admin.directory.domain.readonly",
             "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
             "https://www.googleapis.com/auth/admin.reports.audit.readonly",
             "https://www.googleapis.com/auth/apps.alerts"]
GCP_SCOPES = ["https://www.googleapis.com/auth/cloud-platform.read-only"]
WS_QUERIES = ("users", "admins", "domains", "login_events", "admin_events", "alerts")
GCP_QUERIES = ("projects", "iam_policy", "service_account_keys", "firewalls_open", "instances", "buckets", "sql_instances", "log_sinks")
# permissions that would let the account change things: the test warns if the service account has any of them
WRITE_PERMS = ["resourcemanager.projects.setIamPolicy", "compute.instances.delete", "compute.firewalls.update",
               "storage.buckets.delete", "iam.serviceAccountKeys.create", "cloudsql.instances.update"]
PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_TOKENS = {}


class GoogleError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))


def _b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _req(method, url, token=None, body=None, form=None, timeout=30):
    if urllib.parse.urlsplit(url).hostname not in HOSTS or not url.startswith("https://"):
        raise GoogleError("not an allowed Google address")
    headers = {"User-Agent": "ai-guardian"}
    data = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
    elif form is not None:
        data, headers["Content-Type"] = urllib.parse.urlencode(form).encode(), "application/x-www-form-urlencoded"
    try:
        with _OPENER.open(urllib.request.Request(url, data=data, headers=headers, method=method), timeout=timeout) as r:
            raw = r.read(16 * 2**20 + 1)
            if len(raw) > 16 * 2**20:
                raise GoogleError("answer too large")
            return r.status, json.loads(raw.decode() or "null")
    except urllib.error.HTTPError as e:
        try:
            err = json.loads(e.read().decode())
            msg = (err.get("error") or {}).get("message") if isinstance(err.get("error"), dict) else err.get("error_description") or err.get("error")
        except ValueError:
            msg = None
        return e.code, {"error": str(msg or e.reason)[:300]}
    except (urllib.error.URLError, OSError) as e:
        raise GoogleError(f"can't reach Google: {getattr(e, 'reason', e)}")


def key_info(f):
    try:
        k = json.loads(f["service_account_json"])
    except (ValueError, TypeError):
        raise GoogleError("The service account key isn't valid JSON")
    if k.get("type") != "service_account" or not k.get("client_email") or "PRIVATE KEY" not in (k.get("private_key") or ""):
        raise GoogleError("That isn't a service account key (type service_account with client_email and private_key)")
    return k


def token(f, scopes, subject=None):
    """An access token for these scopes (cached until 5 minutes before it expires)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    k = key_info(f)
    cache = (k["client_email"], subject, tuple(scopes))
    t = _TOKENS.get(cache)
    if t and t[1] > time.time() + 300:
        return t[0]
    now = int(time.time())
    claims = {"iss": k["client_email"], "scope": " ".join(scopes), "aud": TOKEN_URL, "iat": now, "exp": now + 3600}
    if subject:
        claims["sub"] = subject
    head = {"alg": "RS256", "typ": "JWT", **({"kid": k["private_key_id"]} if k.get("private_key_id") else {})}
    signing = _b64(json.dumps(head).encode()) + "." + _b64(json.dumps(claims).encode())
    try:
        pk = serialization.load_pem_private_key(k["private_key"].encode(), None)
    except ValueError:
        raise GoogleError("The private key in the service account key can't be read")
    sig = pk.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())
    st, d = _req("POST", TOKEN_URL, form={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                          "assertion": signing + "." + _b64(sig)})
    if st != 200 or not (d or {}).get("access_token"):
        err = str((d or {}).get("error", ""))
        if "unauthorized_client" in err or "not authorized" in err.lower():
            raise GoogleError("Google refused the token: domain-wide delegation isn't set up for this client ID with these "
                              "exact scopes" if subject else "Google refused the token: " + err)
        raise GoogleError(f"Google refused the token: {err or st}")
    _TOKENS[cache] = (d["access_token"], now + int(d.get("expires_in", 3600)))
    return d["access_token"]


def _pages(url, tok, key, max_pages=10, page_param="pageToken"):
    items, nxt = [], None
    for _ in range(max_pages):
        u = url + (("&" if "?" in url else "?") + f"{page_param}={urllib.parse.quote(nxt)}" if nxt else "")
        st, d = _req("GET", u, tok)
        if st != 200:
            raise GoogleError(f"{urllib.parse.urlsplit(url).path}: {st} {(d or {}).get('error', '')}")
        items += (d or {}).get(key) or []
        nxt = (d or {}).get("nextPageToken")
        if not nxt:
            return items, False
    return items, True


ADMIN = "https://admin.googleapis.com/admin"


def workspace(f, query):
    if query not in WS_QUERIES:
        raise GoogleError("unknown query")
    tok = token(f, WS_SCOPES, f["admin_email"])
    if query in ("users", "admins"):
        users, more = _pages(f"{ADMIN}/directory/v1/users?customer=my_customer&maxResults=500&projection=basic", tok, "users")
        rows = [{"email": u.get("primaryEmail"), "admin": u.get("isAdmin"), "delegated_admin": u.get("isDelegatedAdmin"),
                 "2sv_enrolled": u.get("isEnrolledIn2Sv"), "2sv_enforced": u.get("isEnforcedIn2Sv"), "suspended": u.get("suspended"),
                 "last_login": u.get("lastLoginTime"), "created": u.get("creationTime"), "org_unit": u.get("orgUnitPath")}
                for u in users]
        if query == "users":
            return rows, more
        roles, _ = _pages(f"{ADMIN}/directory/v1/customer/my_customer/roles?maxResults=100", tok, "items")
        names = {str(r.get("roleId")): r.get("roleName") for r in roles}
        assigns, _ = _pages(f"{ADMIN}/directory/v1/customer/my_customer/roleassignments?maxResults=200", tok, "items")
        by_id = {}
        for a in assigns:
            by_id.setdefault(a.get("assignedTo"), []).append(names.get(str(a.get("roleId")), a.get("roleId")))
        return {"admins": [r for r in rows if r["admin"] or r["delegated_admin"]], "role_assignments_by_user_id": by_id,
                "roles": sorted(n for n in names.values() if n)}, more
    if query == "domains":
        st, d = _req("GET", f"{ADMIN}/directory/v1/customer/my_customer/domains", tok)
        if st != 200:
            raise GoogleError(f"domains: {st} {(d or {}).get('error', '')}")
        return [{"domain": x.get("domainName"), "verified": x.get("verified"), "primary": x.get("isPrimary")}
                for x in (d or {}).get("domains") or []], False
    if query in ("login_events", "admin_events"):
        app = "login" if query == "login_events" else "admin"
        since = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - 30 * 86400))
        acts, more = _pages(f"https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/{app}"
                            f"?maxResults=1000&startTime={since}", tok, "items", max_pages=3)
        counts, notable = {}, []
        watch = {"suspicious_login", "suspicious_login_less_secure_app", "suspicious_programmatic_login", "gov_attack_warning",
                 "account_disabled_password_leak", "account_disabled_hijacked", "GRANT_ADMIN_PRIVILEGE", "ASSIGN_ROLE",
                 "CREATE_ROLE", "CHANGE_TWO_STEP_VERIFICATION_ENFORCEMENT", "TOGGLE_ALLOW_ADMIN_PASSWORD_RESET",
                 "ADD_TO_TRUSTED_OAUTH2_APPS", "CHANGE_APPLICATION_SETTING"}
        for a in acts:
            for e in a.get("events") or []:
                n = e.get("name")
                counts[n] = counts.get(n, 0) + 1
                if n in watch and len(notable) < 100:
                    notable.append({"time": (a.get("id") or {}).get("time"), "event": n, "actor": (a.get("actor") or {}).get("email"),
                                    "ip": a.get("ipAddress")})
        return {"days": 30, "event_counts": counts, "notable": notable}, more
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 90 * 86400))
    alerts, more = _pages("https://alertcenter.googleapis.com/v1beta1/alerts?pageSize=100&filter="
                          + urllib.parse.quote(f'createTime >= "{since}"'), tok, "alerts", max_pages=3)
    return [{"type": a.get("type"), "source": a.get("source"), "created": a.get("createTime"),
             "severity": (a.get("metadata") or {}).get("severity"), "status": (a.get("metadata") or {}).get("status")}
            for a in alerts], more


def gcp_projects(f, tok):
    want = [p for p in (f.get("projects") or "").split() if PROJECT.match(p)]
    items, _ = _pages("https://cloudresourcemanager.googleapis.com/v1/projects?filter=lifecycleState%3AACTIVE", tok, "projects", 5)
    ids = [p.get("projectId") for p in items]
    return [p for p in ids if p in want] if want else ids[:30]


def gcp(f, query, project=None):
    if query not in GCP_QUERIES:
        raise GoogleError("unknown query")
    tok = token(f, GCP_SCOPES)
    projects = gcp_projects(f, tok)
    if query == "projects":
        return [{"project": p} for p in projects], False
    if project:
        if project not in projects:
            raise GoogleError("that project isn't one the connector may read")
        projects = [project]
    rows, errors = [], []
    for p in projects[:30]:
        try:
            rows += _gcp_one(tok, query, p)
        except GoogleError as e:
            errors.append(f"{p}: {e}")
    return {"rows": rows, "projects": len(projects), "errors": errors[:20]}, False


def _gcp_one(tok, query, p):
    def get(url, key):
        return _pages(url, tok, key, 5)[0]
    if query == "iam_policy":
        st, d = _req("POST", f"https://cloudresourcemanager.googleapis.com/v1/projects/{p}:getIamPolicy",
                     tok, body={"options": {"requestedPolicyVersion": 3}})          # a read: returns the policy, changes nothing
        if st != 200:
            raise GoogleError(f"{st} {(d or {}).get('error', '')}")
        out = []
        for b in (d or {}).get("bindings") or []:
            members = b.get("members") or []
            risky = [m for m in members if m in ("allUsers", "allAuthenticatedUsers") or m.endswith("@gmail.com")]
            if b.get("role") in ("roles/owner", "roles/editor") or risky or b.get("role", "").endswith("Admin"):
                out.append({"project": p, "role": b.get("role"), "members": members[:30], "count": len(members),
                            "public_or_personal": risky, "condition": bool(b.get("condition"))})
        out.append({"project": p, "audit_configs": [a.get("service") for a in (d or {}).get("auditConfigs") or []]})
        return out
    if query == "service_account_keys":
        sas = get(f"https://iam.googleapis.com/v1/projects/{p}/serviceAccounts?pageSize=100", "accounts")
        out = []
        for sa in sas[:60]:
            st, d = _req("GET", f"https://iam.googleapis.com/v1/{urllib.parse.quote(sa['name'], safe='/@')}/keys?keyTypes=USER_MANAGED", tok)
            keys = (d or {}).get("keys") or [] if st == 200 else []
            out.append({"project": p, "account": sa.get("email"), "disabled": sa.get("disabled", False),
                        "user_managed_keys": [{"created": k.get("validAfterTime"), "expires": k.get("validBeforeTime")} for k in keys]})
        return out
    if query == "firewalls_open":
        rules = get(f"https://compute.googleapis.com/compute/v1/projects/{p}/global/firewalls?maxResults=500", "items")
        return [{"project": p, "rule": r.get("name"), "network": (r.get("network") or "").rsplit("/", 1)[-1],
                 "sources": r.get("sourceRanges"), "allowed": r.get("allowed"), "targets": r.get("targetTags") or "all instances",
                 "logging": (r.get("logConfig") or {}).get("enable", False)}
                for r in rules if r.get("direction") == "INGRESS" and not r.get("disabled")
                and set(r.get("sourceRanges") or []) & {"0.0.0.0/0", "::/0"}]
    if query == "instances":
        st, d = _req("GET", f"https://compute.googleapis.com/compute/v1/projects/{p}/aggregated/instances?maxResults=500", tok)
        if st != 200:
            raise GoogleError(f"{st} {(d or {}).get('error', '')}")
        out = []
        for zone, v in ((d or {}).get("items") or {}).items():
            for i in v.get("instances") or []:
                md = {m.get("key"): m.get("value") for m in (i.get("metadata") or {}).get("items") or []}
                sa = (i.get("serviceAccounts") or [{}])[0]
                out.append({"project": p, "name": i.get("name"), "zone": zone.rsplit("/", 1)[-1], "status": i.get("status"),
                            "public_ips": [a.get("natIP") for n in i.get("networkInterfaces") or [] for a in n.get("accessConfigs") or [] if a.get("natIP")],
                            "default_service_account": (sa.get("email") or "").endswith("-compute@developer.gserviceaccount.com"),
                            "full_api_access": "https://www.googleapis.com/auth/cloud-platform" in (sa.get("scopes") or []),
                            "os_login": md.get("enable-oslogin"), "serial_port": md.get("serial-port-enable"),
                            "shielded_secure_boot": (i.get("shieldedInstanceConfig") or {}).get("enableSecureBoot")})
        return out
    if query == "buckets":
        out = []
        for b in get(f"https://storage.googleapis.com/storage/v1/b?project={p}&maxResults=500", "items")[:100]:
            st, pol = _req("GET", f"https://storage.googleapis.com/storage/v1/b/{urllib.parse.quote(b['name'])}/iam", tok)
            public = sorted({m for x in (pol or {}).get("bindings") or [] for m in x.get("members") or []
                             if m in ("allUsers", "allAuthenticatedUsers")}) if st == 200 else ["(policy not readable)"]
            ic = b.get("iamConfiguration") or {}
            out.append({"project": p, "bucket": b.get("name"), "public_members": public,
                        "public_access_prevention": ic.get("publicAccessPrevention"),
                        "uniform_access": (ic.get("uniformBucketLevelAccess") or {}).get("enabled"),
                        "versioning": (b.get("versioning") or {}).get("enabled", False), "logging": bool(b.get("logging"))})
        return out
    if query == "sql_instances":
        st, d = _req("GET", f"https://sqladmin.googleapis.com/v1/projects/{p}/instances", tok)
        if st != 200:
            raise GoogleError(f"{st} {(d or {}).get('error', '')}")
        out = []
        for i in (d or {}).get("items") or []:
            s = i.get("settings") or {}
            ip = s.get("ipConfiguration") or {}
            out.append({"project": p, "name": i.get("name"), "version": i.get("databaseVersion"), "public_ip": ip.get("ipv4Enabled"),
                        "authorized_networks": [n.get("value") for n in ip.get("authorizedNetworks") or []],
                        "ssl_mode": ip.get("sslMode") or ("required" if ip.get("requireSsl") else "not required"),
                        "backups": (s.get("backupConfiguration") or {}).get("enabled")})
        return out
    sinks = get(f"https://logging.googleapis.com/v2/projects/{p}/sinks?pageSize=200", "sinks")
    return [{"project": p, "sinks": [{"name": s.get("name"), "destination": s.get("destination"), "filter": (s.get("filter") or "")[:200]}
                                     for s in sinks]}]


def test_workspace(f):
    if not re.fullmatch(r"[^@\s]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", f.get("admin_email") or ""):
        raise GoogleError("Enter the read-only admin's e-mail address")
    tok = token(f, WS_SCOPES, f["admin_email"])
    st, d = _req("GET", f"{ADMIN}/directory/v1/users?customer=my_customer&maxResults=1&projection=basic", tok)
    if st != 200:
        raise GoogleError(f"Reading users failed: {(d or {}).get('error', st)}")
    return "ok", "Connected", [f"Acting as {f['admin_email']} with read-only scopes only",
                               "Service account " + key_info(f)["client_email"]]


def test_gcp(f):
    tok = token(f, GCP_SCOPES)
    projects = gcp_projects(f, tok)
    if not projects:
        raise GoogleError("The service account can't see any project: grant it Viewer and Security Reviewer")
    details = [f"{len(projects)} project(s) readable: " + ", ".join(projects[:5]) + ("…" if len(projects) > 5 else "")]
    st, d = _req("POST", f"https://cloudresourcemanager.googleapis.com/v1/projects/{projects[0]}:testIamPermissions",
                 tok, body={"permissions": WRITE_PERMS})                       # asks what it may do; changes nothing
    granted = (d or {}).get("permissions") or [] if st == 200 else []
    if granted:
        details.append("The service account can change things: " + ", ".join(granted) + ". Give it only Viewer and Security Reviewer.")
        return "warn", "Connected, with a warning", details
    details.append("No write permissions found")
    return "ok", "Connected", details
