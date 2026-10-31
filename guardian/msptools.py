"""RMM and MDM tools MSPs use: Datto RMM, N-able N-central, ConnectWise Automate, Jamf Pro, Kandji. Read-only.

Each tool has a few fixed, named reads; the answers are reduced to the fields the agents need (patch state, antivirus,
last contact, OS version, disk encryption...). Built from the vendors' API documentation; field names are read
defensively because they differ between versions.
"""
import base64
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

QUERIES = {"datto_rmm": ("devices", "sites"), "ncentral": ("devices", "active_issues"), "cw_automate": ("computers",),
           "jamf": ("version", "computers", "mobile_devices"), "kandji": ("devices", "blueprints")}
URL_RX = re.compile(r"^https://[A-Za-z0-9.-]+(?::\d{2,5})?$")


class MspError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def _req(method, url, ctx=None, headers=None, body=None, form=None, timeout=40):
    h = {"User-Agent": "ai-guardian", "Accept": "application/json", **(headers or {})}
    data = None
    if body is not None:
        data, h["Content-Type"] = json.dumps(body).encode(), "application/json"
    elif form is not None:
        data, h["Content-Type"] = urllib.parse.urlencode(form).encode(), "application/x-www-form-urlencoded"
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx or ssl.create_default_context()))
    try:
        with opener.open(urllib.request.Request(url, data=data, headers=h, method=method), timeout=timeout) as r:
            raw = r.read(30 * 2**20)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise MspError("the API refused the credentials or the account lacks read access")
        raise MspError(f"the API answered {e.code}")
    except (urllib.error.URLError, OSError) as e:
        raise MspError(f"can't reach it: {getattr(e, 'reason', e)}")
    try:
        return json.loads(raw.decode() or "null")
    except ValueError:
        raise MspError("the API returned something that isn't JSON")


def base_url(f, key="url"):
    u = (f.get(key) or "").strip().rstrip("/")
    if not u.startswith("https://"):
        u = "https://" + u
    if not URL_RX.match(u):
        raise MspError("enter the server address like https://server.example.com")
    return u


def _g(d, *path, default=None):
    for p in path:
        d = d.get(p) if isinstance(d, dict) else None
    return default if d is None else d


# -- Datto RMM ---------------------------------------------------------------------------------------------------
def datto(f, query):
    base = base_url(f)
    tok = _req("POST", base + "/auth/oauth/token", headers={"Authorization": "Basic " + base64.b64encode(b"public-client:public").decode()},
               form={"grant_type": "password", "username": f["api_key"], "password": f["api_secret"]}).get("access_token")
    if not tok:
        raise MspError("Datto RMM didn't issue a token")
    h = {"Authorization": f"Bearer {tok}"}
    path = "/api/v2/account/devices?max=250" if query == "devices" else "/api/v2/account/sites?max=250"
    key = "devices" if query == "devices" else "sites"
    rows, url = [], base + path
    for _ in range(20):
        d = _req("GET", url, headers=h) or {}
        rows += d.get(key) or []
        nxt = _g(d, "pageDetails", "nextPageUrl")
        if not nxt or not nxt.startswith(base + "/"):
            break
        url = nxt
    if query == "sites":
        return [{"site": s.get("name"), "devices": _g(s, "devicesStatus", "numberOfDevices")} for s in rows]
    return [{"device": d.get("hostname"), "site": d.get("siteName"), "type": _g(d, "deviceType", "category"),
             "os": d.get("operatingSystem"), "online": d.get("online"), "last_seen": d.get("lastSeen"),
             "reboot_required": d.get("rebootRequired"), "patch_status": _g(d, "patchManagement", "patchStatus"),
             "patches_pending": _g(d, "patchManagement", "patchesApprovedPending"),
             "patches_not_approved": _g(d, "patchManagement", "patchesNotApproved"),
             "antivirus": _g(d, "antivirus", "antivirusProduct"), "antivirus_status": _g(d, "antivirus", "antivirusStatus")} for d in rows]


# -- N-able N-central --------------------------------------------------------------------------------------------
def ncentral(f, query, ctx):
    base = base_url(f)
    auth = _req("POST", base + "/api/auth/authenticate", ctx, {"Authorization": f"Bearer {f['jwt']}"})
    tok = _g(auth, "tokens", "access", "token")
    if not tok:
        raise MspError("N-central didn't issue a token")
    h = {"Authorization": f"Bearer {tok}"}
    if query == "devices":
        d = _req("GET", base + "/api/devices?pageSize=1000", ctx, h) or {}
        return [{"device": x.get("longName") or x.get("deviceName"), "class": x.get("deviceClass"), "os": x.get("supportedOs") or x.get("osName"),
                 "customer": x.get("customerName") or x.get("soName"), "last_check_in": x.get("lastApplianceCheckinTime")}
                for x in d.get("data") or []]
    units = (_req("GET", base + "/api/org-units?pageSize=200", ctx, h) or {}).get("data") or []
    out = []
    for u in units[:30]:
        try:
            issues = (_req("GET", base + f"/api/org-units/{int(u['orgUnitId'])}/active-issues?pageSize=200", ctx, h) or {}).get("data") or []
        except (MspError, KeyError, ValueError):
            continue
        out += [{"org_unit": u.get("orgUnitName"), "device": i.get("deviceName"), "service": i.get("serviceName"),
                 "state": i.get("notificationState") or i.get("serviceState"), "since": i.get("transitionTime")} for i in issues]
    return out


# -- ConnectWise Automate ----------------------------------------------------------------------------------------
def automate(f, ctx):
    base = base_url(f)
    tok = _req("POST", base + "/cwa/api/v1/apitoken", ctx, {"clientId": f["client_id"]},
               body={"UserName": f["username"], "Password": f["password"]}).get("AccessToken")
    if not tok:
        raise MspError("Automate didn't issue a token (two-factor accounts need an integrator login)")
    d = _req("GET", base + "/cwa/api/v1/computers?pageSize=1000&page=1", ctx, {"Authorization": f"Bearer {tok}", "clientId": f["client_id"]})
    return [{"computer": c.get("ComputerName"), "client": _g(c, "Client", "Name"), "os": c.get("OperatingSystemName"),
             "last_contact": c.get("RemoteAgentLastContact") or c.get("LastContact"), "last_patched": c.get("LastPatchedDate"),
             "antivirus": _g(c, "VirusScanner", "Name"), "reboot_needed": c.get("IsRebootNeeded")} for c in d or []]


# -- Jamf Pro ----------------------------------------------------------------------------------------------------
def jamf(f, query):
    base = base_url(f)
    tok = _req("POST", base + "/api/oauth/token", form={"grant_type": "client_credentials", "client_id": f["client_id"],
                                                         "client_secret": f["client_secret"]}).get("access_token")
    if not tok:
        raise MspError("Jamf Pro didn't issue a token")
    h = {"Authorization": f"Bearer {tok}"}
    if query == "version":
        return _req("GET", base + "/api/v1/jamf-pro-version", headers=h)
    if query == "mobile_devices":
        d = _req("GET", base + "/api/v2/mobile-devices?page=0&page-size=500", headers=h) or {}
        return [{"device": x.get("name"), "model": x.get("model"), "os": x.get("osVersion") or x.get("softwareVersion"),
                 "managed": x.get("managed")} for x in d.get("results") or []]
    rows = []
    for page in range(10):
        d = _req("GET", base + "/api/v1/computers-inventory?section=GENERAL&section=OPERATING_SYSTEM&section=SECURITY"
                 f"&section=DISK_ENCRYPTION&page={page}&page-size=200", headers=h) or {}
        rows += d.get("results") or []
        if len(rows) >= (d.get("totalCount") or 0):
            break
    return [{"computer": _g(c, "general", "name"), "last_contact": _g(c, "general", "lastContactTime"),
             "managed": _g(c, "general", "remoteManagement", "managed"), "os": _g(c, "operatingSystem", "version"),
             "filevault": _g(c, "diskEncryption", "bootPartitionEncryptionDetails", "partitionFileVault2State"),
             "sip": _g(c, "security", "sipStatus"), "gatekeeper": _g(c, "security", "gatekeeperStatus"),
             "firewall": _g(c, "security", "firewallEnabled"), "auto_login_disabled": _g(c, "security", "autoLoginDisabled")}
            for c in rows]


# -- Kandji ------------------------------------------------------------------------------------------------------
def kandji(f, query):
    base = base_url(f)
    h = {"Authorization": f"Bearer {f['token']}"}
    if query == "blueprints":
        d = _req("GET", base + "/api/v1/blueprints?limit=300", headers=h) or {}
        return [{"blueprint": b.get("name"), "devices": b.get("computers_count")} for b in d.get("results") or []]
    rows = []
    for off in range(0, 3000, 300):
        d = _req("GET", base + f"/api/v1/devices?limit=300&offset={off}", headers=h) or []
        rows += d if isinstance(d, list) else []
        if not isinstance(d, list) or len(d) < 300:
            break
    return [{"device": d.get("device_name"), "platform": d.get("platform"), "os": d.get("os_version"), "model": d.get("model"),
             "blueprint": d.get("blueprint_name"), "last_check_in": d.get("last_check_in"), "missing": d.get("is_missing"),
             "agent_installed": d.get("agent_installed")} for d in rows]


def run(ctype, f, query, ctx=None):
    if query not in QUERIES.get(ctype, ()):
        raise MspError("unknown query")
    if ctype == "datto_rmm":
        return datto(f, query)
    if ctype == "ncentral":
        return ncentral(f, query, ctx)
    if ctype == "cw_automate":
        return automate(f, ctx)
    if ctype == "jamf":
        return jamf(f, query)
    return kandji(f, query)
