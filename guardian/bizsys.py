"""Business systems: SAP S/4HANA / ECC (ABAP), SAP BTP and Salesforce, read-only.

Same rules as the other connectors: the agent picks a named read from a fixed list; this code signs in and runs it.
- SAP ABAP: RFC_READ_TABLE over the SOAP RFC service (/sap/bc/soap/rfc), only the tables and columns listed in
  SAP_QUERIES. Password columns are never requested; RFC destinations come back as flags (stored password yes/no).
- SAP BTP: the Cloud Management (accounts) API and the authorization API, GET only. Destination configurations are
  reduced to name, type, URL host, authentication and proxy type: credentials are dropped before anything is returned.
- Salesforce: OAuth client credentials, then the fixed SOQL queries in SF_QUERIES (REST or Tooling API), GET only.
"""
import base64
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

from . import connectors as conn

MAX_BYTES = 8 * 1024 * 1024
URL = re.compile(r"^https://[A-Za-z0-9.-]{1,253}(:\d{1,5})?/?$")


class BizError(Exception):
    pass


def _req(url, ctx, method="GET", headers=None, body=None, timeout=30):
    req = urllib.request.Request(url, method=method, data=body, headers={"User-Agent": "ai-guardian", **(headers or {})})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            data = r.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise BizError("answer too large")
            return r.status, data
    except urllib.error.HTTPError as e:
        return e.code, e.read(4000)
    except (urllib.error.URLError, OSError) as e:
        raise BizError(f"Can't reach it: {getattr(e, 'reason', e)}")


def _json(data):
    try:
        return json.loads(data.decode() or "null")
    except ValueError:
        return None


def _xml(data):
    """Parse an answer without DTDs or entities (XXE, billion laughs)."""
    low = data[:200000].decode("utf-8", "replace").lower()
    if "<!doctype" in low or "<!entity" in low:
        raise BizError("the server answered with a DTD; refused")
    try:
        return ET.fromstring(data)
    except ET.ParseError as e:
        raise BizError(f"not valid XML: {e}")


def _base(url):
    url = (url or "").strip().rstrip("/")
    if not URL.match(url + "/"):
        raise BizError("Use the address like https://sap.example.com:44300 (https only, no path)")
    return url


def _ctx(url, f, pin):
    """Verified TLS, or (verify off) pinned to the certificate seen on the first test, like the other connectors."""
    u = urllib.parse.urlparse(url)
    try:
        return conn._tls_context(u.hostname, u.port or 443, f.get("verify_tls"), pin)
    except conn.Result as e:
        raise BizError(e.message)


# -- SAP ABAP (S/4HANA, ECC) ----------------------------------------------------------------------------------------
# name: (table, columns, WHERE lines or None, row limit). Columns never include password hashes.
CRITICAL_PROFILES = {"SAP_ALL", "SAP_NEW", "S_A.SYSTEM", "S_A.ADMIN", "S_A.DEVELOP"}
SAP_DEFAULT_USERS = "('SAP*','DDIC','EARLYWATCH','TMSADM','SAPCPIC','SAPSUPPORT')"
SAP_QUERIES = {
    "clients": ("T000", ["MANDT", "MTEXT", "CCCATEGORY", "CCCORACTIV", "CCNOCLIIND", "CCIMAILDIS"], None, 100),
    "default_users": ("USR02", ["MANDT", "BNAME", "USTYP", "UFLAG", "TRDAT", "CODVN", "PWDSTATE"], [f"BNAME IN {SAP_DEFAULT_USERS}"], 200),
    "users": ("USR02", ["BNAME", "USTYP", "CLASS", "UFLAG", "TRDAT", "GLTGB", "CODVN", "PWDSTATE"], None, 5000),
    "critical_profiles": ("UST04", ["BNAME", "PROFILE"], ["PROFILE IN ('SAP_ALL','SAP_NEW','S_A.SYSTEM','S_A.ADMIN','S_A.DEVELOP')"], 2000),
    "critical_roles": ("AGR_USERS", ["AGR_NAME", "UNAME", "FROM_DAT", "TO_DAT"],
                       ["AGR_NAME LIKE 'SAP_BC_%' OR AGR_NAME LIKE 'SAP_ALL%' OR AGR_NAME LIKE '%ADMIN%'"], 2000),
    "rfc_destinations": ("RFCDES", ["RFCDEST", "RFCTYPE", "RFCOPTIONS"], None, 2000),
    "trusted_systems": ("RFCSYSACL", ["RFCSYSID", "RFCTRUSTSY", "RFCDEST", "RFCSNC"], None, 500),
    "security_parameters": ("PAHI", ["PARNAME", "PARVALUE", "PARDATE"],
                            ["PARNAME LIKE 'login/%' OR PARNAME LIKE 'rsau/%' OR PARNAME LIKE 'auth/%' OR PARNAME LIKE 'snc/%'",
                             "OR PARNAME LIKE 'gw/%' OR PARNAME LIKE 'icm/HTTPS%' OR PARNAME LIKE 'ms/acl%' OR PARNAME LIKE 'system/secure%'"], 3000),
    "components": ("CVERS", ["COMPONENT", "RELEASE", "EXTRELEASE", "COMP_TYPE"], None, 500),
    "applied_notes": ("CWBNTCUST", ["NUMM", "NTSTATUS", "PRSTATUS"], ["NTSTATUS = 'E'"], 5000),
}


def _rfc_options(opts):
    """RFCDES.RFCOPTIONS → safe flags. It can hold user names and a password marker; only flags leave this function."""
    parts = dict(p.split("=", 1) for p in (opts or "").split(",") if "=" in p)
    return {"host": parts.get("H", "")[:100], "user": parts.get("U", "")[:40], "client": parts.get("M", ""),
            "stored_password": "v" in parts or "P" in parts, "trusted": parts.get("Q") == "Y"}


def sap_read(f, pin, query, limit=None):
    """One fixed table read. Returns (rows, pin)."""
    table, cols, where, cap = SAP_QUERIES[query]
    base = _base(f["url"])
    ctx, pin = _ctx(base, f, pin)
    client = re.sub(r"\D", "", str(f.get("client") or ""))[:3]
    items = "".join(f"<item><FIELDNAME>{c}</FIELDNAME></item>" for c in cols)
    opts = "".join(f"<item><TEXT>{escape(w)}</TEXT></item>" for w in (where or []))
    env = ('<?xml version="1.0" encoding="utf-8"?><soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/">'
           '<soap-env:Body><urn:RFC_READ_TABLE xmlns:urn="urn:sap-com:document:sap:rfc:functions">'
           f"<DELIMITER>|</DELIMITER><QUERY_TABLE>{table}</QUERY_TABLE><ROWCOUNT>{min(limit or cap, cap)}</ROWCOUNT>"
           f"<FIELDS>{items}</FIELDS><OPTIONS>{opts}</OPTIONS><DATA/></urn:RFC_READ_TABLE></soap-env:Body></soap-env:Envelope>")
    auth = base64.b64encode(f"{f['username']}:{f['password']}".encode()).decode()
    url = f"{base}/sap/bc/soap/rfc" + (f"?sap-client={client}" if client else "")
    st, data = _req(url, ctx, "POST", {"Authorization": f"Basic {auth}", "Content-Type": "text/xml; charset=utf-8",
                                       "SOAPAction": "urn:sap-com:document:sap:rfc:functions"}, env.encode())
    if st == 401:
        raise BizError("sign-in refused: wrong user or password, or the user is locked")
    if st == 403:
        raise BizError("not allowed: the user lacks S_RFC for RFC_READ_TABLE or S_TABU_NAM for " + table)
    if st == 404:
        raise BizError("the SOAP RFC service (/sap/bc/soap/rfc) isn't active: activate it in SICF for this user's access")
    root = _xml(data)
    fault = next((e for e in root.iter() if e.tag.split("}")[-1] in ("faultstring", "message")), None)
    if st != 200 or fault is not None:
        raise BizError(f"SAP refused the read of {table}: {(fault.text if fault is not None else str(st))[:200]}")
    rows = []
    for wa in root.iter():
        if wa.tag.split("}")[-1] == "WA" and wa.text is not None:
            vals = [v.strip() for v in wa.text.split("|")]
            rows.append(dict(zip(cols, vals)))
    if query == "critical_profiles":
        rows = [r for r in rows if r.get("PROFILE") in CRITICAL_PROFILES]
    if query == "rfc_destinations":
        rows = [{"RFCDEST": r.get("RFCDEST"), "RFCTYPE": r.get("RFCTYPE"), **_rfc_options(r.get("RFCOPTIONS"))} for r in rows]
    return rows, pin


def test_sap(f, pin):
    try:
        rows, pin = sap_read(f, pin, "clients")
        own, _ = sap_read(f, pin, "critical_profiles")
    except BizError as e:
        raise conn.Result("error", str(e))
    mine = [r["PROFILE"] for r in own if r.get("BNAME", "").upper() == f["username"].upper() and r.get("PROFILE") in CRITICAL_PROFILES]
    details = [f"Clients: {', '.join(r['MANDT'] + ' ' + r.get('MTEXT', '') for r in rows)[:300]}",
               "Reads: users, roles and profiles, RFC destinations, trusted systems, security parameters, components, notes"]
    if mine:
        details.append(f"This user has {', '.join(mine)}: use a technical user with display authorizations only")
        return conn._done("warn", "Connected, but the user has powerful profiles", details, pin)
    return conn._done("ok", "Connected (read-only table reads)", details, pin)


# -- SAP BTP ------------------------------------------------------------------------------------------------------------
def _service_key(raw, what):
    try:
        k = json.loads(raw or "")
    except ValueError:
        raise BizError(f"The {what} isn't valid JSON: paste the whole service key")
    uaa = k.get("uaa") or k
    need = [x for x in ("url", "clientid", "clientsecret") if not uaa.get(x)]
    if need:
        raise BizError(f"The {what} is missing {', '.join(need)}")
    return k, uaa


def _uaa_token(uaa):
    url = _base(uaa["url"]) + "/oauth/token"
    body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": uaa["clientid"], "client_secret": uaa["clientsecret"]}).encode()
    st, data = _req(url, ssl.create_default_context(), "POST", {"Content-Type": "application/x-www-form-urlencoded"}, body)
    d = _json(data) if st == 200 else None
    if not isinstance(d, dict) or "access_token" not in d:
        raise BizError(f"BTP sign-in refused ({st})")
    return d["access_token"]


def _btp_get(base, token, path, params=None):
    url = base.rstrip("/") + path + ("?" + urllib.parse.urlencode(params) if params else "")
    st, data = _req(url, ssl.create_default_context(), headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    if st in (401, 403):
        raise BizError(f"not allowed to read {path}: check the service key's plan and roles")
    if st != 200:
        raise BizError(f"{path}: error {st}")
    return _json(data)


def _dest_safe(d):
    """A destination without its credentials: only what's needed to judge it."""
    host = urllib.parse.urlparse(d.get("URL") or "").hostname or ""
    return {"name": d.get("Name"), "type": d.get("Type"), "host": host, "https": (d.get("URL") or "").lower().startswith("https://"),
            "authentication": d.get("Authentication"), "proxy": d.get("ProxyType"),
            "trust_all": str(d.get("TrustAll", "")).lower() == "true"}


BTP_QUERIES = ("global_account", "subaccounts", "role_collections", "role_collection_users", "identity_providers", "destinations")


def btp_read(f, query, name=None):
    if query in ("global_account", "subaccounts"):
        k, uaa = _service_key(f["cis_key"], "Cloud Management service key")
        accounts = (k.get("endpoints") or {}).get("accounts_service_url")
        if not accounts:
            raise BizError("The Cloud Management service key has no accounts_service_url (use plan 'central')")
        tok = _uaa_token(uaa)
        if query == "global_account":
            d = _btp_get(accounts, tok, "/accounts/v1/globalAccount")
            return {k_: d.get(k_) for k_ in ("displayName", "guid", "licenseType", "commercialModel", "createdDate", "modifiedDate")} if isinstance(d, dict) else d
        d = _btp_get(accounts, tok, "/accounts/v1/subaccounts")
        return [{k_: s.get(k_) for k_ in ("displayName", "guid", "region", "subdomain", "betaEnabled", "usedForProduction", "state")}
                for s in (d or {}).get("value", [])]
    if query in ("role_collections", "role_collection_users", "identity_providers"):
        if not f.get("authz_key"):
            raise BizError("Add the authorization API service key (XSUAA, plan apiaccess) to read role collections and trust")
        k, uaa = _service_key(f["authz_key"], "authorization API service key")
        api = (uaa.get("apiurl") or k.get("apiurl") or "")
        tok = _uaa_token(uaa)
        if query == "role_collections":
            d = _btp_get(api, tok, "/sap/rest/authorization/v2/rolecollections")
            return [{"name": r.get("name"), "description": r.get("description"), "roles": len(r.get("roleReferences") or []),
                     "read_only": r.get("isReadOnly")} for r in (d or [])]
        if query == "role_collection_users":
            if not name or not re.fullmatch(r"[\w .()/-]{1,120}", name):
                raise BizError("give the role collection name, e.g. Subaccount Administrator")
            d = _btp_get(api, tok, "/sap/rest/authorization/v2/rolecollections/" + urllib.parse.quote(name), {"withUsers": "true"})
            users = (d or {}).get("userReferences") or []
            return {"name": name, "users": [{"username": u.get("username"), "origin": u.get("origin")} for u in users[:500]], "total": len(users)}
        d = _btp_get(api, tok, "/sap/rest/identity-providers")
        return [{"origin": i.get("originKey"), "name": i.get("name"), "type": i.get("type"), "active": i.get("active", i.get("status"))}
                for i in (d or [])] if isinstance(d, list) else d
    if query == "destinations":
        if not f.get("destination_key"):
            raise BizError("Add the destination service key to review destinations")
        k, uaa = _service_key(f["destination_key"], "destination service key")
        tok = _uaa_token(uaa)
        d = _btp_get(k.get("uri") or "", tok, "/destination-configuration/v1/subaccountDestinations")
        return [_dest_safe(x) for x in (d or []) if isinstance(x, dict)][:1000]
    raise BizError("unknown query")


def test_btp(f):
    try:
        ga = btp_read(f, "global_account")
        subs = btp_read(f, "subaccounts")
        details = [f"Global account: {ga.get('displayName')}", f"Subaccounts: {len(subs)}"]
        for key, q, label in (("authz_key", "role_collections", "Role collections"), ("destination_key", "destinations", "Destinations")):
            if f.get(key):
                details.append(f"{label}: {len(btp_read(f, q))}")
            else:
                details.append(f"{label}: not set up (optional key missing)")
    except BizError as e:
        raise conn.Result("error", str(e))
    return conn._done("ok", "Connected (read-only APIs)", details)


# -- Salesforce -----------------------------------------------------------------------------------------------------------
SF_API = "v61.0"
SF_QUERIES = {   # name: (tooling API?, SOQL)
    "health_check": (True, "SELECT Score, CustomBaselineId, DurableId FROM SecurityHealthCheck"),
    "health_check_risks": (True, "SELECT RiskType, Setting, SettingGroup, OrgValue, StandardValue FROM SecurityHealthCheckRisks"),
    "admins": (False, "SELECT Assignee.Username, Assignee.IsActive, Assignee.LastLoginDate, PermissionSet.Name, PermissionSet.IsOwnedByProfile, "
                      "PermissionSet.Profile.Name FROM PermissionSetAssignment WHERE (PermissionSet.PermissionsModifyAllData = true OR "
                      "PermissionSet.PermissionsManageUsers = true) AND Assignee.IsActive = true"),
    "inactive_users": (False, "SELECT Username, Profile.Name, LastLoginDate, CreatedDate FROM User WHERE IsActive = true AND UserType = 'Standard' "
                              "AND (LastLoginDate < LAST_N_DAYS:90 OR LastLoginDate = null)"),
    "mfa_methods": (False, "SELECT User.Username, HasUserVerifiedMobileNumber, HasTotp, HasU2F, HasSalesforceAuthenticator, HasBuiltInAuthenticator "
                           "FROM TwoFactorMethodsInfo"),
    "guest_users": (False, "SELECT Username, Profile.Name, IsActive FROM User WHERE UserType = 'Guest' AND IsActive = true"),
    "connected_apps": (False, "SELECT Name, CreatedDate, LastModifiedDate, OptionsAllowAdminApprovedUsersOnly, OptionsRefreshTokenValidityMetric "
                              "FROM ConnectedApplication"),
    "failed_logins": (False, "SELECT LoginType, Status, SourceIp, LoginTime, Application FROM LoginHistory WHERE Status != 'Success' "
                             "AND LoginTime = LAST_N_DAYS:7 ORDER BY LoginTime DESC LIMIT 500"),
    "org": (False, "SELECT Name, OrganizationType, InstanceName, IsSandbox, TrialExpirationDate FROM Organization"),
}


def _sf_token(f):
    base = _base(f["instance_url"])
    body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": f["client_id"], "client_secret": f["client_secret"]}).encode()
    st, data = _req(base + "/services/oauth2/token", ssl.create_default_context(), "POST", {"Content-Type": "application/x-www-form-urlencoded"}, body)
    d = _json(data)
    if st != 200 or not isinstance(d, dict) or "access_token" not in d:
        msg = (d or {}).get("error_description", "") if isinstance(d, dict) else ""
        raise BizError(f"Salesforce sign-in refused: {msg[:160] or st} (client credentials flow on, run-as user set?)")
    return base, d["access_token"]


def sf_read(f, query):
    tooling, soql = SF_QUERIES[query]
    base, tok = _sf_token(f)
    path = f"/services/data/{SF_API}/" + ("tooling/" if tooling else "") + "query"
    url = f"{base}{path}?q={urllib.parse.quote(soql)}"
    rows, pages = [], 0
    while url and pages < 10:
        st, data = _req(url, ssl.create_default_context(), headers={"Authorization": f"Bearer {tok}", "Accept": "application/json"})
        d = _json(data)
        if st != 200:
            err = d[0].get("message", "") if isinstance(d, list) and d else str(st)
            raise BizError(f"{query}: {err[:200]}")
        rows += [{k: v for k, v in r.items() if k != "attributes"} for r in (d or {}).get("records", [])]
        nxt = (d or {}).get("nextRecordsUrl")
        url = base + nxt if nxt and nxt.startswith("/services/data/") else None
        pages += 1
    return rows


def test_sf(f):
    try:
        org = sf_read(f, "org")
        score = sf_read(f, "health_check")
    except BizError as e:
        raise conn.Result("error", str(e))
    o = org[0] if org else {}
    details = [f"Org: {o.get('Name')} ({o.get('OrganizationType')}, {o.get('InstanceName')}{', sandbox' if o.get('IsSandbox') else ''})",
               f"Health Check score: {score[0].get('Score') if score else 'not readable'}"]
    return conn._done("ok", "Connected (read-only queries)", details)


def cap(rows):
    body = json.dumps(rows, default=str)
    if isinstance(rows, list) and len(body) > 30000:
        keep = max(1, int(len(rows) * 30000 / len(body)))
        return {"count": len(rows), "rows": rows[:keep], "truncated": True}
    return {"count": len(rows), "rows": rows} if isinstance(rows, list) else rows
