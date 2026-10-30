"""Ticketing: ServiceNow (first system). Guardian opens one incident per finding, keeps it across runs, adds work notes
when a re-check verifies a fix, and reads the ticket's state back into the Fix plan.

Uses the ServiceNow Table API (/api/now/table/<table>) with a dedicated integration user (basic auth). Like the alert
channels, the password is needed when nobody is signed in (tickets after a scheduled run), so it is protected by the
server's file permissions rather than the vault.
"""
import base64
import hashlib
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

INSTANCE_RE = re.compile(r"^https://[A-Za-z0-9-]+\.service-now\.com$|^https://[A-Za-z0-9.-]+\.[A-Za-z]{2,}(:\d+)?$")
# Guardian priority -> ServiceNow impact / urgency (1 = high, 3 = low); ServiceNow derives its own priority from these
IMPACT_URGENCY = {1: (1, 1), 2: (2, 1), 3: (2, 2), 4: (3, 3)}
# incident.state: 1 New, 2 In Progress, 3 On Hold, 6 Resolved, 7 Closed, 8 Canceled
STATE = {"1": "new", "2": "in_progress", "3": "on_hold", "6": "resolved", "7": "closed", "8": "canceled"}
CORRELATION = "ai-it-guardian"


class TicketError(Exception):
    pass


class ServiceNow:
    def __init__(self, cfg, password):
        self.base = cfg["instance"].rstrip("/")
        if not INSTANCE_RE.match(self.base):
            raise TicketError("The instance must look like https://yourcompany.service-now.com")
        self.table = cfg.get("table") or "incident"
        if not re.fullmatch(r"[a-z_][a-z0-9_]{0,79}", self.table):
            raise TicketError("Unknown table name")
        self.cfg = cfg
        self.auth = "Basic " + base64.b64encode(f'{cfg["username"]}:{password}'.encode()).decode()

    def _call(self, method, path, body=None, query=None):
        url = f"{self.base}/api/now/{path}" + ("?" + urllib.parse.urlencode(query) if query else "")
        req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": self.auth, "Accept": "application/json",
                                              "Content-Type": "application/json", "User-Agent": "AI-IT-Guardian"})
        try:
            with urllib.request.urlopen(req, timeout=20, context=ssl.create_default_context()) as r:
                return json.loads(r.read() or b"{}").get("result")
        except urllib.error.HTTPError as e:
            try:
                detail = json.loads(e.read()).get("error", {})
                msg = detail.get("message") or detail.get("detail") or str(e.code)
            except ValueError:
                msg = str(e.code)
            hint = {401: " (wrong user or password)", 403: " (the integration user lacks a role, e.g. itil)"}.get(e.code, "")
            raise TicketError(f"ServiceNow refused: {msg}{hint}") from None
        except (urllib.error.URLError, OSError) as e:
            raise TicketError(f"Can't reach ServiceNow: {getattr(e, 'reason', e)}") from None

    def test(self):
        rows = self._call("GET", f"table/{self.table}", query={"sysparm_limit": 1, "sysparm_fields": "number"})
        me = self._call("GET", "table/sys_user", query={"sysparm_query": f'user_name={self.cfg["username"]}',
                                                         "sysparm_fields": "user_name,roles", "sysparm_limit": 1})
        return {"table": self.table, "readable": rows is not None, "user": (me or [{}])[0].get("user_name", self.cfg["username"])}

    def url(self, sys_id):
        return f"{self.base}/nav_to.do?uri={self.table}.do?sys_id={sys_id}"

    def create(self, finding, run_id, console_url):
        prio = finding.get("priority") or 4
        impact, urgency = IMPACT_URGENCY.get(prio, (3, 3))
        r = finding.get("risk_info") or {}
        lines = [f"Guardian finding {finding['id']} (run {run_id}), priority P{prio}, severity {finding.get('severity')}.",
                 f"Device / scope: {finding.get('asset')}", ""]
        if finding.get("reason"):
            lines += ["Why this priority: " + finding["reason"], ""]
        lines += ["Evidence: " + (finding.get("evidence") or "")[:3000], "", "Fix: " + (finding.get("recommendation") or ""),
                  "", f"Due (Guardian target): {finding.get('due') or '-'}", f"Open in Guardian: {console_url}/"]
        body = {"short_description": f"[Guardian P{prio}] {finding['title']}"[:160], "description": "\n".join(lines),
                "impact": str(impact), "urgency": str(urgency), "correlation_id": f"{CORRELATION}:{finding['key']}"[:100],
                "correlation_display": "AI IT Guardian"}
        for k in ("assignment_group", "caller_id", "category", "cmdb_ci"):
            if self.cfg.get(k):
                body[k] = self.cfg[k]
        res = self._call("POST", f"table/{self.table}", body)
        return {"system": "servicenow", "number": res.get("number"), "sys_id": res.get("sys_id"), "url": self.url(res.get("sys_id")),
                "state": STATE.get(str(res.get("state")), str(res.get("state")))}

    def find(self, key):
        """An open ticket Guardian created earlier for the same issue (correlation id), or None."""
        rows = self._call("GET", f"table/{self.table}", query={
            "sysparm_query": f"correlation_id={CORRELATION}:{key}^stateNOT IN7,8", "sysparm_fields": "number,sys_id,state",
            "sysparm_limit": 1})
        if not rows:
            return None
        r = rows[0]
        return {"system": "servicenow", "number": r["number"], "sys_id": r["sys_id"], "url": self.url(r["sys_id"]),
                "state": STATE.get(str(r.get("state")), str(r.get("state")))}

    def state(self, sys_id):
        r = self._call("GET", f"table/{self.table}/{sys_id}", query={"sysparm_fields": "number,state,assigned_to,close_notes"})
        return {"state": STATE.get(str(r.get("state")), str(r.get("state"))),
                "assigned_to": (r.get("assigned_to") or {}).get("display_value") if isinstance(r.get("assigned_to"), dict) else None}

    def note(self, sys_id, text, resolve=False):
        body = {"work_notes": text[:4000]}
        if resolve:
            body.update(state="6", close_code=self.cfg.get("close_code") or "Solved (Permanently)", close_notes=text[:4000])
        self._call("PATCH", f"table/{self.table}/{sys_id}", body)


# -- shared helpers for the other systems ---------------------------------------------------------------------
HOST_RE = re.compile(r"^https://[A-Za-z0-9.-]+\.[A-Za-z]{2,}(:\d+)?$")
SEVERITY_WORD = {1: "critical", 2: "high", 3: "medium", 4: "low"}


def _http(method, url, headers, body=None, form=None, timeout=20):
    data = None
    h = {"Accept": "application/json", "User-Agent": "AI-IT-Guardian", **headers}
    if body is not None:
        data, h["Content-Type"] = json.dumps(body).encode(), "application/json"
    if form is not None:
        data, h["Content-Type"] = urllib.parse.urlencode(form).encode(), "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
            raw = r.read()
            return json.loads(raw) if raw.strip() else None
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")[:400]
        hint = {401: " (wrong credentials)", 403: " (the API user lacks a permission)", 404: " (not found: check the address or IDs)"}.get(e.code, "")
        raise TicketError(f"Refused ({e.code}){hint}: {raw[:200]}") from None
    except (urllib.error.URLError, OSError) as e:
        raise TicketError(f"Can't reach it: {getattr(e, 'reason', e)}") from None


def _base(url, what):
    url = (url or "").strip().rstrip("/")
    if not HOST_RE.match(url):
        raise TicketError(f"{what} must look like https://host")
    return url


def _text(finding, run_id, console_url):
    prio = finding.get("priority") or 4
    lines = [f"Guardian finding {finding['id']} (run {run_id}), priority P{prio}, severity {finding.get('severity')}.",
             f"Device / scope: {finding.get('asset')}", ""]
    if finding.get("reason"):
        lines += ["Why this priority: " + finding["reason"], ""]
    lines += ["Evidence: " + (finding.get("evidence") or "")[:3000], "", "Fix: " + (finding.get("recommendation") or ""), "",
              f"Due (Guardian target): {finding.get('due') or '-'}", f"Open in Guardian: {console_url}/",
              f"Guardian reference: {CORRELATION}:{finding['key']}"]
    return "\n".join(lines)


def _title(finding):
    return f"[Guardian P{finding.get('priority') or 4}] {finding['title']}"[:150]


# -- ConnectWise PSA (Manage REST API) -------------------------------------------------------------------------
class ConnectWise:
    """API member keys (public / private) + a clientId from developer.connectwise.com."""

    def __init__(self, cfg, secret):
        self.cfg, self.base = cfg, _base(cfg.get("site"), "Site") + "/v4_6_release/apis/3.0"
        auth = base64.b64encode(f'{cfg["company_id"]}+{cfg["public_key"]}:{secret}'.encode()).decode()
        self.h = {"Authorization": f"Basic {auth}", "clientId": cfg["client_id"]}

    def _ref(self, key):
        return hashlib.sha256(key.encode()).hexdigest()[:20]          # externalXRef holds up to ~100 characters

    def test(self):
        info = _http("GET", f"{self.base}/system/info", self.h)
        return {"system": f"ConnectWise {(info or {}).get('version', '')}".strip(), "user": self.cfg["public_key"][:6] + "…"}

    def create(self, f, run_id, console_url):
        prio = f.get("priority") or 4
        body = {"summary": _title(f)[:100], "initialDescription": _text(f, run_id, console_url), "externalXRef": self._ref(f["key"]),
                "board": {"name": self.cfg["board"]}, "company": {"identifier": self.cfg["company"]},
                "severity": {1: "High", 2: "High", 3: "Medium", 4: "Low"}[prio], "impact": {1: "High", 2: "Medium", 3: "Medium", 4: "Low"}[prio]}
        t = _http("POST", f"{self.base}/service/tickets", self.h, body)
        return self._out(t)

    def _out(self, t):
        st = "closed" if t.get("closedFlag") else ("new" if (t.get("status") or {}).get("name", "").lower().startswith("new") else "in_progress")
        return {"system": "connectwise", "number": f"#{t['id']}", "id": t["id"], "url": None, "state": st}

    def find(self, key):
        q = urllib.parse.urlencode({"conditions": f'externalXRef="{self._ref(key)}" and closedFlag=false', "pageSize": 1})
        rows = _http("GET", f"{self.base}/service/tickets?{q}", self.h) or []
        return self._out(rows[0]) if rows else None

    def state(self, tid):
        return {"state": self._out(_http("GET", f"{self.base}/service/tickets/{int(tid)}", self.h))["state"]}

    def note(self, tid, text, resolve=False):
        _http("POST", f"{self.base}/service/tickets/{int(tid)}/notes", self.h,
              {"text": text[:4000], "internalAnalysisFlag": True, "detailDescriptionFlag": False})
        if resolve:
            _http("PATCH", f"{self.base}/service/tickets/{int(tid)}", self.h,
                  [{"op": "replace", "path": "status/name", "value": self.cfg.get("closed_status") or "Closed (resolved)"}])


# -- Autotask PSA (REST API) ----------------------------------------------------------------------------------
class Autotask:
    """An API-only user (username, secret) and the integration code from Autotask › Admin › Resources."""
    COMPLETE = 5

    def __init__(self, cfg, secret):
        self.cfg, self.base = cfg, _base(cfg.get("zone_url"), "Zone URL") + "/ATServicesRest/V1.0"
        self.h = {"UserName": cfg["username"], "Secret": secret, "ApiIntegrationCode": cfg["integration_code"]}

    def test(self):
        v = _http("GET", f"{self.base}/Version", self.h)
        return {"system": f"Autotask {v if isinstance(v, str) else ''}".strip(), "user": self.cfg["username"]}

    def _out(self, t):
        st = t.get("status")
        return {"system": "autotask", "number": t.get("ticketNumber") or f"#{t['id']}", "id": t["id"], "url": None,
                "state": "resolved" if st == self.COMPLETE else ("new" if st == 1 else "in_progress")}

    def create(self, f, run_id, console_url):
        prio = f.get("priority") or 4
        body = {"companyID": int(self.cfg["company_id"]), "queueID": int(self.cfg["queue_id"]), "status": 1,
                "priority": {1: 4, 2: 1, 3: 2, 4: 3}[prio],            # Autotask: 4 Critical, 1 High, 2 Medium, 3 Low
                "title": _title(f)[:255], "description": _text(f, run_id, console_url)[:8000]}
        r = _http("POST", f"{self.base}/Tickets", self.h, body)
        t = _http("GET", f"{self.base}/Tickets/{int(r['itemId'])}", self.h)["item"]
        return self._out(t)

    def find(self, key):
        q = {"filter": [{"op": "contains", "field": "description", "value": f"{CORRELATION}:{key}"},
                        {"op": "noteq", "field": "status", "value": self.COMPLETE}], "MaxRecords": 1}
        rows = (_http("POST", f"{self.base}/Tickets/query", self.h, q) or {}).get("items") or []
        return self._out(rows[0]) if rows else None

    def state(self, tid):
        return {"state": self._out(_http("GET", f"{self.base}/Tickets/{int(tid)}", self.h)["item"])["state"]}

    def note(self, tid, text, resolve=False):
        _http("POST", f"{self.base}/Tickets/{int(tid)}/Notes", self.h,
              {"ticketID": int(tid), "title": "AI IT Guardian", "description": text[:3000], "noteType": 1, "publish": 2})
        if resolve:
            _http("PATCH", f"{self.base}/Tickets", self.h, {"id": int(tid), "status": self.COMPLETE})


# -- HaloPSA --------------------------------------------------------------------------------------------------
class HaloPSA:
    """An API application (client credentials) with permission to read and edit tickets."""
    CLOSED = 9

    def __init__(self, cfg, secret):
        self.cfg, self.url = cfg, _base(cfg.get("url"), "Halo address")
        self.secret, self._tok = secret, None

    def _h(self):
        if not self._tok:
            r = _http("POST", f"{self.url}/auth/token", {}, form={"grant_type": "client_credentials", "client_id": self.cfg["client_id"],
                                                               "client_secret": self.secret, "scope": "all"})
            self._tok = (r or {}).get("access_token")
            if not self._tok:
                raise TicketError("HaloPSA didn't return a token")
        return {"Authorization": f"Bearer {self._tok}"}

    def test(self):
        _http("GET", f"{self.url}/api/Tickets?count=1", self._h())
        return {"system": "HaloPSA", "user": self.cfg["client_id"][:8] + "…"}

    def _out(self, t):
        st = t.get("status_id")
        return {"system": "halopsa", "number": f"#{t['id']}", "id": t["id"], "url": f"{self.url}/ticket?id={t['id']}",
                "state": "closed" if st == self.CLOSED else ("new" if st == 1 else "in_progress")}

    def create(self, f, run_id, console_url):
        prio = f.get("priority") or 4
        body = [{"summary": _title(f), "details": _text(f, run_id, console_url).replace("\n", "<br>"),
                 "client_id": int(self.cfg["customer_id"]), "priority_id": prio,
                 **({"tickettype_id": int(self.cfg["tickettype_id"])} if self.cfg.get("tickettype_id") else {})}]
        r = _http("POST", f"{self.url}/api/Tickets", self._h(), body)
        return self._out(r[0] if isinstance(r, list) else r)

    def find(self, key):
        q = urllib.parse.urlencode({"search": f"{CORRELATION}:{key}", "open_only": "true", "count": 1})
        rows = (_http("GET", f"{self.url}/api/Tickets?{q}", self._h()) or {}).get("tickets") or []
        return self._out(rows[0]) if rows else None

    def state(self, tid):
        return {"state": self._out(_http("GET", f"{self.url}/api/Tickets/{int(tid)}", self._h()))["state"]}

    def note(self, tid, text, resolve=False):
        _http("POST", f"{self.url}/api/Actions", self._h(),
              [{"ticket_id": int(tid), "note": text[:4000], "outcome": "Private Note", "hiddenfromuser": True,
                **({"new_status": self.CLOSED} if resolve else {})}])


# -- Jira Service Management / Jira Cloud ---------------------------------------------------------------------
class Jira:
    """An Atlassian account e-mail and an API token (id.atlassian.com › Security › API tokens)."""

    def __init__(self, cfg, secret):
        self.cfg, self.url = cfg, _base(cfg.get("site"), "Site")
        self.h = {"Authorization": "Basic " + base64.b64encode(f'{cfg["email"]}:{secret}'.encode()).decode()}

    def _label(self, key):
        return "guardian-" + hashlib.sha256(key.encode()).hexdigest()[:16]

    @staticmethod
    def _adf(text):
        return {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": l}]} if l else
                                                          {"type": "paragraph", "content": []} for l in text.split("\n")]}

    def test(self):
        me = _http("GET", f"{self.url}/rest/api/3/myself", self.h)
        _http("GET", f"{self.url}/rest/api/3/project/{urllib.parse.quote(self.cfg['project_key'])}", self.h)
        return {"system": "Jira", "user": (me or {}).get("emailAddress") or self.cfg["email"]}

    def _out(self, key, fields=None):
        cat = (((fields or {}).get("status") or {}).get("statusCategory") or {}).get("key", "new")
        return {"system": "jira", "number": key, "id": key, "url": f"{self.url}/browse/{key}",
                "state": {"new": "new", "indeterminate": "in_progress", "done": "resolved"}.get(cat, "in_progress")}

    def create(self, f, run_id, console_url):
        fields = {"project": {"key": self.cfg["project_key"]}, "summary": _title(f), "issuetype": {"name": self.cfg.get("issuetype") or "Task"},
                  "description": self._adf(_text(f, run_id, console_url)), "labels": ["ai-it-guardian", self._label(f["key"])]}
        r = _http("POST", f"{self.url}/rest/api/3/issue", self.h, {"fields": fields})
        return self._out(r["key"])

    def find(self, key):
        jql = f'labels = "{self._label(key)}" AND statusCategory != Done'
        r = _http("POST", f"{self.url}/rest/api/3/search/jql", self.h, {"jql": jql, "maxResults": 1, "fields": ["status"]})
        rows = (r or {}).get("issues") or []
        return self._out(rows[0]["key"], rows[0].get("fields")) if rows else None

    def state(self, tid):
        r = _http("GET", f"{self.url}/rest/api/3/issue/{urllib.parse.quote(tid)}?fields=status", self.h)
        return {"state": self._out(tid, r.get("fields"))["state"]}

    def note(self, tid, text, resolve=False):
        _http("POST", f"{self.url}/rest/api/3/issue/{urllib.parse.quote(tid)}/comment", self.h, {"body": self._adf(text[:4000])})
        if resolve:
            tr = _http("GET", f"{self.url}/rest/api/3/issue/{urllib.parse.quote(tid)}/transitions", self.h).get("transitions", [])
            done = next((t for t in tr if ((t.get("to") or {}).get("statusCategory") or {}).get("key") == "done"), None)
            if done:
                _http("POST", f"{self.url}/rest/api/3/issue/{urllib.parse.quote(tid)}/transitions", self.h, {"transition": {"id": done["id"]}})


# -- what the console shows and stores per system ------------------------------------------------------------
def F(name, label, secret=False, placeholder="", required=True):
    return {"name": name, "label": label, "secret": secret, "placeholder": placeholder, "required": required}


SYSTEMS = {
    "servicenow": {"label": "ServiceNow", "fields": [
        F("instance", "Instance", placeholder="https://yourcompany.service-now.com"), F("username", "Integration user"),
        F("password", "Password", secret=True), F("assignment_group", "Assignment group (optional)", required=False),
        F("caller_id", "Caller (optional)", required=False), F("category", "Category (optional)", required=False)]},
    "connectwise": {"label": "ConnectWise PSA", "fields": [
        F("site", "API site", placeholder="https://api-eu.myconnectwise.net"), F("company_id", "Company ID (your login company)"),
        F("public_key", "Public key"), F("private_key", "Private key", secret=True),
        F("client_id", "Client ID (developer.connectwise.com)"), F("board", "Service board", placeholder="Service Desk"),
        F("company", "Customer company identifier", placeholder="MusterAG"),
        F("closed_status", "Status used to close (optional)", required=False, placeholder="Closed (resolved)")]},
    "autotask": {"label": "Autotask PSA", "fields": [
        F("zone_url", "Zone URL", placeholder="https://webservices16.autotask.net"), F("username", "API user"),
        F("secret", "Secret", secret=True), F("integration_code", "Tracking identifier (integration code)"),
        F("company_id", "Company ID (number)"), F("queue_id", "Queue ID (number)")]},
    "halopsa": {"label": "HaloPSA", "fields": [
        F("url", "Halo address", placeholder="https://yourcompany.halopsa.com"), F("client_id", "Client ID"),
        F("client_secret", "Client secret", secret=True), F("customer_id", "Customer (client) ID (number)"),
        F("tickettype_id", "Ticket type ID (optional)", required=False)]},
    "jira": {"label": "Jira Service Management", "fields": [
        F("site", "Site", placeholder="https://yourcompany.atlassian.net"), F("email", "Account e-mail"),
        F("api_token", "API token", secret=True), F("project_key", "Project key", placeholder="IT"),
        F("issuetype", "Issue type (optional)", required=False, placeholder="Task")]},
}
CLASSES = {"servicenow": ServiceNow, "connectwise": ConnectWise, "autotask": Autotask, "halopsa": HaloPSA, "jira": Jira}


def secret_field(system):
    return next(f["name"] for f in SYSTEMS[system]["fields"] if f["secret"])


def make(system, cfg, secret):
    if system not in CLASSES:
        raise TicketError("Unknown ticketing system")
    missing = [f["label"] for f in SYSTEMS[system]["fields"] if f["required"] and not f["secret"] and not str(cfg.get(f["name"]) or "").strip()]
    if missing:
        raise TicketError("Missing: " + ", ".join(missing))
    if system == "servicenow":
        return ServiceNow(cfg, secret)
    return CLASSES[system](cfg, secret)
