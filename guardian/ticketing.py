"""Ticketing: ServiceNow (first system). Guardian opens one incident per finding, keeps it across runs, adds work notes
when a re-check verifies a fix, and reads the ticket's state back into the Fix plan.

Uses the ServiceNow Table API (/api/now/table/<table>) with a dedicated integration user (basic auth). Like the alert
channels, the password is needed when nobody is signed in (tickets after a scheduled run), so it is protected by the
server's file permissions rather than the vault.
"""
import base64
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
