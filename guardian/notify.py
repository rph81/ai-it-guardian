"""Alerts after a run: e-mail, Microsoft Teams, Slack and a generic webhook.

Channel settings (SMTP password, webhook URLs) are needed when nobody is signed in, e.g. after a scheduled run at
night, so like the sign-in provider secrets they are protected by the server's file permissions, not the vault.
"""
import json
import smtplib
import ssl
import urllib.parse
import urllib.request
from email.message import EmailMessage

from .graph import is_open

THRESHOLDS = {"p1": 1, "p2": 2, "p3": 3, "all": 4}


def build_alert(graph_data, run_id, base_url, threshold="p2", changes_on=True):
    """Subject, plain-text body and a list of lines; None when there is nothing worth sending."""
    limit = THRESHOLDS.get(threshold, 2)
    ch = graph_data.get("changes") or {}
    lines = []
    fch = ch.get("findings")
    prio = lambda f: (f.get("risk") or {}).get("priority") or {"critical": 1, "high": 2, "medium": 3}.get(f.get("severity"), 4)
    if fch:
        new = [f for f in fch.get("new", []) if (f.get("priority") or 4) <= limit]
        for f in new[:15]:
            lines.append(f"New P{f.get('priority') or '?'}: {f['title']} ({f.get('asset')})")
        if fch.get("not_seen_again"):
            lines.append(f"{len(fch['not_seen_again'])} finding(s) from the previous assessment were not found again")
    elif graph_data.get("summary"):
        for f in sorted((f for f in graph_data.get("findings", []) if is_open(f) and prio(f) <= limit), key=prio)[:15]:
            lines.append(f"P{prio(f)}: {f['title']} ({f.get('asset')})")
    sch = ch.get("scan")
    if changes_on and sch:
        for k, label in (("new_devices", "New device"), ("gone_devices", "Device gone"), ("new_ports", "New open port"),
                         ("new_internet_ports", "New port open to the internet"), ("new_forwards", "New router port forward"),
                         ("new_internet_cves", "New CVE listed for the public IP")):
            for item in (sch.get(k) or [])[:10]:
                lines.append(f"{label}: {item}")
    if not lines:
        return None
    s = graph_data.get("summary") or {}
    head = f"score {s['score']} ({s['grade']}) · " if s.get("score") is not None else ""
    subject = f"Guardian: {len(lines)} item(s) need attention · {head}run {run_id}"
    body = "\n".join(["Guardian finished a run and found:", ""] + [f"- {l}" for l in lines] +
                     ["", f"Open the console: {base_url}/", "Guardian is read-only: nothing on the network was changed."])
    return {"subject": subject, "body": body, "lines": lines}


def _post(url, payload, timeout=15):
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError("Webhook addresses must start with https://")
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json",
                                                                               "User-Agent": "AI-IT-Guardian"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status


def send(cfg, alert):
    """Send to every enabled channel; returns {channel: "ok" | error text}."""
    out = {}
    if cfg.get("email", {}).get("on"):
        e = cfg["email"]
        try:
            msg = EmailMessage()
            msg["Subject"], msg["From"], msg["To"] = alert["subject"], e["sender"], ", ".join(e["to"])
            msg.set_content(alert["body"])
            ctx = ssl.create_default_context()
            if int(e.get("port", 587)) == 465:
                s = smtplib.SMTP_SSL(e["host"], 465, context=ctx, timeout=20)
            else:
                s = smtplib.SMTP(e["host"], int(e.get("port", 587)), timeout=20)
                s.starttls(context=ctx)
            with s:
                if e.get("username"):
                    s.login(e["username"], e.get("password", ""))
                s.send_message(msg)
            out["email"] = "ok"
        except Exception as x:                                  # noqa: BLE001 - reported per channel
            out["email"] = f"{type(x).__name__}: {x}"[:200]
    text = alert["subject"] + "\n\n" + alert["body"]
    for ch, payload in (
        # Teams "Workflows" webhooks (Post to a channel when a webhook request is received) take an Adaptive Card
        ("teams", {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
            "body": [{"type": "TextBlock", "text": alert["subject"], "weight": "Bolder", "wrap": True},
                     *[{"type": "TextBlock", "text": "• " + l, "wrap": True, "spacing": "None"} for l in alert["lines"][:25]]]}}]}),
        ("slack", {"text": text}),
        ("webhook", {"source": "ai-it-guardian", "subject": alert["subject"], "items": alert["lines"], "text": alert["body"]}),
    ):
        url = cfg.get(ch, {}).get("url") if cfg.get(ch, {}).get("on") else None
        if url:
            try:
                _post(url, payload)
                out[ch] = "ok"
            except Exception as x:                              # noqa: BLE001 - reported per channel
                out[ch] = f"{type(x).__name__}: {x}"[:200]
    return out
