"""Shadow AI: which AI apps and services a customer uses, found in what Guardian can already read.

Sources: apps users or admins connected to Microsoft 365 (service principals and their consents), apps authorised in
Google Workspace (token events), apps installed on managed devices (Intune detected apps, NinjaOne software), and AI
services in Azure (Azure OpenAI / AI services, Machine Learning, AI Search) and AWS (Bedrock logging and guardrails).
Everything is read-only; the names are matched against a fixed catalogue below.
"""
import re

# (pattern, product, vendor, note) - note flags what matters for a small business
CATALOG = [
    (r"chat\s?gpt|openai", "ChatGPT / OpenAI", "OpenAI", ""),
    (r"\bclaude\b|anthropic", "Claude", "Anthropic", ""),
    (r"\bgemini\b|\bbard\b", "Gemini", "Google", ""),
    (r"microsoft 365 copilot|m365 copilot|copilot for microsoft 365", "Microsoft 365 Copilot", "Microsoft", "sanctioned in most tenants"),
    (r"github copilot", "GitHub Copilot", "GitHub", ""),
    (r"perplexity", "Perplexity", "Perplexity", ""),
    (r"deepseek", "DeepSeek", "DeepSeek", "data processed in China"),
    (r"mistral|le chat", "Mistral Le Chat", "Mistral AI", ""),
    (r"\bgrok\b|x\.ai|xai", "Grok", "xAI", ""),
    (r"\bmeta ai\b", "Meta AI", "Meta", ""),
    (r"character\.ai|characterai", "Character.AI", "Character.AI", "consumer chatbot"),
    (r"\bpoe\b", "Poe", "Quora", ""),
    (r"otter\.?ai|\botter\b", "Otter.ai", "Otter.ai", "records and transcribes meetings"),
    (r"fireflies", "Fireflies.ai", "Fireflies.ai", "records and transcribes meetings"),
    (r"read\.ai|\bread ai\b", "Read AI", "Read AI", "records and transcribes meetings"),
    (r"tl;?dv", "tl;dv", "tl;dv", "records and transcribes meetings"),
    (r"fathom", "Fathom", "Fathom", "records and transcribes meetings"),
    (r"krisp", "Krisp", "Krisp", "meeting notes"),
    (r"grammarly", "Grammarly", "Grammarly", "reads what users type"),
    (r"quillbot", "QuillBot", "QuillBot", ""),
    (r"\bdeepl\b", "DeepL", "DeepL", "translation; free version may keep texts"),
    (r"jasper", "Jasper", "Jasper", ""),
    (r"copy\.ai", "Copy.ai", "Copy.ai", ""),
    (r"writesonic", "Writesonic", "Writesonic", ""),
    (r"notion ai", "Notion AI", "Notion", ""),
    (r"midjourney", "Midjourney", "Midjourney", ""),
    (r"cursor", "Cursor", "Anysphere", "code assistant"),
    (r"tabnine", "Tabnine", "Tabnine", "code assistant"),
    (r"codeium|windsurf", "Windsurf / Codeium", "Windsurf", "code assistant"),
    (r"replit", "Replit", "Replit", "code assistant"),
    (r"superhuman", "Superhuman", "Superhuman", "AI e-mail client"),
    (r"lindy", "Lindy", "Lindy", "AI agents with mailbox access"),
    (r"zapier", "Zapier (AI actions)", "Zapier", "automation with broad access"),
    (r"make\.com|integromat", "Make", "Make", "automation with broad access"),
    (r"n8n", "n8n", "n8n", "automation with broad access"),
    (r"hugging\s?face", "Hugging Face", "Hugging Face", ""),
    (r"ollama|lm studio|gpt4all|jan\.ai", "Local AI model runner", "various", "models running on the device"),
]
COMPILED = [(re.compile(p, re.I), name, vendor, note) for p, name, vendor, note in CATALOG]
# delegated permissions that let an app read company data on behalf of users
BROAD = re.compile(r"^(Mail\.Read|Mail\.ReadWrite|Mail\.Send|Files\.Read\.All|Files\.ReadWrite\.All|Sites\.Read\.All|"
                   r"Sites\.ReadWrite\.All|Calendars\.Read|Calendars\.ReadWrite|Chat\.Read|ChannelMessage\.Read\.All|"
                   r"OnlineMeetingTranscript\.Read\.All|OnlineMeetings\.Read|Notes\.Read\.All|Directory\.Read\.All|"
                   r"User\.Read\.All)$", re.I)


def classify(name, publisher=""):
    """The catalogue entry this app name matches, or None."""
    text = f"{name} {publisher}"
    for rx, product, vendor, note in COMPILED:
        if rx.search(text):
            return {"product": product, "vendor": vendor, "note": note}
    return None


def from_m365(sps, grants):
    """Service principals + delegated consents -> AI apps with who consented and which broad permissions they hold."""
    by_id = {}
    for g in grants:
        x = by_id.setdefault(g.get("clientId"), {"admin": False, "users": 0, "scopes": set()})
        if g.get("consentType") == "AllPrincipals":
            x["admin"] = True
        else:
            x["users"] += 1
        x["scopes"] |= set((g.get("scope") or "").split())
    out = []
    for sp in sps:
        hit = classify(sp.get("displayName") or "", (sp.get("verifiedPublisher") or {}).get("displayName") or sp.get("publisherName") or "")
        if not hit:
            continue
        g = by_id.get(sp.get("id"), {"admin": False, "users": 0, "scopes": set()})
        out.append({**hit, "app": sp.get("displayName"), "publisher_verified": bool((sp.get("verifiedPublisher") or {}).get("verifiedPublisherId")),
                    "admin_consent": g["admin"], "users_consented": g["users"],
                    "broad_permissions": sorted(s for s in g["scopes"] if BROAD.match(s)),
                    "all_permissions": sorted(g["scopes"])[:30], "source": "Microsoft 365 consent"})
    return out


def from_google_tokens(activities):
    """Workspace token 'authorize' events -> AI apps, how many users authorised them and the scopes."""
    apps = {}
    for a in activities:
        for e in a.get("events") or []:
            if e.get("name") != "authorize":
                continue
            p = {x.get("name"): x.get("value") or x.get("multiValue") for x in e.get("parameters") or []}
            hit = classify(str(p.get("app_name") or ""))
            if not hit:
                continue
            x = apps.setdefault(p.get("app_name"), {**hit, "app": p.get("app_name"), "users": set(), "scopes": set(),
                                                    "source": "Google Workspace authorisation"})
            x["users"].add((a.get("actor") or {}).get("email"))
            sc = p.get("scope")
            x["scopes"] |= set(sc if isinstance(sc, list) else str(sc or "").split())
    return [{**x, "users": len(x["users"]), "scopes": sorted(x["scopes"])[:20]} for x in apps.values()]


def from_software(items, source):
    """Installed software lists (Intune detected apps, NinjaOne) -> AI apps with device counts."""
    apps = {}
    for s in items:
        name = s.get("displayName") or s.get("name") or ""
        hit = classify(name, s.get("publisher") or "")
        if not hit:
            continue
        x = apps.setdefault(hit["product"], {**hit, "app": name, "devices": 0, "versions": set(), "source": source})
        x["devices"] += int(s.get("deviceCount") or 1)
        if s.get("version"):
            x["versions"].add(str(s["version"]))
    return [{**x, "versions": sorted(x["versions"])[:5]} for x in apps.values()]
