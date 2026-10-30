"""MITRE ATT&CK (Enterprise) mapping: which attacker technique each finding enables.

The catalogue holds the techniques that the weaknesses Guardian finds lead to, each under its main tactic (some
techniques belong to several tactics in ATT&CK; the heat map shows them once). Findings are mapped by rules on their
title and evidence; the Risk analyst can set or refine the techniques per finding. IDs and names follow ATT&CK
Enterprise; check https://attack.mitre.org for the current version.
"""
import re

TACTICS = [("TA0043", "Reconnaissance"), ("TA0001", "Initial Access"), ("TA0002", "Execution"), ("TA0003", "Persistence"),
           ("TA0004", "Privilege Escalation"), ("TA0005", "Defense Evasion"), ("TA0006", "Credential Access"), ("TA0007", "Discovery"),
           ("TA0008", "Lateral Movement"), ("TA0009", "Collection"), ("TA0011", "Command and Control"), ("TA0010", "Exfiltration"),
           ("TA0040", "Impact")]

TECHNIQUES = {
    "T1595": ("Active Scanning", "TA0043"), "T1592": ("Gather Victim Host Information", "TA0043"),
    "T1190": ("Exploit Public-Facing Application", "TA0001"), "T1133": ("External Remote Services", "TA0001"),
    "T1078": ("Valid Accounts", "TA0001"), "T1078.001": ("Valid Accounts: Default Accounts", "TA0001"),
    "T1078.003": ("Valid Accounts: Local Accounts", "TA0001"), "T1078.004": ("Valid Accounts: Cloud Accounts", "TA0001"),
    "T1566": ("Phishing", "TA0001"), "T1199": ("Trusted Relationship", "TA0001"), "T1195": ("Supply Chain Compromise", "TA0001"),
    "T1203": ("Exploitation for Client Execution", "TA0002"), "T1059": ("Command and Scripting Interpreter", "TA0002"),
    "T1098": ("Account Manipulation", "TA0003"), "T1136": ("Create Account", "TA0003"), "T1505.003": ("Server Software Component: Web Shell", "TA0003"),
    "T1068": ("Exploitation for Privilege Escalation", "TA0004"), "T1548": ("Abuse Elevation Control Mechanism", "TA0004"),
    "T1484.001": ("Domain or Tenant Policy Modification: Group Policy", "TA0004"),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "TA0005"), "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", "TA0005"),
    "T1070": ("Indicator Removal", "TA0005"), "T1550": ("Use Alternate Authentication Material", "TA0005"),
    "T1110": ("Brute Force", "TA0006"), "T1110.003": ("Brute Force: Password Spraying", "TA0006"),
    "T1558.003": ("Steal or Forge Kerberos Tickets: Kerberoasting", "TA0006"), "T1558.004": ("Steal or Forge Kerberos Tickets: AS-REP Roasting", "TA0006"),
    "T1003": ("OS Credential Dumping", "TA0006"), "T1557": ("Adversary-in-the-Middle", "TA0006"), "T1040": ("Network Sniffing", "TA0006"),
    "T1552": ("Unsecured Credentials", "TA0006"), "T1528": ("Steal Application Access Token", "TA0006"),
    "T1621": ("Multi-Factor Authentication Request Generation", "TA0006"),
    "T1046": ("Network Service Discovery", "TA0007"), "T1087": ("Account Discovery", "TA0007"), "T1018": ("Remote System Discovery", "TA0007"),
    "T1210": ("Exploitation of Remote Services", "TA0008"), "T1021.001": ("Remote Services: Remote Desktop Protocol", "TA0008"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "TA0008"), "T1021.004": ("Remote Services: SSH", "TA0008"),
    "T1021.006": ("Remote Services: Windows Remote Management", "TA0008"),
    "T1114.003": ("Email Collection: Email Forwarding Rule", "TA0009"), "T1039": ("Data from Network Shared Drive", "TA0009"),
    "T1530": ("Data from Cloud Storage", "TA0009"), "T1125": ("Video Capture", "TA0009"),
    "T1071": ("Application Layer Protocol", "TA0011"), "T1572": ("Protocol Tunneling", "TA0011"), "T1219": ("Remote Access Software", "TA0011"),
    "T1567": ("Exfiltration Over Web Service", "TA0010"), "T1048": ("Exfiltration Over Alternative Protocol", "TA0010"),
    "T1486": ("Data Encrypted for Impact", "TA0040"), "T1490": ("Inhibit System Recovery", "TA0040"), "T1485": ("Data Destruction", "TA0040"),
    "T1498": ("Network Denial of Service", "TA0040"),
}

ID = re.compile(r"^T\d{4}(\.\d{3})?$")
# (pattern on title + evidence, techniques). Several rules can match one finding; the union is used.
RULES = [
    (r"\brdp\b|3389|remote desktop|\bnla\b", ["T1021.001", "T1133"]),
    (r"\bssh\b", ["T1021.004"]),
    (r"password (login|authentication)|brute.?force|lockout|weak password|password policy", ["T1110"]),
    (r"smb\s?v?1|\bsmb\b.*(signing|v1)|eternalblue", ["T1210", "T1021.002"]),
    (r"smb signing|ntlm|llmnr|nbt-?ns|wdigest", ["T1557"]),
    (r"\bwinrm\b|5985|5986", ["T1021.006"]),
    (r"\bmfa\b|multi-factor|2fa|two-factor|second factor", ["T1078", "T1110", "T1621"]),
    (r"legacy (auth|sign-?in|protocol)|basic auth|imap|pop3|smtp auth", ["T1110.003", "T1078"]),
    (r"kerberoast", ["T1558.003"]), (r"as-?rep", ["T1558.004"]),
    (r"default (password|credential|account|community|login)|community ['\"]?public|factory (password|default)", ["T1078.001"]),
    (r"laps|local admin", ["T1078.003"]),
    (r"stale|inactive|dormant|unused account|never signed", ["T1078"]),
    (r"global admin|domain admin|privileged|too many (owners|admins)|\bowner\b.*(guest|service principal)|admincount", ["T1078", "T1098"]),
    (r"guest|consent|oauth|third-party app|service principal", ["T1528", "T1078.004"]),
    (r"forward(ing|s)? (rule|mail)|mail.*forward|external forward|inbox rule", ["T1114.003"]),
    (r"firewall.{0,30}(off|disabled|not enabled)|(off|disabled).{0,20}firewall|nsg.*(any|0\.0\.0\.0)|open to (any|the internet)", ["T1562.004", "T1190"]),
    (r"defender|antivirus|anti-malware|real-?time protection|edr", ["T1562.001"]),
    (r"cleartext|plain-?text|unencrypted|telnet|\bftp\b|http (instead|without)|no tls|not encrypted", ["T1040", "T1557"]),
    (r"self-?signed|certificate|weak (tls|cipher)|tls 1\.[01]|sslv|expired cert", ["T1557"]),
    (r"upnp|port forward|exposed|reachable from the internet|internet-facing|public ip|shodan", ["T1190", "T1133"]),
    (r"admin (page|interface|panel)|login page|management interface|web interface|http header|security header", ["T1190"]),
    (r"missing (security )?updates|updates? pending|pending updates|patch|outdated|behind latest|end of (life|support)|unsupported|\beol\b", ["T1068", "T1210"]),
    (r"cve-\d{4}-\d+|vulnerab|exploit|remote code|rce|injection|bypass", ["T1210"]),
    (r"camera|nvr|hikvision|dahua", ["T1125"]),
    (r"backup|restore|snapshot|soft delete|immutab|recovery", ["T1490"]),
    (r"dmarc|spf|dkim|spoof", ["T1566"]),
    (r"public (blob|bucket|container|storage)|storage account.*public|anonymous (access|read)", ["T1530"]),
    (r"\bsnmp\b", ["T1592"]),
    (r"open (dns )?resolver|amplification", ["T1498"]),
    (r"share|nas|file server", ["T1039"]),
    (r"secret|api key|token|password in|credentials? (in|stored|exposed)|private key", ["T1552"]),
    (r"anydesk|teamviewer|remote access (tool|software)", ["T1219"]),
    (r"vpn", ["T1133"]),
]
_RULES = [(re.compile(p, re.I), ts) for p, ts in RULES]


def techniques(f):
    """The finding's techniques: the analyst's if set, otherwise from the rules. Most relevant first, at most 5."""
    own = [t for t in (f.get("attack") or []) if t in TECHNIQUES]
    if own:
        return own[:5]
    text = f'{f.get("title", "")} {f.get("evidence", "")[:600]}'
    out = []
    for rx, ts in _RULES:
        if rx.search(text):
            out += [t for t in ts if t not in out]
    if (f.get("risk") or {}).get("ransomware") and "T1486" not in out:
        out.append("T1486")
    if (f.get("risk") or {}).get("exposure") == "internet" and not ({"T1190", "T1133"} & set(out)):
        out.insert(0, "T1190")
    return out[:5]


def label(t):
    name, tactic = TECHNIQUES[t]
    return {"id": t, "name": name, "tactic": tactic, "tactic_name": dict(TACTICS)[tactic],
            "url": "https://attack.mitre.org/techniques/" + t.replace(".", "/") + "/"}


def matrix(findings):
    """Tactic columns with the techniques Guardian's open findings enable, and which findings."""
    by = {}
    for f in findings:
        for t in techniques(f):
            by.setdefault(t, []).append(f["id"])
    cols = []
    for tid, tname in TACTICS:
        cells = [{**label(t), "findings": fs} for t, fs in by.items() if TECHNIQUES[t][1] == tid]
        cols.append({"id": tid, "name": tname, "techniques": sorted(cells, key=lambda c: (-len(c["findings"]), c["id"]))})
    return {"tactics": cols, "techniques": len(by), "mapped": sum(1 for f in findings if techniques(f)), "total": len(findings)}


def catalog():
    return [{"id": t, "name": n, "tactic": dict(TACTICS)[ta]} for t, (n, ta) in TECHNIQUES.items()]
