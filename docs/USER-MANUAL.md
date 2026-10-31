# AI IT Guardian · User manual

This manual walks through every screen of the Guardian console and the everyday tasks: running an assessment,
reading the results, fixing issues, compliance evidence and the settings.

> **About the screenshots.** They show a fictional sample site ("Demo office", network 192.168.50.0/24, demo
> accounts). No real network, device or person appears in them. Your console shows your own data in the same places.

**Contents**

1. [What Guardian does](#1-what-guardian-does)
2. [First-time setup](#2-first-time-setup)
3. [Signing in, roles and the vault](#3-signing-in-roles-and-the-vault)
4. [The dashboard](#4-the-dashboard)
5. [Running an assessment](#5-running-an-assessment)
6. [Run detail: the eight tabs](#6-run-detail-the-eight-tabs)
7. [Fix: remediation](#7-fix-remediation)
8. [Code & web apps](#8-code--web-apps)
9. [Settings](#9-settings)
10. [Everyday workflows](#10-everyday-workflows)
11. [Costs](#11-costs)
12. [Troubleshooting](#12-troubleshooting)
13. [Where to find more](#13-where-to-find-more)

---

## 1. What Guardian does

Guardian assesses a network the way a security consultant would, using a team of AI agents:

1. **Scan** (a normal program, no AI): finds every device, its open ports and services, TLS certificates, UPnP port
   forwards and what the internet sees on your public IP.
2. **Identify**: the Discovery agent works out what each device is (router, NAS, camera, printer…).
3. **Assess**: specialist agents look at the network, operating systems, web interfaces, firmware, the internet
   perimeter and, through **connectors** you set up, the inside of servers, Active Directory, Microsoft 365, Azure and
   your RMM.
4. **Analyse**: the Risk analyst ranks every finding (P1–P4), Attack paths chains them into realistic attacks, and
   Compliance maps them to CIS, ISO 27001, NIS2, the Swiss nLPD (and CIS Azure).
5. **Report**: a score, a grade, an executive summary and the actions that matter most.

Guardian is **read-only** by default. It changes something only when an admin turns remediation on and approves that
one change with a passkey (see [Fix](#7-fix-remediation)).

---

## 2. First-time setup

The installation itself is described in [INSTALL.md](../INSTALL.md). After the first start:

1. Open the console address (e.g. `https://guardian.example.com:8443`).
2. Enter the **first-time setup code** shown by the installer (also in `/opt/ai-guardian/console/setup-code`).
3. Create the first **admin** with a **passkey** (Face ID, Touch ID, Windows Hello or a security key).
4. Guardian creates the **vault** and shows a **recovery key** once. Store it offline (password manager, printed copy
   in a safe). It opens the vault if every admin passkey is lost.
5. Unlock the vault and go to **Settings › AI agents**:
   - **Anthropic API key**: from the Claude Console, ideally a dedicated workspace with a spend limit and a service
     account (role Developer). Enter the key's **expiry date** too: the dashboard then warns you 30 days before it
     expires.
   - **NVD API key** (optional, free from nvd.nist.gov): makes CVE look-ups faster.
6. Run a first **Scan only** to see your devices, then a **Scan + AI assessment**.

---

## 3. Signing in, roles and the vault

**Signing in** uses passkeys, optionally Google or Microsoft sign-in (set up in Settings › Security & vault). There are
no passwords.

**Roles**

| Role | Can |
|---|---|
| **Viewer** | Read runs, reports, fix plan, compliance |
| **Operator** | Everything a viewer can, plus start runs, edit the fix plan, re-check findings, add evidence, open tickets |
| **Admin** | Everything, plus settings, users, connectors, remediation, deleting evidence |

**The vault** holds every secret (API keys, connector passwords, evidence files, fix accounts) encrypted. It opens
only when an admin or operator confirms with their passkey, and closes on sign-out or after the idle time you set.

- The chip **VAULT UNLOCKED / LOCKED** at the top right shows its state; **Lock** closes it at once.
- While the vault is locked you can still read runs and reports, but AI runs, connectors, chat, evidence and exports
  need it unlocked.

---

## 4. The dashboard

![Dashboard](manual/01-dashboard.png)

**Site** (under the title, when there is more than one site): choose the customer site you work on, or **All sites**.
Everything below shows that site only.

![Customer site with a collector](manual/01c-remote-site.png)

A customer site with a collector has **Scan through collector** and **Scan + AI through collector**: the scan and
the AI agents' network checks run at the customer, and its on-site connectors (AD, Linux, Windows, Synology, Proxmox)
are checked there too, with the credentials sealed to that collector. The buttons are greyed out while the collector
is offline or paused by the customer. **New assessment** creates an assessment you fill by importing another
scanner's report in its Fix plan.

![All sites](manual/01b-all-sites.png)

**All sites** lists every site you may see with its score, last assessment, open priority 1 findings, overdue items,
open findings, collector and where its tickets go. Click a row to open the site. Details: [MULTISITE.md](MULTISITE.md).

**Left rail** (always visible): Overview, Agents, Map, Plan, Paths, Comply, Report, Log, Fix, Code and Settings
(the number on Settings counts connector suggestions waiting for you).

**Top**

| Element | What it does |
|---|---|
| **Scan only** | Network scan without AI: devices, ports, internet exposure. Free, about 7 minutes |
| **Scan + AI assessment** | Scan plus all agents and the report. About 30 minutes, about $4–7 of API credit for ~35 devices |
| **Open latest report** | Opens the most recent report in a new tab |
| **Replay agent map** | Replays how the agents worked in the latest run |
| Vault chip, **Lock**, your name, **Sign out** | Vault state and your session |

Theme, light / dark mode and text size are set only in **Settings › Appearance**.

**API key warning:** 30 days before the Anthropic key's expiry date (entered in Settings › AI agents), a yellow
banner at the top says when it expires and what to do; after the date it says AI runs have stopped.

**Posture / Status**: the latest assessment's headline, the **score** (0–100) and grade, number of **devices**,
**internet** port forwards, open **services**, and **open findings** by severity. **Findings / Trend** shows how the
number of open findings changes over assessments. **Run / Cost** shows the AI cost of the latest run per agent.

**Run / Now** (right): whether a run is in progress, how long it has been running and who started it.

Scrolling down:

![Dashboard, full](manual/02-dashboard-full.png)

- **Fix / First**: the top actions from the report.
- **Inventory**: every device with type, IP and risk.
- **Changes**: what changed since the previous run (new devices, new open ports, findings fixed or new).
- **Runs**: the history; click a run to open it in the workspace below.

---

## 5. Running an assessment

| Mode | When | Needs |
|---|---|---|
| **Scan only** | Any time; check for new devices or ports | nothing |
| **Scan + AI assessment** | Full assessment | API key, vault unlocked |
| **Re-run AI on a scan** | Re-analyse an existing scan (e.g. after adding a connector) | API key, vault unlocked |
| **Rebuild report** | Regenerate a report after changes | nothing |

While a run is going, the **Map & chat** and **Live log** tabs show what the agents do. You can stop a run at any time.

**Connectors and the vault:** agents that sign in through connectors (Active Directory, Patch & configuration,
Microsoft 365, Azure, NinjaOne…) only run when the vault was **unlocked when the run started**; Guardian hands them the
credentials in memory and never to the AI.

**Scheduled runs** are set in Settings › Schedules & alerts (see [§9](#schedules--alerts)).

---

## 6. Run detail: the eight tabs

Pick a run in **Runs** (or the latest is shown). The workspace has eight tabs; **Open in new tab** opens the report on
its own.

### 6.1 Report

![Report](manual/03-report.png)

The report a manager or customer reads: score and grade, headline, executive summary, findings per severity, **What
to fix first** (with effort and the finding IDs), then every finding with evidence and the recommended fix, the
devices, and the compliance summary. The report follows your theme from Settings › Appearance.

### 6.2 Fix plan

![Fix plan](manual/04-fix-plan.png)

Every open finding, ranked by the Risk analyst. Each row shows:

- **Priority** P1–P4 (P1 = fix within 7 days, P2 30, P3 90, P4 180), **severity**, **Actively exploited** (CISA KEV),
  **EPSS** (chance of exploitation in 30 days), **Internet / Internal** exposure, status.
- Open a row to see **Why this priority** and the **Fix**, and to set an **Owner**, a **Due** date (defaults from the
  priority), a **Status** (Open, In progress, Fixed – to verify, Risk accepted) and a **Note**.
- **Re-check** sends this one finding back to the agent that found it (a short, cheap follow-up). If it's fixed, the
  status becomes **Verified fixed**.
- **Open ticket** creates a ticket in your ticketing system (ServiceNow, ConnectWise PSA, Autotask, HaloPSA or Jira
  Service Management, if set up); the ticket number then shows on the row. **Sync tickets** reads the tickets' states
  back.

**Import results from another scanner** (top of the Fix plan): choose a **Nessus** (.nessus), **OpenVAS / Greenbone**,
**Qualys** or **Rapid7 InsightVM** XML export, or a **CSV** (columns ip, title, severity, and optionally cve, port,
description, solution), click **Preview** to see how many findings and devices it holds, then **Import**. Imported
findings show a **from Nessus** (etc.) chip and get a priority like the others (actively exploited CVEs and services
forwarded to the internet first). A finding Guardian already has on the same device (same CVE or title) isn't
duplicated: it shows **also 1 scanner**.

**Or pull them directly**: with a **Tenable**, **Qualys** or **Rapid7 InsightVM** connector for the run's site (Settings ›
Connectors › Scanners), pick it under the file box, **Preview**, then **Import**. Guardian reads the open findings
(medium and above) through the scanner's API with a read-only user; Tenable exports can take a few minutes. Details:
[IMPORT.md](IMPORT.md).

Filters: **Open**, **Overdue**, **Priority 1–2**, **Done**, **All**. Owners, dates, statuses and notes carry over to the
next assessment when the Risk analyst recognises the same issue.

### 6.3 Attack paths

![Attack paths](manual/05-attack-paths.png)

Realistic chains of weaknesses from an entry point (the internet, a phished user, a camera) to what the business
can't lose. Each step names its finding; **choke points** are the fixes that break a path, usually the best place to
start. A step can carry its ATT&CK technique ID.

### 6.3b ATT&CK

![ATT&CK matrix](manual/05b-attack-matrix.png)

The open findings in the MITRE ATT&CK Enterprise matrix: one column per tactic that has findings (Initial Access,
Credential Access, Lateral Movement…), one cell per technique, darker when more findings enable it. Click a cell to list
those findings; the technique ID opens its page on attack.mitre.org. The Risk analyst assigns up to five techniques per
finding; findings it hasn't ranked (or imported ones) get them from Guardian's built-in rules. The same IDs appear as
chips on Fix plan rows, in the report (a "What an attacker could do" section and on each finding) and in Appendix A of
the compliance PDF. Details: [ATTACK.md](ATTACK.md).

### 6.4 Compliance

![Compliance](manual/06-compliance.png)

One tab per framework: CIS Controls v8 IG1, ISO/IEC 27001:2022 Annex A, NIS2 Art. 21(2), Swiss revFADP / nLPD,
**PCI DSS v4.0** and **SOC 2** (Trust Services Criteria), plus CIS Microsoft Azure and CIS AWS Foundations when those
agents ran. The bar shows **Met / Partly / Gap / Not assessed**; filter by status below it.

![PCI DSS](manual/06b-compliance-pci.png)

PCI DSS and SOC 2 are mostly about processes, so many of their controls stay **Not assessed** until you add your own
status or evidence. Their control titles are paraphrased: check the official texts before an audit.

Click a control to:
- read the agent's note and the findings behind it;
- set **your own status** and a **note for the auditor** (kept for later assessments);
- **Add evidence** (PDF, PNG, JPG, TXT, CSV, DOCX, XLSX, up to 10 MB) with an optional *valid until* date.

Rules: a control with **open findings** keeps the gap even if you choose "Met"; evidence without a status counts as
**Partly**; expired evidence no longer counts. **Export** creates the **PDF** compliance report or an **evidence pack**
(ZIP with the PDF, the files and checksums). Details: [COMPLIANCE.md](COMPLIANCE.md).

### 6.5 Agents

![Agents](manual/07-agents.png)

Every agent of the run: status, what it did, rounds, checks per tool, tokens and cost. Click an agent to see each step
it took.

### 6.6 Map & chat

![Map and chat](manual/08-map-chat.png)

The live map: the Orchestrator in the middle, the specialists and analysts around it. Lines light up for orders
(orange), checks on the network (blue), findings, notes between agents (purple) and finished agents (green). The
timeline on the right lists every event; **Replay run** plays it back (1×, 3×, 8×).

**Talk / Orchestrator**: ask about the run ("why is the NAS P1?") or ask for more checks. The Orchestrator proposes
orders; nothing goes to an agent until an operator clicks **Send**. Everything stays read-only. Uses a little API
credit and needs the vault unlocked.

### 6.7 Live log

![Live log](manual/09-live-log.png)

The raw log of the run, useful when something fails.

---

## 7. Fix: remediation

![Fix page](manual/11-fix.png)

**Remediation / Status**: Guardian is read-only (**OFF**) until an admin clicks **Turn on · passkey** for 30 minutes,
1 hour or 4 hours. It turns itself off after that, or with **Turn off now**, or when Guardian restarts.

**Never / Automatic** lists what Guardian never changes: firmware, router WAN / firewall rules, the access path it
uses itself, anything without a backup.

**Fix / Proposals**: fixes for the latest run's findings. Each card shows the risk, the recipe, the finding, **why**,
**what could break**, and **backup / rollback**. A card without the needed fix account says what to add. With
remediation on, **Approve and apply · passkey** runs the change: backup → change → check → automatic rollback if the
check fails. Windows update proposals offer **Restart if needed**.

**Changes** lists every change record (CR-0001…) step by step, with **Roll back · passkey** where possible.

**Fix accounts** (admins):

![Fix accounts](manual/11-fix-accounts.png)

| Section | For |
|---|---|
| Linux servers (SSH) | A `guardian-fix` user with Guardian's key and exactly the sudo commands shown; optional Proxmox guest for snapshots |
| Proxmox snapshots | A token that may only take and roll back snapshots (taken before Linux updates) |
| Windows (WinRM) | A separate local admin account used only for approved fixes |
| Microsoft 365 fix app | A separate app with a short list of write permissions; Guardian refuses an app with more |
| NinjaOne patch jobs | A second NinjaOne API client (Management + Control) for approved patch jobs |

Available fixes: close a UPnP forward; SSH password login off; Linux updates and automatic updates; Windows SMBv1 off,
firewall on, Defender real-time on, Windows updates; Microsoft 365 external forwarding rules, stale accounts, legacy
sign-in block (report-only); NinjaOne OS patches. Details: [FIXES.md](FIXES.md).

---

## 8. Code & web apps

![Code scan](manual/12-code-scan.png)

**Repository scan.** Paste the address of a **GitHub**, **GitLab** (gitlab.com) or **Azure DevOps** repository to check it for malicious or risky code before you use
it: install scripts, obfuscated code, suspicious network calls, leaked secrets, typo-squatted dependencies, risky GitHub
workflows, and **infrastructure-as-code** mistakes (Terraform, Kubernetes, Dockerfiles, Bicep / ARM: open firewalls,
public storage, privileged containers, secrets in templates). Private repositories need a read-only token for that
service (Settings › Integrations). The result is a verdict with each finding, the file and line. Optional AI review of the
riskiest files (uses API credit).

![Web app and image checks](manual/12-web-check.png)

**Web app check.** A safe, read-only check of a web app you're responsible for: security headers, cookies, exposed
files (.git, .env, backups, actuator), error pages that leak details, CORS, directory listings, and, with a test
account's sign-in header, pages for signed-in users that also load without signing in. GET and HEAD only, the app's
own address only, at most 2 requests a second; links that look like actions are skipped and forms are never sent. An
admin starts it with a passkey and confirms being allowed to test the app. The sign-in value is never stored.

**Container image check.** Give an image (nginx:1.27, ghcr.io/org/app:2.1); Guardian reads it from the registry without
running it and checks the packages inside (Debian, Ubuntu, Alpine, Python, npm) against known vulnerabilities and
malware (OSV), plus root user, secrets in environment variables and a base OS out of support.

Both list their findings with **Add to Fix plan** (into the chosen site's latest assessment). Details: [WEB-AND-IMAGE-CHECKS.md](WEB-AND-IMAGE-CHECKS.md).

---

## 9. Settings

The left menu lists the sections. Some are for admins only.

### Connectors

![Connectors](manual/10-settings-connectors.png)

With more than one site, the **Site** box at the top chooses whose connectors you see and add; a connector belongs to
one site. For a customer site, connectors to systems inside its network (AD, Linux, Windows, Synology, Proxmox,
firewalls, VMware, Docker, Kubernetes) are checked at the customer through its collector; cloud ones from the server.

![Business systems connectors](manual/10-settings-business.png)

**Business systems** connectors (SAP S/4HANA / ECC, SAP BTP, Salesforce) feed the Business systems agent: default and
powerful SAP users, RFC destinations with stored passwords, security parameters, support-package level; BTP
administrators, identity providers and destinations; Salesforce Health Check, admins without MFA, guest users. Each
needs a read-only technical user or service key; the steps are on the card. Details: [BUSINESS-SYSTEMS.md](BUSINESS-SYSTEMS.md).

![Cloud connectors](manual/10-settings-cloud.png)

**Cloud** connectors: **Microsoft Azure** (Reader + Security Reader app; [AZURE.md](AZURE.md)) and **Amazon Web Services**
(a read-only role with SecurityAudit and ViewOnlyAccess, reached through sts:AssumeRole with an external ID; [AWS.md](AWS.md)).
The AWS agent checks root and IAM users, public S3 buckets and snapshots, security groups open to the internet, RDS,
CloudTrail, GuardDuty, Security Hub, Config and KMS, and maps them to CIS AWS Foundations in the compliance view.
**Google Cloud** and **Google Workspace** use a service account key with read-only roles and scopes; the Google agent
checks IAM (public or personal members, owners, old keys), open firewall rules, public buckets and Cloud SQL, and in
Workspace 2-step verification, admins, suspicious logins and alerts ([GOOGLE.md](GOOGLE.md)).

![Infrastructure connectors](manual/10-settings-infra.png)

**Infrastructure** connectors feed the Infrastructure agent: **VMware vSphere** (vCenter, Read-only role),
**Docker** (through a read-only socket proxy, because Docker's own API has no read-only mode) and **Kubernetes** (a
service account that can't read secrets). The **Firewall** connector (Endpoints & network: OPNsense, pfSense,
FortiGate, UniFi) reads firmware, rules, port forwards, admin access and VPN settings. Answers have passwords and keys
hidden. Details: [INFRASTRUCTURE.md](INFRASTRUCTURE.md).

![Scanner connectors](manual/10-settings-scanners.png)

**Scanners** (Tenable, Qualys, Rapid7 InsightVM) aren't used by agents: they let you pull those tools' findings into a
run's Fix plan (§6.2).

Connectors let Guardian look **inside** systems with a read-only account you create. **Suggested from your last scan**
proposes connectors for devices it found (e.g. a Synology NAS); **All connectors** lists every type with what it checks
and step-by-step instructions. Each connector has a **Test** that checks the account and warns if it has more rights
than needed.

| Connector | Used by |
|---|---|
| Active Directory | Active Directory agent |
| Linux (SSH), Windows (WinRM), Synology DSM, Proxmox VE / Backup Server | Patch & configuration agent |
| Microsoft 365 / Entra ID | Microsoft 365 & Entra ID, Device fleet agents |
| Microsoft Azure (separate Reader app) | Azure agent ([AZURE.md](AZURE.md)) |
| Amazon Web Services | AWS agent ([AWS.md](AWS.md)) |
| Google Workspace, Google Cloud | Google agent ([GOOGLE.md](GOOGLE.md)) |
| SAP S/4HANA / ECC, SAP BTP, Salesforce | Business systems agent ([BUSINESS-SYSTEMS.md](BUSINESS-SYSTEMS.md)) |
| Firewall, VMware vSphere, Docker, Kubernetes | Infrastructure agent ([INFRASTRUCTURE.md](INFRASTRUCTURE.md)) |
| Tenable, Qualys, Rapid7 InsightVM | Fix plan › Import (pull findings) |
| NinjaOne (RMM) | Patch & configuration agent |
| Email domain (DNS) | Internet perimeter (SPF, DKIM, DMARC) |

### Users & access

![Users](manual/10-settings-users.png)

Invite people (they set up their own passkey), choose their role, grant or revoke vault access, and see what each role
may do.

### Security & vault

![Security and vault](manual/10-settings-security.png)

Vault state and **auto-lock** (idle time and maximum), how secrets are protected, the **recovery key** (replace it if
it may have been seen), and **sign-in providers** (Google, Microsoft).

### My account

![My account](manual/10-settings-account.png)

Your passkeys (add a second one on another device), your name.

### AI agents

![AI agents](manual/10-settings-ai.png)

The Anthropic and NVD keys, the Anthropic key's **expiry date** (for the dashboard warning), the model and effort,
which agents run, and scaling for large sites (several copies of a specialist in parallel).

### Scan scope

![Scan scope](manual/10-settings-scope.png)

Today Guardian scans the network of its own interface. Choosing other networks and addresses to leave out is planned.

### Evidence library

![Evidence library](manual/10-settings-evidence.png)

Every evidence file: the controls it supports (`framework:control`, e.g. `iso27001:6.3`), validity date and state
(valid, expires soon, expired). Change the controls or the date, download, delete (admins). Files are encrypted with
the vault key and checked against their fingerprint.

### Sites & collectors

![Sites](manual/10-settings-sites.png)

Customer sites assessed through an on-site collector. **Add a site**, **Install**
(passkey: a one-time code and the commands for the Linux app, Docker or VM appliance), **Revoke**. Status shows Online,
Paused by customer, Disconnected by customer or Not reachable. Details: [ONSITE-COLLECTOR.md](ONSITE-COLLECTOR.md).

**Settings** on a site's row opens its own settings:

![Site settings](manual/10-site-general.png)

- **General**: name, customer and networks.
- **Ticketing**: where this customer's tickets go. **Our PSA** uses your system from Settings › Ticketing, filed under
  the customer (company, board, queue or project, depending on the system); **Customer's own system** uses their
  ServiceNow, Jira… with its own address and secret; **Off**. The auto-ticket priority and close-on-verify can follow
  the default or be set for this site. **Save and test** checks the connection with this site's settings.

![Site ticketing](manual/10-site-ticketing.png)

- **Access**: which operators and viewers may see the site (admins see all). A user nobody has limited sees every site.

![Site access](manual/10-site-access.png)

- **Disclosure**: a public vulnerability-disclosure page for this customer (NIS2 expects one) and a ready-made
  security.txt. Reports land here; **Add to Fix plan** or **Dismiss**. Details: [DISCLOSURE.md](DISCLOSURE.md).

![Site disclosure settings](manual/10-site-disclosure.png)

What the reporter sees:

![Disclosure page](manual/13-disclosure-page.png)

- **Decoys**: tracking links, fake admin logins (honey credentials) and bait Word documents. Guardian creates them, you
  place them; any use raises an alert (a sign-in with the planted password is high). Details: [DECOYS.md](DECOYS.md).

![Decoys](manual/10-site-decoys.png)

- **Connectors**: where to find this site's connectors. Details: [MULTISITE.md](MULTISITE.md).
- **Schedule**: a quick scan (daily or weekly) and a full scan + AI (weekly or monthly) through the site's
  collector. Skipped while the collector is offline or paused.

![Site schedule](manual/10-site-schedule.png)

**What the customer controls** on the collector: pause / resume and disconnect, quiet hours when no jobs run, a
status page on their LAN (HTTPS, own password) and automatic updates on or off. Every job is signed by Guardian and
checked against the customer's scope before it runs. Details: [ONSITE-COLLECTOR.md](ONSITE-COLLECTOR.md).

### Schedules & alerts

![Schedules and alerts](manual/10-settings-schedules.png)

- **Network scan**: off, daily or weekly (free).
- **Full AI assessment**: off, weekly or monthly (uses credit).
- **Scheduled AI runs while the vault is locked**: off by default; allowing it keeps a root-only copy of the API key
  (read the trade-off on the page).
- **Alerts** after each run: new findings at or above a priority, findings fixed, network changes; by e-mail, Microsoft
  Teams, Slack or webhook. **Send a test** checks the channels. Details: [SCHEDULES-ALERTS.md](SCHEDULES-ALERTS.md).

### Ticketing

![Ticketing](manual/10-settings-ticketing.png)

Pick the **system**: ServiceNow, ConnectWise PSA, Autotask PSA, HaloPSA or Jira Service Management. The fields
change with the system (address, API user, secret, and where tickets go: board, queue, customer or project). Then:
automatic tickets after each assessment for a chosen priority, closing the ticket when Guardian verifies the fix, and
**Test the connection**. These are the defaults; each site can send its tickets elsewhere (Sites & collectors ›
Settings › Ticketing). Details: [TICKETING.md](TICKETING.md).

### Integrations

![Integrations](manual/10-settings-integrations.png)

- **SIEM output**: after each run, one event per finding (new ones only, or all) to Microsoft Sentinel (Logs ingestion
  API), Splunk (HTTP Event Collector) or syslog (RFC 5424 over TLS, TCP or UDP). **Send a test event** checks them.
- **Private repositories**: read-only tokens for GitHub, GitLab and Azure DevOps, for scanning private repositories on
  the Code page.
- **MCP server**: tokens that let other AI tools (Claude Desktop, Claude Code and others) read Guardian's sites,
  findings, attack paths and ATT&CK map. Creating one needs your passkey; remove it to cut access at once.

Details: [INTEGRATIONS.md](INTEGRATIONS.md).

### Appearance

![Appearance](manual/10-settings-appearance.png)

Theme, light / dark mode and **text size** (useful on large 4K screens). Saved per user. This is the only place to
change them; every page and the report follow it.

---

## 10. Everyday workflows

**Weekly (5 minutes)**
1. Check the alert e-mail / Teams message after the scheduled scan.
2. Open the dashboard: new devices or ports under **Changes**?
3. Open **Fix plan › Overdue** and follow up with owners.

**After an AI assessment**
1. Read the **Report** headline and *What to fix first*.
2. In the **Fix plan**, give P1 and P2 findings an owner; open tickets if you use ServiceNow.
3. Look at **Attack paths** for choke points.
4. When something is fixed: set status **Fixed** and press **Re-check**.

**Fixing with Guardian**
1. Add the fix account the proposal asks for (Fix page › Fix accounts).
2. Turn remediation on (passkey), approve the change (passkey), watch the steps.
3. Re-check the finding.

**Preparing an audit**
1. In **Compliance**, go through "Not assessed" controls; add evidence (policies, training records, backup tests) and
   your status and notes.
2. Check the **Evidence library** for expired files.
3. **Export** the PDF, or the evidence pack for the auditor.

---

## 11. Costs

| Action | API cost (approx.) |
|---|---|
| Scan only | free |
| Full AI assessment, ~35 devices | $4–7 |
| Re-check of one finding | a few cents |
| Chat with the Orchestrator | a few cents per question |
| Code scan with AI review | a few cents to ~$1 |

The dashboard's **Run / Cost** shows the actual cost per agent. Set a monthly spend limit on the Claude Console
workspace you use for Guardian.

---

## 12. Troubleshooting

| Symptom | What to do |
|---|---|
| "Unlock the vault with your passkey first" | Click the vault chip and confirm with your passkey |
| An AI run fell back to "scan only" | The vault was locked at the scheduled time; run it by hand or allow unattended AI runs |
| A connector agent says "needs a connector" | The vault was locked when the run started, or the connector's test fails |
| Connector test fails | Follow the steps shown for that connector; check the account, network access and certificate |
| A finding is wrong | Set status **Risk accepted** with a note, or ask the Orchestrator to re-check it |
| Text too small on a big screen | Settings › Appearance › Text size |
| A fix shows "Needs attention" | Open the change record; the steps say what failed and what was rolled back |

---

## 13. Where to find more

| Topic | Document |
|---|---|
| Installation and certificates | [INSTALL.md](../INSTALL.md) |
| Every agent and what it checks | [AGENTS.md](AGENTS.md) |
| Schedules, alerts, fix plan | [SCHEDULES-ALERTS.md](SCHEDULES-ALERTS.md) |
| Ticketing (ServiceNow, ConnectWise, Autotask, HaloPSA, Jira) | [TICKETING.md](TICKETING.md) |
| Azure posture agent | [AZURE.md](AZURE.md) |
| AWS posture agent | [AWS.md](AWS.md) |
| Google Workspace and Google Cloud | [GOOGLE.md](GOOGLE.md) |
| Firewalls, VMware, Docker, Kubernetes | [INFRASTRUCTURE.md](INFRASTRUCTURE.md) |
| SAP, SAP BTP and Salesforce | [BUSINESS-SYSTEMS.md](BUSINESS-SYSTEMS.md) |
| MITRE ATT&CK mapping | [ATTACK.md](ATTACK.md) |
| Compliance evidence and PDF | [COMPLIANCE.md](COMPLIANCE.md) |
| Fixes and patching | [FIXES.md](FIXES.md) |
| Importing other scanners' results | [IMPORT.md](IMPORT.md) |
| On-site collector | [ONSITE-COLLECTOR.md](ONSITE-COLLECTOR.md) |
| Several customers (sites, access, ticketing per site) | [MULTISITE.md](MULTISITE.md) |
| SIEM output and MCP server | [INTEGRATIONS.md](INTEGRATIONS.md) |
| Vulnerability-disclosure page | [DISCLOSURE.md](DISCLOSURE.md) |
| Decoys | [DECOYS.md](DECOYS.md) |
| Web app and container image checks | [WEB-AND-IMAGE-CHECKS.md](WEB-AND-IMAGE-CHECKS.md) |
