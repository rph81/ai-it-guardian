# AI IT Guardian

A read-only IT and security assessment of a small business network, done by a team of AI agents.
A scanner maps the network; Claude agents identify every device, assess each layer, talk to each other when
one finds something another should check, and write a prioritized report for the business owner.
You watch them work live and can talk to the Orchestrator that coordinates them.

**Installing: see [INSTALL.md](INSTALL.md)**. It covers everything from creating the Proxmox container to the first report.
**The agents, what each one checks and which products it is modelled on: [docs/AGENTS.md](docs/AGENTS.md).**
**Schedules, alerts and the fix plan: [docs/SCHEDULES-ALERTS.md](docs/SCHEDULES-ALERTS.md).**
**Ticketing (ServiceNow): [docs/TICKETING.md](docs/TICKETING.md).**
**User manual (every screen, with screenshots): [docs/USER-MANUAL.md](docs/USER-MANUAL.md).**
**Azure posture agent: [docs/AZURE.md](docs/AZURE.md).**
**Compliance evidence and PDF: [docs/COMPLIANCE.md](docs/COMPLIANCE.md).**
**Fixes and patching (agentless and NinjaOne): [docs/FIXES.md](docs/FIXES.md).**
**On-site collector (sites at customers): [docs/ONSITE-COLLECTOR.md](docs/ONSITE-COLLECTOR.md).**

Nothing on the network is changed. Agents have no shell: only fixed, non-intrusive checks, web requests without
credentials, and public vulnerability lookups (NVD, CISA KEV, FIRST EPSS, endoflife.date).

## What's in it

| Part | What it does |
|---|---|
| **Scanner** (`guardian/collector.py`) | ARP, ports, services, OS guesses, web titles, TLS, UPnP, mDNS, router forwards, what the internet sees on the public IP. No AI, free, ~7 min. |
| **Agents** (`guardian/agents.py`) | Discovery → Orchestrator → specialists (Network, OS & endpoints, Web & APIs, Firmware, Internet perimeter), a few at a time → analysts (Risk analyst, Attack paths, Compliance) → Report writer. See [docs/AGENTS.md](docs/AGENTS.md). |
| **Active Directory** (`guardian/access.py`) | Through the AD connector (normal domain user, LDAPS): admins, Kerberoastable / AS-REP roastable accounts, delegation, password and lockout policy, krbtgt age, stale accounts, end-of-life Windows, LAPS. Modelled on Tenable Identity Exposure. |
| **Patch & configuration** (`guardian/access.py`) | Through the Linux SSH, Synology and Proxmox connectors: pending security updates, OSV-vulnerable packages, reboot needed, end-of-life OS, SSH, firewall, users, hardening; DSM version; Proxmox updates, users, backup jobs. Fixed read-only checks only. Modelled on Nessus credentialed scans and Qualys VMDR. |
| **Microsoft 365 & Entra ID**, **Device fleet** | Through the Microsoft 365 connector (an app with read-only Graph permissions): MFA and Conditional Access, legacy sign-ins, admins, guests, app consents, forwarding rules, Secure Score; Intune compliance, encryption, stale devices, end-of-life OS, Defender alerts. |
| **Risk analyst** | Ranks every finding P1–P4 by real-world risk: actively exploited (CISA KEV) and ransomware use, EPSS exploitation probability, internet exposure, device criticality. Merges duplicates; links findings to the previous assessment. Modelled on Tenable VPR, Qualys TruRisk, Rapid7 Active Risk. |
| **Attack paths** | Chains findings into realistic paths to what matters most and names the choke-point fixes. Reasoned from evidence, never exploited. Modelled on Tenable One, Wiz toxic combinations, NodeZero narratives. |
| **Compliance** (`guardian/controls.py`) | Maps the assessment to CIS Controls v8 IG1 (56), ISO 27001:2022 Annex A (93), NIS2 Art. 21 (10) and Swiss revFADP / nLPD (9): met, partly, gap or not assessed, with evidence. |
| **Fix plan** | Per finding: owner, due date from the priority (P1 7 days … P4 180), status, note, **Re-check** by the agent that found it; carried over to the next assessment. |
| **Schedules & alerts** (`guardian/notify.py`, `guardian/changes.py`) | Daily/weekly scans and weekly/monthly AI assessments; after each run, alerts by e-mail, Teams, Slack or webhook with new priority findings and network changes since the last run. |
| **Scaling** | For big sites, a specialist's devices are split across several copies that run in parallel: automatic (devices per copy) or manual, with min/max copies per agent (Settings → AI agents). |
| **Agent notes** | A specialist that finds something in another's area sends it a note (`send_note`). The Orchestrator delivers it on the receiver's next round, adds it to its brief if it hasn't started, or runs a follow-up if it has finished. |
| **Console** (`console.py`, `guardian/web/`) | HTTPS web app: an overview of the selected run (posture, exposure, fix-first findings, riskiest devices, trend, cost), start/stop runs, reports, live **Agents** cards, the live **agent map** (with replay), the **Orchestrator chat**, settings. |
| **Themes** (`guardian/web/theme.js`, `console.css`) | Light / dark / system, and five colour themes (Ember, Arctic, Volt, Crimson, Mono), saved per account. Text size: Auto (grows with the window on large screens, e.g. 215% on a 4K screen) or a fixed 100–200%. Fonts are served locally (`guardian/web/fonts/`, SIL OFL), so the console never contacts a third party. |
| **Orchestrator chat** (`guardian/chat.py`) | Ask about a run; ask for re-checks. It proposes orders; an operator confirms each one before an agent gets it. |
| **Vault** (`guardian/vault.py`) | Users, passkeys (with PRF), encrypted secrets (API keys, connector passwords, SSH key), tamper-evident audit log. |
| **Sign-in** (`guardian/auth.py`) | Passkeys (Touch ID, Face ID, Windows Hello, security keys); optionally Google / Microsoft accounts. Roles: viewer, operator, admin. |
| **Connectors** (`guardian/connectors.py`) | Read-only accounts on systems (Synology, Proxmox, Linux SSH, SNMPv3, AD, e-mail domain…), suggested from the scan. Tested and stored now; used by agents in a later phase. |
| **Code scan** (`guardian/codescan.py`, `/code`) | Paste a public GitHub link: Guardian reads one archive of that commit in memory (never runs it), applies static rules (install scripts, hidden code, exfiltration, credential theft, leaked keys, risky Actions, binaries, typosquats), checks dependencies with OSV (CVEs and known malware), and the Code agent reviews the flagged files and gives a verdict. Runs in its own process with memory, CPU and time limits. |
| **Report** (`guardian/report.py`) | One self-contained HTML file: score, summary, fix-first list, attack paths, compliance summary, findings with priority and evidence. |

## What it costs to run

| | |
|---|---|
| Scan only | free |
| Full AI assessment, Opus 5.5 (default), ~35 devices | about **$4–7** with prompt caching (about $10–20 without) |
| Same on Fable 5.1 | about 2.5× more |
| A chat question | a few cents |
| A follow-up re-check by one agent | about $0.30–1.50 |

Each run's real cost is shown per agent in the console (Agents tab, and in the runs list).

## How a run is recorded

Each run is a folder `runs/<date-time>/`:

- `graph.json`: everything known (devices, findings, agent states and costs, notes between agents, plan, summary)
- `events.jsonl`: one line per event (order, check, finding, note, done…), which the agent map draws
- `chat.json`: the Orchestrator chat for that run, including proposed and sent orders
- `inbox.jsonl`: orders sent from the chat (and Re-check) to the agents
- `tracking.json`: the fix plan (owner, due date, status, note per finding), written only by the console
- `report.html`: the report

`graph.json` also holds `attack_paths`, `compliance` (status per framework and control), `changes` (devices, ports,
internet exposure and findings compared with the previous run) and, per finding, `risk` (priority, reason, KEV, EPSS,
exposure) and `previous` (the same issue in the previous assessment).

## Safety rules the code enforces

- Agents only call the tools listed for their layer; every address is checked against the scanned network.
- HTTP is GET/HEAD only, without credentials; probes are nmap scripts from the safe/discovery categories.
- Text found on the network (banners, pages, device names) is passed to agents as data, never as instructions.
- The chat can't send orders by itself: it proposes them, and an operator confirms.
- Connector credentials reach a run through a pipe, live only in its memory, and are used by fixed, named read-only
  checks; agents never see them. Connector agents run only when the vault was unlocked when the run started.
- Analysts work on the findings only; the only outside data they fetch is the public CISA KEV and FIRST EPSS feeds
  (and web search for the Risk analyst). They can't send notes or start other agents.
- API keys are given to a run in memory only; agents never see them or connector passwords.
- Code scans never execute repository code. The Code agent's only tools read files from the archive and record findings
  (no shell, network or web search); text in the code addressed to reviewers is flagged, not obeyed; secrets found are masked.

## Roadmap

1. **Now**: read-only assessment, live agents, agent-to-agent notes, Orchestrator chat, cost tracking.
   **Agents v2, wave 1 (now)**: Risk analyst, Attack paths, Compliance; fix plan with re-check; schedules; alerts.
   **Wave 2 (now)**: Active Directory agent; Patch & configuration agent (Linux SSH, Synology, Proxmox).
   **Wave 3 (now)**: Microsoft 365 connector with Microsoft 365 & Entra ID and Device fleet agents; Windows (WinRM)
   connector in Patch & configuration.
   **Ticketing**: ServiceNow incidents per finding, auto-created after runs, state synced into the Fix plan.
   **Azure (now)**: Azure posture agent (Defender for Cloud, exposure, network, storage, databases, Key Vault, VMs,
   identity, logging, backup, policy) and the CIS Microsoft Azure Foundations framework.
   **Compliance pack (now)**: evidence uploads per control (encrypted, with validity), your own status and notes,
   compliance PDF and evidence pack (ZIP with checksums).
   **Fixes and patching (now)**: agentless Linux and Windows updates and hardening, Microsoft 365 fixes through a
   separate fix app, NinjaOne patch status and patch jobs; Proxmox snapshots before Linux updates.
   **On-site collector, phase A (now)**: sites, collector gateway, enrollment, heartbeat, revoke; collector with
   pause / disconnect. Phase B: scans and AI assessments through the collector.
   **Ticketing (now)**: ServiceNow, ConnectWise PSA, Autotask PSA, HaloPSA, Jira Service Management.
   **Next, in this order**: several customers (sites)
   in one console; import of other scanners' results; MITRE ATT&CK mapping; integrations with business systems
   (SAP S/4HANA, SAP BTP and other leading platforms); medium / low priority gap features; AWS posture agent;
   on-site collector phases B–D. Then a **final testing phase** against real systems (real AI run, AD, Microsoft 365, fix recipes, NinjaOne,
   Azure, Windows, ServiceNow, alert channels, collector packages, outside penetration test of the gateway).
   Built-in VPN client: on hold pending a design review (the on-site collector covers most of the need).
2. **Next**: agents use the connectors (inside view of NAS, hypervisors, servers); more connector sign-in methods
   (Kerberos, WinRM, OAuth with certificates, client certificates, TOTP); Microsoft 365 and Google Workspace;
   RADIUS / TACACS+ / 802.1X checks.
3. **Now (first recipes)**: remediation on the **Fix** page. Off by default; an admin turns it on with a passkey for 30 min to 4 h and approves each change with a passkey again. Active recipes: close a UPnP port forward, turn off SSH password login (Linux, through a separate `guardian-fix` account with 6 allowed sudo commands). Every change is backed up first, verified, rolled back automatically if the check fails, and recorded (CR-0001…) in the audit log. Firmware, WAN/firewall rules and Guardian's own access path always stay manual.

## Command line

See [INSTALL.md § 11](INSTALL.md#11-command-line-optional). In short:

| Command | What it does |
|---|---|
| `run.py --collect-only` | scan only |
| `run.py` | scan + agents + report |
| `run.py --resume runs/<dir>` | agents + report on an existing scan |
| `run.py --followup runs/<dir>` | run orders sent from the chat, then refresh the report |
| `run.py --report runs/<dir>` | rebuild the report |
