# AI IT Guardian

A read-only IT and security assessment of a small business network, done by a team of AI agents.
A scanner maps the network; Claude agents identify every device, assess each layer, talk to each other when
one finds something another should check, and write a prioritized report for the business owner.
You watch them work live and can talk to the Orchestrator that coordinates them.

**Installing: see [INSTALL.md](INSTALL.md)**. It covers everything from creating the Proxmox container to the first report.

Nothing on the network is changed. Agents have no shell: only fixed, non-intrusive checks, web requests without
credentials, and public vulnerability lookups (NVD, CISA KEV, endoflife.date).

## What's in it

| Part | What it does |
|---|---|
| **Scanner** (`guardian/collector.py`) | ARP, ports, services, OS guesses, web titles, TLS, UPnP, mDNS, router forwards, what the internet sees on the public IP. No AI, free, ~7 min. |
| **Agents** (`guardian/agents.py`) | Discovery → Orchestrator → specialists (Network, OS & endpoints, Web & APIs, Firmware, Internet perimeter), a few at a time → Report writer. |
| **Scaling** | For big sites, a specialist's devices are split across several copies that run in parallel: automatic (devices per copy) or manual, with min/max copies per agent (Settings → AI agents). |
| **Agent notes** | A specialist that finds something in another's area sends it a note (`send_note`). The Orchestrator delivers it on the receiver's next round, adds it to its brief if it hasn't started, or runs a follow-up if it has finished. |
| **Console** (`console.py`, `guardian/web/`) | HTTPS web app: an overview of the selected run (posture, exposure, fix-first findings, riskiest devices, trend, cost), start/stop runs, reports, live **Agents** cards, the live **agent map** (with replay), the **Orchestrator chat**, settings. |
| **Themes** (`guardian/web/theme.js`, `console.css`) | Light / dark / system, and five colour themes (Ember, Arctic, Volt, Crimson, Mono), saved per account. Text size: Auto (grows with the window on large screens, e.g. 215% on a 4K screen) or a fixed 100–200%. Fonts are served locally (`guardian/web/fonts/`, SIL OFL), so the console never contacts a third party. |
| **Orchestrator chat** (`guardian/chat.py`) | Ask about a run; ask for re-checks. It proposes orders; an operator confirms each one before an agent gets it. |
| **Vault** (`guardian/vault.py`) | Users, passkeys (with PRF), encrypted secrets (API keys, connector passwords, SSH key), tamper-evident audit log. |
| **Sign-in** (`guardian/auth.py`) | Passkeys (Touch ID, Face ID, Windows Hello, security keys); optionally Google / Microsoft accounts. Roles: viewer, operator, admin. |
| **Connectors** (`guardian/connectors.py`) | Read-only accounts on systems (Synology, Proxmox, Linux SSH, SNMPv3, AD, e-mail domain…), suggested from the scan. Tested and stored now; used by agents in a later phase. |
| **Report** (`guardian/report.py`) | One self-contained HTML file: score, summary, fix-first list, findings with evidence. |

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
- `inbox.jsonl`: orders sent from the chat to the agents
- `report.html`: the report

## Safety rules the code enforces

- Agents only call the tools listed for their layer; every address is checked against the scanned network.
- HTTP is GET/HEAD only, without credentials; probes are nmap scripts from the safe/discovery categories.
- Text found on the network (banners, pages, device names) is passed to agents as data, never as instructions.
- The chat can't send orders by itself: it proposes them, and an operator confirms.
- API keys are given to a run in memory only; agents never see them or connector passwords.

## Roadmap

1. **Now**: read-only assessment, live agents, agent-to-agent notes, Orchestrator chat, cost tracking.
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
