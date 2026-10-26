# AI IT Guardian — proof of concept

A read-only IT and security assessment of a network, done by AI agents.
A deterministic collector maps the network; six Claude agents then identify every device,
assess each layer and write a prioritized report for a business owner.

Nothing on the network is changed. Agents have no shell: only fixed, non-intrusive checks,
web requests without credentials, and public vulnerability lookups (NVD, CISA KEV, endoflife.date).

## Where it runs

| What | Where |
|---|---|
| Collector + agents | Proxmox container **303 `ai-guardian`** (192.168.1.92), installed in `/opt/ai-guardian` |
| Source code | this folder |
| Results | `/opt/ai-guardian/runs/<date-time>/` in the container (`graph.json` + `report.html`) |

## One-time setup: API key (for the AI step)

1. Create a key at **console.anthropic.com → Settings → API Keys** (needs billing set up).
2. In the Proxmox web UI, open **lab → Shell** and run (the key is not shown while you type):

   ```bash
   read -rsp "API key: " K && pct exec 303 -- sed -i "s|^ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=$K|" /opt/ai-guardian/.env && unset K && echo " saved"
   ```

Optional settings in `/opt/ai-guardian/.env`:
- `GUARDIAN_MODEL` — `claude-opus-5-5` (default) or `claude-fable-5-1` (stronger, ~2.5x the cost)
- `GUARDIAN_EFFORT` — `low`, `medium` (default), `high`
- `NVD_API_KEY` — free key from nvd.nist.gov; makes vulnerability lookups much faster

## Running it

From **lab → Shell** in the Proxmox web UI:

```bash
pct enter 303
cd /opt/ai-guardian
```

| Command | What it does | Time | Cost |
|---|---|---|---|
| `./venv/bin/python run.py --collect-only` | Scan only, no AI | ~7 min | free |
| `./venv/bin/python run.py` | Scan + AI agents + report | ~20–40 min | a few dollars |
| `./venv/bin/python run.py --resume runs/<dir>` | AI agents + report on an existing scan | ~15–30 min | a few dollars |
| `./venv/bin/python run.py --report runs/<dir>` | Re-create the HTML report | seconds | free |

`exit` leaves the container.

## Viewing a report on your Mac

In Terminal on your Mac (asks for the Proxmox root password; replace `<dir>`):

```bash
ssh root@192.168.1.252 "pct exec 303 -- cat /opt/ai-guardian/runs/<dir>/report.html" > ~/Downloads/guardian-report.html && open ~/Downloads/guardian-report.html
```

To list runs: `ssh root@192.168.1.252 "pct exec 303 -- ls /opt/ai-guardian/runs"`

## What the agents do

| Agent | Looks at |
|---|---|
| Discovery | Identifies every device: type, role, vendor, model, OS, firmware |
| Orchestrator | Decides which specialist looks at which device |
| Network | Exposed services, legacy/cleartext protocols, segmentation |
| OS & endpoints | Operating systems, end-of-life status, server software CVEs |
| Web & APIs | Admin pages, TLS and certificates, exposed APIs, headers |
| Firmware | Installed vs latest firmware, vendor support status, firmware CVEs |
| Internet perimeter | What the internet sees on the public IP, router port forwards |
| Report | Score, grade, executive summary, prioritized fix list |

## Updating the code in the container

Changed files are copied with the Proxmox connector and checked with `sha256sum` against this folder.
`install.sh` installs from scratch on any Debian 13 machine (run as root from this folder).

## Removing it

- Container: Proxmox UI → 303 → More → Remove.
- Connector SSH access to the host, in **lab → Shell**:

  ```bash
  sed -i --follow-symlinks '/ proxmox-mcp$/d' /root/.ssh/authorized_keys
  ```
