# On-site collector (design proposal)

> Status: **approved 30 Oct 2026.** Phase A (sites, gateway, enrollment, heartbeat, customer controls) is being built.
> How the gateway is published on the internet is decided later; the code doesn't depend on it.

Guardian today assesses the network it sits on. To assess a customer's network from the central Guardian (the
**server**), a small **site collector** runs at the customer. It does the network work locally and only ever
connects **out** to the server. The AI agents, the vault, reports, the fix plan and ticketing stay on the server.

```
 Customer site                                         Guardian server (LXC 303)
 ┌──────────────────────────────┐   HTTPS 443, out only   ┌─────────────────────────────────────────┐
 │ Site collector               │ ─────────────────────▶ │ Gateway  (new, only /c/v1/*)            │
 │  · discovery (ARP, nmap)     │   signed requests +     │   enrollment · job queue · results      │
 │  · probes, TLS, HTTP         │   jobs                  │                                         │
 │  · AD / Linux / Windows /    │ ◀───────────────────── │ Console (unchanged, stays LAN-only)     │
 │    Synology / Proxmox checks │   (replies to its own   │   sites · runs · agents · vault ·       │
 │  · local scope, pause,       │    requests)            │   reports · fix plan · ticketing        │
 │    disconnect                │                         │                                         │
 └──────────────────────────────┘                        └─────────────────────────────────────────┘
```

## Why this instead of a VPN

| | Site collector | VPN from the server |
|---|---|---|
| Customer firewall | Outbound 443 only, nothing to open | A tunnel into their network |
| Discovery | Full: ARP, MAC vendors, broadcasts | Routed only: no ARP, no broadcasts |
| Overlapping subnets (192.168.1.0/24 everywhere) | Not a problem | Needs namespaces / NAT |
| Tunnel drops mid-scan | Nothing leaks: the collector only scans its own LAN | Scans can hit the wrong network |
| What the customer controls | Scope pinned on site, pause switch, local activity log | Little |
| Cost for the customer | A small container or VM | VPN account and rules |

## What changes on the server

1. **Sites (customers)** — a site has a name, customer, collector status and its own connectors, schedules, runs,
   fix plan and alerts. The existing local network becomes the first site ("This network"). Users can be limited to
   some sites. This is also the "several customers in one console" item from the roadmap.
2. **Gateway** — a separate service (`ai-guardian-gateway`, own port 8444, own system user, own systemd unit) that
   serves only the collector API. The admin console is never exposed to the internet. For the POC it runs next to
   the console on LXC 303 (LAN only); when it's published it moves to its own container in a DMZ VLAN. How it's
   published (Cloudflare Tunnel or other) is decided then.
3. **Enrollment** — an admin adds a site and creates a one-time enrollment code (passkey, valid 24 h, single use).
   The collector creates its own Ed25519 key pair and sends the public key with the code. From then on **every
   request is signed** with that key (method, path, time, one-time id, body hash), so authentication works the same
   whatever sits in front (proxy, tunnel, load balancer). The collector pins the gateway's TLS certificate from the
   install command. Client certificates at the edge can be added when it's published. **Revoke** cuts a collector
   off at once.
4. **Job queue** — the AI agents keep the same tools. When a run belongs to a remote site, the live tools (probe,
   http_get, tls_inspect, ad_query, linux_check, windows_check, synology_info, proxmox_get…) become jobs for that
   site's collector, and the agent waits for the result (with a timeout). Lookups that don't touch the network
   (CVE, EPSS, KEV, end-of-life) and Microsoft 365 (cloud API) stay on the server.
5. **Customer credentials** — entered in the console as today, but sealed with the collector's public key and
   stored only in sealed form: only that collector can open them. The server and its vault never keep them in
   clear.
6. **UI** — Sites page (status, last seen, version, scope), Add site with the install command, site picker on the
   dashboard and when starting a run, site name in reports, alerts and tickets.

## The collector

- **Packaging, three options:** a **VM appliance** (ready image for Proxmox, Hyper-V, VMware; nothing installed on
  the customer's servers), a **Linux app** (package + systemd service) and **Docker** (`--network host`, only the
  `NET_RAW` and `NET_ADMIN` capabilities). A Windows app may follow later (needs Npcap; check Nmap/Npcap OEM
  licensing before selling).
- **No inbound ports.** It polls the gateway for work (long poll) and posts results.
- **Fixed job types only.** Each job is signed by the server, has an expiry and a one-time id; the collector checks
  all three. There is no "run this command" job.
- **Scope is set on site.** At install the customer's subnets are written into the collector's config. A job for
  any address outside them is refused locally, whatever the server asks.
- **Read-only.** No remediation in the first version.
- **Customer-side controls** (local status page, LAN only, local admin sign-in):
  - **Pause / Resume**: stays connected, refuses all jobs. Optional reason, shown to you.
  - **Disconnect / Connect**: closes the connection to Guardian completely; nothing is sent or received until
    someone presses Connect on site. Optional reason (sent just before closing) and optional automatic reconnect.
  - **Maintenance windows**: when full scans may run; jobs outside them are held.
  - **Scope**: set on site; only a local admin can change it.
  - **Activity log**: every job and every pause/disconnect, kept 90 days, tamper-evident, CSV export.
  - Neither Pause nor Disconnect can be undone from the server side. Scheduled assessments are skipped and the
    alert says why.
- **No AI key, no vault, no reports** on the collector. Results are kept only until they're delivered.
- **Updates:** signed releases; the collector checks the signature before updating.

## Job types (version 1)

| Job | Used by |
|---|---|
| `discover` (ARP sweep, nmap, broadcast, SSDP, banners, WAN view from the site) | Network scan |
| `probe`, `http_get`, `tls_inspect` | Network, OS, Web, Firmware agents |
| `ad_query`, `linux_check`, `linux_packages`, `windows_check`, `synology_info`, `proxmox_get` | Connector agents |
| `recheck` (any of the above for one finding) | Fix plan › Re-check |

## Phase A: what's built (30 Oct 2026)

| Piece | Where |
|---|---|
| Gateway service (`ai-guardian-gateway`, port 8444, user `guardian-gw`, systemd sandbox) | `gateway.py`, `ai-guardian-gateway.service` |
| Shared site database (sites, collectors, one-time ids, events) | `guardian/sitestore.py` → `/opt/ai-guardian/gateway/gateway.db` |
| Console API: sites, enrollment codes (passkey), revoke, remove | `console.py` (`/api/sites…`) |
| **Settings › Sites & collectors**: list, add, Install (Linux app / Docker / VM appliance commands), Revoke | `guardian/web/sites.js` |
| Collector: `enroll`, `run`, `status`, `pause`, `resume`, `disconnect`, `connect`, `log` | `collector/guardian_collector.py` |
| Linux app install, systemd unit (sandboxed), Dockerfile | `collector/install.sh`, `collector/guardian-collector.service`, `collector/Dockerfile` |

**Not yet:** jobs (scans run through the collector), the site picker and per-site runs, the customer's web status
page and maintenance windows (phase B); the published packages and VM image (phase D). Until the status page exists,
the customer uses the commands below.

### Using it

1. **Settings › Sites & collectors › Add a site**, then **Install** (passkey). Copy the command for the package the
   customer uses and fill in their subnets.
2. At the customer (Linux app, until the package is published):
   ```
   git clone https://github.com/rph81/ai-it-guardian && cd ai-it-guardian/collector && sudo ./install.sh
   sudo guardian-collector enroll https://<guardian>:8444 <CODE> --pin sha256:<pin> --scope 10.20.0.0/22,10.20.8.0/24
   sudo systemctl enable --now guardian-collector
   ```
   Docker: `docker build -t guardian-collector:1.0.0 collector/`, then the two commands from the Install screen.
3. The site turns **Online** in the console within a few seconds.

Customer controls on the collector host:

| Command | Effect |
|---|---|
| `sudo guardian-collector status` | Site, server, pin, state, scope, activity log check |
| `sudo guardian-collector pause --reason "month-end"` / `resume` | Stay connected, refuse all work; Guardian shows "Paused by customer" + reason at once |
| `sudo guardian-collector disconnect --reason "..."` / `connect` | Tell Guardian why, then no connection at all until `connect` |
| `sudo guardian-collector log` | The activity log (hash-chained; `status` says whether it's intact) |

The gateway only listens on the LAN for now (port 8444 of LXC 303). Publishing it is a separate decision.

### Tests (phase A)

50 automated checks against a running gateway, all passing: unknown routes and methods (404, no docs, no banner),
unknown/duplicate fields, wrong types, NaN, oversized bodies (413), query strings, shell characters, over-broad
scopes, wrong TLS pin (refused by the collector), single-use codes, replayed requests, old and future timestamps,
wrong key, tampered body, signature reused on another path, unknown and revoked collectors, malformed headers,
5-failure enrollment lockout, per-address rate limit, expired codes, pause / disconnect / connect reaching the
server, no traffic while disconnected, private key file mode 0600, tamper detection in the activity log. An
end-to-end run between a collector on another machine and the gateway on LXC 303 confirmed enrollment, heartbeat,
pause, resume, disconnect (silent afterwards) and revocation.

## Phases

| Phase | Delivers |
|---|---|
| A | Sites in the console, gateway service, enrollment, revoke, heartbeat, Sites page; collector client with enroll, heartbeat, pause, disconnect |
| B | `discover` and probe jobs (signed by the console); remote scans and AI assessments; site picker; scheduling per site; customer status page and maintenance windows |
| C | Connector checks on site with sealed credentials |
| D | VM appliance, Linux package, Docker image; signed auto-update; buffering when the server is unreachable |
| Later | Remediation through the collector, with admin passkey **and** the customer's local approval |

## Security requirements (code)

The gateway is the only Guardian code reachable from outside, so it's written to be as small and strict as possible.

**Gateway**
- Five routes only (`enroll`, `heartbeat`, `jobs`, `result`, `disconnect` under `/c/v1/`). Anything else is a 404;
  no API docs, no static files, no server banner.
- Order of checks: size limit → signature headers present and well-formed → collector known and active → time
  within ±2 minutes → Ed25519 signature over method, path, collector id, time, one-time id and body hash → one-time
  id never seen (recorded only after a valid signature, so strangers can't write to the database) → only then is
  the JSON body parsed.
- Every body has a fixed schema: unknown fields rejected, every value typed and bounded.
- Size caps on bodies and headers, timeouts on every request, rate limits per address and per collector, a cap on
  concurrent connections.
- Enrollment codes: random, shown once, stored only as a hash, valid 24 h, single use, lockout after repeated
  failures from an address.
- Constant-time comparisons for secrets. No shell commands, no `eval`, no deserialisation other than JSON, no file
  paths from input.
- Errors are generic for the caller (`400`, `401`, `404`, `413`, `429`); details go to the local log only.
- Its own system user; no access to the vault, the Anthropic key, connector secrets or reports. It shares only a
  small database with the console (sites, collectors, jobs).

**Jobs and results**
- Jobs (phase B) are signed by the console with a key the gateway doesn't have, so a compromised gateway can't
  create jobs.
- Results are untrusted: fixed schema and size cap per job type; agents receive them as data, never instructions;
  nothing changes anything without the admin's passkey.

**Collector**
- Checks every job: signature, expiry, one-time id, job type from a fixed list, target inside the local scope.
- No shell; tools run with fixed argument lists and minimal privileges.
- Status page on the LAN only, local sign-in, CSRF protection on every action, security headers.
- Private key stored readable by the collector's user only.

**Process**
- Security tests for each rule (bad signature, replay, old timestamp, oversized and malformed bodies, unknown
  fields, revoked collector, used or expired code, lockout), fuzzing of the parsers, Guardian's own code scan on
  every change, and a review of the gateway before it's published.

## Decisions

1. Publishing the gateway on the internet: **decided later** (Cloudflare Tunnel or other).
2. Packaging: **VM appliance, Linux app and Docker** (decided 30 Oct 2026).
3. Customer credentials: **sealed to the collector** (recommended; confirmed when phase C starts).
