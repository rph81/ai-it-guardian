# Ticketing

Guardian can open a ticket for each finding in **ServiceNow, ConnectWise PSA, Autotask PSA, HaloPSA or Jira Service
Management**, keep it linked across assessments, read its state back into the **Fix plan**, and add a note (optionally
close it) when a re-check verifies the fix. Choose the system in **Settings › Ticketing**; the fields change with it.

## The other systems

| System | What to create | Fields in Guardian | How Guardian finds its own ticket again |
|---|---|---|---|
| **ConnectWise PSA** | API member with a role that can read/edit service tickets; API keys (public / private); a clientId from developer.connectwise.com | API site (e.g. `https://api-eu.myconnectwise.net`), company ID, public key, private key, client ID, service board, customer company identifier, optional closing status | `externalXRef` holds a hash of the Guardian reference |
| **Autotask PSA** | API-only user (Admin › Resources) with an API tracking identifier | Zone URL (e.g. `https://webservices16.autotask.net`), API user, secret, tracking identifier, company ID, queue ID | The description carries `ai-it-guardian:<run>/<finding>` |
| **HaloPSA** | API application (client credentials) allowed to read and edit tickets | Halo address, client ID, client secret, customer (client) ID, optional ticket type ID | Search on the Guardian reference in the details |
| **Jira Service Management** | An account for Guardian and an API token (id.atlassian.com › Security › API tokens) | Site (`https://yourcompany.atlassian.net`), account e-mail, API token, project key, optional issue type | A label `guardian-<hash>` (plus `ai-it-guardian`) |

| Guardian priority | ConnectWise severity / impact | Autotask priority | HaloPSA priority | Jira |
|---|---|---|---|---|
| P1 | High / High | Critical | 1 | in the summary `[Guardian P1]` |
| P2 | High / Medium | High | 2 | `[Guardian P2]` |
| P3 | Medium / Medium | Medium | 3 | `[Guardian P3]` |
| P4 | Low / Low | Low | 4 | `[Guardian P4]` |

Closing on a verified fix: ConnectWise sets the closing status (default "Closed (resolved)"), Autotask sets status
Complete (5), HaloPSA adds a private note with status Closed (9), Jira adds a comment and moves the issue through the
first transition into the Done category. Tested against simulated APIs (31 checks); not yet against real instances.
Status names and IDs differ between installations: check the closing status, queue and ticket type IDs in yours.

## ServiceNow

## Set up ServiceNow

1. In ServiceNow, create an **integration user** (User Administration › Users › New): tick **Web service access only**,
   give it the **itil** role (create, read and update incidents) and a strong password.
2. In Guardian: **Settings › Ticketing**, tick **Use ServiceNow**, enter
   - **Instance**: `https://yourcompany.service-now.com`
   - **Integration user** and **Password** (type it yourself; it's never shown again — leave empty to keep the saved one)
   - optional **Assignment group**, **Caller**, **Category** (sys_id or name, as your instance accepts them)
3. **Save**, then **Test the connection**.

Like the alert channels, the password is needed after scheduled runs when nobody is signed in, so it's stored outside
the vault and protected by the server's file permissions (root only).

## What Guardian sends

One record in the `incident` table per finding:

| Field | Value |
|---|---|
| `short_description` | `[Guardian P1] <finding title>` |
| `description` | Finding id, run, priority, severity, device, why this priority, evidence (first 3,000 chars), fix, Guardian due date, console link |
| `impact` / `urgency` | P1 → 1/1, P2 → 2/1, P3 → 2/2, P4 → 3/3 (ServiceNow derives its own priority) |
| `correlation_id` | `ai-it-guardian:<run>/<finding>` — Guardian looks this up first, so it never opens a duplicate |
| `assignment_group`, `caller_id`, `category` | from Settings, when set |

## In the Fix plan

- **Open ticket** on a finding creates the incident; the row then shows a chip with the number and state (click to open
  it in ServiceNow).
- **Sync tickets** reads the current states. When ServiceNow says **Resolved** or **Closed**, Guardian marks the finding
  **Fixed (to verify)** and notes it — use **Re-check** so an agent confirms it.
- When a re-check **verifies** the fix, Guardian adds a work note to the incident, and resolves it if you ticked
  **Resolve the ticket when Guardian verifies the fix** (close code "Solved (Permanently)").
- Tickets carry over to the next assessment together with owner, due date and status.

## Automatic tickets

With **Open tickets after each AI assessment** on, after every full AI run (scheduled or by hand) Guardian opens tickets
for open findings at or above the chosen priority that don't have one yet, and syncs the states of existing ones.
Failures never block the run or the alerts; they're written to the audit log (`ticketing-failed`).

## API

| Method | Path | Role |
|---|---|---|
| GET / POST | `/api/ticketing` | admin |
| POST | `/api/ticketing/test` | admin |
| POST | `/api/runs/{run}/tracking/{finding}/ticket` | operator |
| POST | `/api/runs/{run}/tickets/sync` | operator |

All changes are in the audit log (`ticketing-changed`, `ticket-created`, `tickets-synced`).

## Per site

Each site chooses where its tickets go: your system with the customer's company, board, queue or project; the
customer's own system with its own secret; or off. Priority threshold and close-on-verify can be overridden per site.
Settings › Sites & collectors › Settings › Ticketing; details in [MULTISITE.md](MULTISITE.md).
