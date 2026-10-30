# Ticketing (ServiceNow)

Guardian can open a ServiceNow incident for each finding, keep it linked across assessments, read its state back into
the **Fix plan**, and add a work note (optionally resolve it) when a re-check verifies the fix.

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
