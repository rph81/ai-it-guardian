# Schedules, alerts and the fix plan

Everything here is in the console. Schedules and alerts are admin settings (**Settings › Schedules & alerts**); the fix
plan is on each run (**Fix plan** tab, or **Plan** in the left menu).

## Schedules

| Entry | Choices | What runs | Cost |
|---|---|---|---|
| **Network scan** | Off, every day, every week (pick the day) + time | The scanner only: devices, ports, services, internet exposure | Free |
| **Full AI assessment** | Off, every week (day), every month (day 1–28) + time | Scan + all agents + report | Your Anthropic API credit (about $4–7 for ~35 devices) |

- Times are the **server's local time** (the container's time zone; `timedatectl` shows it).
- If both are due at the same time, the full assessment runs (it includes the scan).
- A scheduled run never interrupts another run. It waits up to one hour, then skips that slot.
- **Settings › Schedules & alerts** shows the next scan and the next AI assessment.

### Scheduled AI runs while the vault is locked

The Anthropic key lives in the vault, and the vault is locked when nobody is signed in (it locks itself after the idle
time you set under Security & vault). A scheduled AI assessment at night therefore can't use the key. By default it
**runs a scan instead and tells you so in the alert**.

If you want scheduled AI assessments to run unattended:

1. Sign in as an admin and unlock the vault.
2. **Settings › Schedules & alerts › Scheduled AI runs while the vault is locked › Allow · passkey**.
3. Confirm with your passkey.

Guardian then keeps a copy of the Anthropic key in `/opt/ai-guardian/console/unattended.key`, readable only by root
(mode 600), like the sign-in provider secrets. **Trade-off:** anyone with root access to the container can read it.
**Switch off and delete the copy** removes the file. Both actions are in the audit log.

## Alerts

Alerts are sent after **every run that finishes**, scheduled or started by hand, when there is something worth telling:

- **New findings** at or above your threshold (priority 1 only, 1–2, 1–3, or all new findings). "New" means not seen in
  the previous AI assessment (the Risk analyst links the same issue across runs).
- Findings from the previous assessment that were **not found again**.
- **Network changes** (optional): new or gone devices, new open ports, new ports open to the internet, new router port
  forwards, new CVEs listed for the public IP.
- A note when a scheduled AI run fell back to a scan.

Channel addresses and the e-mail password are needed when nobody is signed in, so (like the sign-in provider secrets)
they're stored outside the vault and protected by the server's file permissions. They're never shown again in the
console: leave a field empty to keep the saved value.

Use **Send a test** after saving. The last alert's result per channel is shown under the form.

### E-mail (SMTP)

| Provider | Server | Port | Username / password |
|---|---|---|---|
| Microsoft 365 | `smtp.office365.com` | 587 | A mailbox with SMTP AUTH enabled (Microsoft 365 admin center › Users › Mail › Manage email apps › Authenticated SMTP) and its password |
| Gmail / Google Workspace | `smtp.gmail.com` | 587 | The address and an **app password** (Google account › Security › 2-Step Verification › App passwords) |
| Your provider | its SMTP server | 587 (STARTTLS) or 465 (TLS) | as given by the provider |

Guardian always encrypts the connection (STARTTLS on 587, TLS on 465).

### Microsoft Teams

1. In Teams, open the channel › **⋯** › **Workflows**.
2. Choose **Post to a channel when a webhook request is received**, name it "Guardian", pick the team and channel.
3. Copy the address it shows (`https://…`) and paste it into **Microsoft Teams** in Guardian. Tick the box and save.

Guardian sends an Adaptive Card with the subject and one line per item.

### Slack

1. Create a Slack app (api.slack.com/apps › Create New App › From scratch) in your workspace.
2. **Incoming Webhooks** › turn on › **Add New Webhook to Workspace** › pick the channel.
3. Copy the address (`https://hooks.slack.com/services/…`) into **Slack** in Guardian. Tick the box and save.

### Webhook (ticketing, automation, SIEM)

Any `https://` address. Guardian sends a JSON `POST`:

```json
{"source": "ai-it-guardian", "subject": "Guardian: 3 item(s) need attention · …", "items": ["New P1: …", "New device: …"], "text": "…"}
```

Use it with Power Automate, n8n, Zapier, Make, or your ticketing system's inbound webhook.

## Fix plan (remediation tracking)

Each run's **Fix plan** lists every open finding, ranked by the Risk analyst (P1 first). For each one you can set:

| Field | Notes |
|---|---|
| **Owner** | Free text: a person, a team, "IT partner" |
| **Due** | Defaults to *first seen + the priority's target* (P1 7 days, P2 30, P3 90, P4 180). Change it if you agree on another date |
| **Status** | Open, In progress, Fixed (to verify), Risk accepted. **Verified fixed** is set by an agent after a successful re-check |
| **Note** | Decision, anything useful (ServiceNow tickets get their own chip: [TICKETING.md](TICKETING.md)) |

- **Filters:** Open, Overdue, Priority 1–2, Done, All.
- **Re-check** sends that one finding back to the agent that found it, as a short follow-up run (vault unlocked, uses a
  little API credit). If the issue is gone, the agent marks it resolved with the evidence and the plan shows
  **Verified fixed**.
- **Carried over:** after the next AI assessment, findings the Risk analyst links to the previous run keep their owner,
  due date, status and note (marked "carried over").
- Every change is written to the audit log.

The tracking is stored per run in `runs/<run>/tracking.json`, written only by the console.
