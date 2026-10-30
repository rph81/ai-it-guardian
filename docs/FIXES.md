# Fixes and patching (remediation)

Guardian is read-only until an admin turns remediation on (**Fix** page, passkey, 30 min to 4 h). Every change is then
proposed from a finding, approved on its own with a passkey, backed up first, checked afterwards and rolled back
automatically if the check fails. Every change is a change record (CR-0001…) in the audit log. Firmware, router WAN /
firewall rules and the access path Guardian itself uses always stay manual.

Two ways to patch, both available:

- **Agentless** (default; nothing installed on the customer's machines): Linux over SSH, Windows over WinRM, Microsoft
  365 through a separate app.
- **RMM**: when the customer has **NinjaOne**, Guardian reads patch status from it and can ask it to install missing
  patches.

## Recipes

| Recipe | Applies to | Backup | Rollback | Needs |
|---|---|---|---|---|
| Close a UPnP port forward | Routers | Forward recorded | Automatic | nothing |
| Turn off SSH password login | Linux | Settings file | Automatic | Linux fix account |
| **Install pending package updates** | Debian / Ubuntu | Proxmox snapshot (if configured) + package list | Restore the snapshot | Linux fix account (+ Proxmox snapshot token) |
| **Turn on automatic security updates** | Debian / Ubuntu | Settings file | Automatic | Linux fix account |
| **Turn off SMBv1** | Windows | Setting | Automatic | Windows fix account |
| **Turn on Windows Firewall** | Windows | Profile states | Automatic, with a dead-man switch on the machine | Windows fix account |
| **Turn on Defender real-time protection** | Windows | Setting | Automatic | Windows fix account |
| **Install Windows updates** | Windows | Installed updates list | Manual (Update history) | Windows fix account |
| **Remove mail rules forwarding outside the company** | Microsoft 365 | Every removed rule exported | Re-created | Microsoft 365 fix app |
| **Disable stale accounts** (90+ days without sign-in) | Microsoft 365 / Entra | Account states | Re-enabled | Microsoft 365 fix app, Entra ID P1 |
| **Block legacy sign-in** (Conditional Access, report-only) | Microsoft 365 / Entra P1 | — | Policy deleted | Microsoft 365 fix app |
| **Install missing OS patches through NinjaOne** | NinjaOne devices | Pending patch list | Manual (NinjaOne) | NinjaOne connector + patch credentials |

Proposals appear on the Fix page when the latest assessment found the matching issue (e.g. a Patch & configuration
finding "SMBv1 enabled" on 192.168.1.20 proposes "Turn off SMBv1 on 192.168.1.20"). A proposal without the needed fix
credentials shows what to add.

## Fix credentials (Fix page › Fix accounts; all stored encrypted in the vault)

### Linux servers
A user `guardian-fix` with Guardian's SSH key and a sudoers file allowing exactly the listed commands. **If you set
up a fix account before this version, replace its sudoers file** with the one shown on the Fix page (it now includes
`apt-get update`, `apt-get … upgrade` and the automatic-updates file, and keeps `DEBIAN_FRONTEND`). Optionally give the
server's Proxmox guest (`node/qemu/101` or `node/lxc/105`).

### Proxmox snapshots (optional)
Role `GuardianSnapshot` with `VM.Snapshot, VM.Snapshot.Rollback, VM.Audit`; user `guardian-fix@pve`; API token
`snapshots` with that role on the guests. Guardian takes a snapshot before installing updates on a guest and the
change's rollback restores it. Without it, Linux updates run without a snapshot and roll back by hand.

### Windows (WinRM, agentless)
A separate account in the machine's local **Administrators** group (installing updates and changing the firewall need
it), over WinRM HTTPS (5986). Not the read-only Windows connector account. Windows' update engine won't install from a
remote session, so Guardian runs it once as a scheduled task (SYSTEM), follows it, and removes the task. The firewall
change arms a switch on the machine that restores the previous state after 2 minutes unless Guardian proves it can
still connect, so a firewall change can't lock Guardian (and its rollback) out. "Restart if needed" on a Windows update
proposal schedules a restart with a 15-minute warning; otherwise Guardian only reports that one is needed.

### Microsoft 365 fix app
A separate app registration (e.g. `Guardian-Fix`), never the read-only Microsoft 365 connector app. Application
permissions, admin consent, nothing else:
`User.Read.All, User.EnableDisableAccount.All, MailboxSettings.ReadWrite, Organization.Read.All, AuditLog.Read.All,
Policy.Read.All, Policy.ReadWrite.ConditionalAccess, Application.Read.All, RoleManagement.Read.Directory,
Directory.Read.All`. Guardian checks the app's permissions when you save it and before each change, and refuses an app
with any other permission (e.g. `Mail.Send`).
- Stale accounts: members only, not guests, not accounts with an admin role, not created in the last 90 days; at most
  50 per change.
- Legacy sign-in: created in **report-only**; switch it to **On** in Entra after checking the report-only results.

### NinjaOne
- **Read** (Settings › Connectors › NinjaOne): an API client with the **Monitoring** scope. The Patch & configuration
  agent reads devices, pending / failed OS and software patches, antivirus status and device health.
- **Patch jobs** (Fix page): a second API client with **Management** and **Control** scopes, used only for approved
  jobs. Guardian asks NinjaOne to apply the device's pending OS patches; NinjaOne installs them with the device's
  policy. Re-check the finding afterwards.

## Tested

34 checks against simulated systems (a Linux host over SSH, a Windows machine over WinRM, Microsoft Graph and NinjaOne
mock servers): each recipe's backup / apply / verify / rollback, nothing-to-do cases, Defender blocked by Tamper
Protection (rolled back), a firewall change that locks Guardian out (restored), Windows updates that all fail (needs
attention, no automatic uninstall), an unreachable machine, internal mail rules kept, admins never disabled, the
report-only policy, an over-privileged fix app refused, the NinjaOne job, and proposals from findings. 15 checks of the
Fix-page endpoints (passwords never returned, credential validation, removal, audit). **Not yet run against real
machines, a real tenant or a real NinjaOne account**: that's in the final testing phase.
