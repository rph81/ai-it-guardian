# Azure posture agent

The **Azure** agent reviews your Azure subscriptions the way Defender for Cloud, Wiz or Prisma Cloud do, against the
CIS Microsoft Azure Foundations Benchmark. It is read-only: it signs in as its own app with only **Reader** and
**Security Reader**, reads through fixed queries and paths, and never sees the secret.

## Set it up (about 10 minutes)

Use a **separate app** from the Microsoft 365 one. A leaked secret then opens only one side, each connector has its own
sign-in logs, and you can rotate or remove one without touching the other.

1. **Entra admin center › App registrations › New registration**: name `Guardian-Azure-Reader`, single tenant, no
   redirect URI. Give it **no** Microsoft Graph permissions.
2. **Certificates & secrets › New client secret** (e.g. 12 months). Copy the value now: it's shown once.
3. **Azure portal › Subscriptions** (or a management group above them) **› Access control (IAM) › Add role assignment**:
   **Reader**, then again **Security Reader**, both for `Guardian-Azure-Reader`. Nothing else.
4. Guardian: **Settings › Connectors › Microsoft Azure**: tenant ID, application (client) ID, the secret, and optionally
   the subscription IDs Guardian may read (space-separated; empty = every subscription the app can see).
5. **Test**: lists the subscriptions and the app's roles. It warns if Security Reader is missing (Defender results
   would be incomplete) or if the app has any other role (Contributor, Owner…): remove those.

The next AI assessment runs the Azure agent automatically when the connector exists.

## What it may read

**Resource Graph, 29 fixed queries** (the agent picks one by name and may narrow it to a resource group or
subscription; it can't write its own query): subscriptions, resource counts, public IPs, NSG rules open to any source,
subnets without NSG, flow logs, VNets (DDoS), gateways / load balancers / firewalls / Bastion, VMs, VM extensions,
disks, storage accounts, SQL servers, PostgreSQL / MySQL / Cosmos DB, Key Vaults, App Services, Defender plans, secure
score, unhealthy Defender recommendations, active Defender alerts, role assignments, custom roles, policy assignments,
non-compliant policies, backup items, VMs without backup, recovery vaults, orphaned resources, untagged resources.

**Management API, 22 GET paths** (api-version fixed by Guardian): subscriptions; per subscription Defender pricings,
secure scores, security contacts, auto-provisioning, activity-log diagnostic settings and alerts, locks, classic
administrators, Advisor; per resource SQL firewall rules, auditing, databases and TDE, PostgreSQL / MySQL firewall
rules, App Service `config/web`, Key Vault secrets and keys (**names and expiry dates only**; values never come through
the management API and Guardian strips everything else), blob service properties, one NSG, a resource's diagnostic
settings.

Safeguards: only subscriptions the connector allows; the resource-group name is checked before it goes into a query;
no write calls exist in the tool (the only POST is the Resource Graph read API); paging links to other hosts are not
followed; results are capped at ~30 KB per call and passed to the agent as data.

## What it reports

One finding per issue, asset `azure/<resource>` or `azure` for subscription-wide issues. Typical findings: RDP / SSH /
databases open to the internet, public blob access, SQL firewall open to all, Defender plans on Free, active Defender
alerts, Key Vaults without purge protection, secrets without expiry, guests or service principals with Owner, too
many Owners, classic co-administrators, activity log not exported, no alerts on security changes, VMs without backup,
vaults without soft delete, non-compliant policies, orphaned disks and IPs (info).

The Risk analyst ranks them with everything else, Attack paths can chain them (exposed VM → managed identity → Key
Vault), and the Compliance agent maps them to **CIS Microsoft Azure Foundations (by section)**, 54 controls with
Guardian's own IDs (AZ-2.1 … AZ-12.3), plus ISO 27001 and NIS2. The Azure framework appears in the Compliance tab and
the report only when the Azure agent ran. Map the AZ- IDs to the official recommendation numbers of the benchmark
version you audit against.

## Tested so far

Against a simulated Azure (sign-in and management API mocked): paging, subscription filter, resource-group filter and
KQL injection refused, unknown queries and paths refused (e.g. `runCommand`, `listKeys`, `..`), other subscriptions
refused, secret values stripped, foreign paging links not followed, no write calls, the connection test with Reader +
Security Reader (ok) and with Contributor (warning). **Not yet run against a real Azure tenant**: that's part of the
final testing phase (the queries' field names follow the documented Azure schemas and may need small fixes then).
