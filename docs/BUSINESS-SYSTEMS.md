# Business systems: SAP S/4HANA / ECC, SAP BTP, Salesforce

The **Business systems** agent reviews the systems a company runs on, the way SAP security tools (SecurityBridge,
Onapsis, EarlyWatch security checks) and Salesforce Security Health Check do. It runs during an AI assessment when at
least one of these connectors exists (Settings › Connectors › Business systems). Everything is read-only.

## SAP S/4HANA / ECC (ABAP)

**How Guardian reads:** the standard SOAP RFC service (`/sap/bc/soap/rfc`, HTTPS) calling `RFC_READ_TABLE` for a fixed
list of tables and columns. No SAP GUI or RFC SDK needed. Password-hash columns are never requested; RFC destinations
are reduced to flags (`stored_password`, `trusted`) before the agent sees them.

**Setup (the SAP administrator):**
1. SICF: activate `/sap/bc/soap/rfc` for the client Guardian reads; HTTPS only.
2. SU01: a user `GUARDIAN_RO` of type **System**.
3. PFCG: a role with `S_RFC` (RFC_TYPE FUNC, RFC_NAME RFC_READ_TABLE, ACTVT 16) and `S_TABU_NAM` (ACTVT 03) for exactly
   T000, USR02, UST04, AGR_USERS, RFCDES, RFCSYSACL, PAHI, CVERS, CWBNTCUST.
4. Add the connector: HTTPS address (e.g. `https://sap.example.com:44300`), client, user, password. A self-signed
   certificate is pinned on the first test. The test warns if the user holds SAP_ALL or another powerful profile.

| Read | Table | Looks for |
|---|---|---|
| clients | T000 | Production clients open for changes, cross-client changes allowed |
| default_users | USR02 | SAP*, DDIC, EARLYWATCH, TMSADM, SAPCPIC, SAPSUPPORT unlocked; old hash versions |
| users | USR02 | Dialog users unused 90+ days, expired but unlocked, weak hash versions |
| critical_profiles / critical_roles | UST04 / AGR_USERS | SAP_ALL, SAP_NEW, S_A.* and admin roles on dialog users |
| rfc_destinations / trusted_systems | RFCDES / RFCSYSACL | Destinations with stored passwords; trust from test systems |
| security_parameters | PAHI | login/*, rsau/enable (audit log), auth/rfc_authority_check, gw/* (RFC gateway), snc/* |
| components / applied_notes | CVERS / CWBNTCUST | Release and support package level, maintenance end |

## SAP BTP

**How Guardian reads:** GET requests to the Cloud Management (accounts) API and, optionally, the authorization API
and the Destination service, with service keys you create. Destination credentials are dropped in code: the agent
sees name, type, host, https, authentication type, proxy type and trust-all only.

**Setup:** Cloud Management Service instance, plan *central*, and a service key (required). Optional: an
Authorization and Trust Management instance, plan *apiaccess*, and a key (role collections, identity providers); a
Destination service key. Paste each key's JSON into the connector.

Checks: production subaccounts with beta features; administrators of the global account and subaccounts, and those
from the default SAP ID service; the default identity provider still active next to the company's; destinations over
HTTP, with basic authentication to the internet, trusting all certificates, or without authentication to on-premise
systems.

## Salesforce

**How Guardian reads:** OAuth client-credentials flow of a connected app whose Run As user is an API-only, read-only
user with *View Setup and Configuration*; then fixed SOQL queries (REST and Tooling API).

Checks: Health Check score and high-risk settings, users with Modify All Data or Manage Users, admins without MFA,
inactive users, active guest users, connected apps open to all users, failed logins in the last 7 days.

## What the findings look like

Assets are `sap/<SID or connector>/<client>`, `btp/<subaccount>` or `salesforce/<org>`. Findings get a priority from
the Risk analyst, MITRE ATT&CK techniques, a place in the compliance map (ISO 27001 access control, NIS2), and tickets
like any other finding. Code: `guardian/bizsys.py` (reads), `guardian/agents.py` (brief).

## Not covered yet

SAP security notes beyond the support-package level (needs SAP's note data), SAP HANA database settings, BTP audit-log
retention and Cloud Connector configuration, Workday, Oracle and other platforms. These follow the same pattern.
