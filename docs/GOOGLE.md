# Google agent: Google Workspace and Google Cloud

Reviews Google Workspace and Google Cloud the way Google's security health page, the CIS Google Workspace and CIS Google
Cloud Foundations benchmarks, Wiz and Security Command Center do. Read-only. Guardian signs in with a service account key
(a signed JWT; no Google SDK) and only contacts Google's API hosts.

## Google Workspace

1. In a Google Cloud project: enable the **Admin SDK API** and the **Alert Center API**; create a service account with a
   JSON key (no project roles needed).
2. Workspace Admin console › Security › Access and data control › API controls › **Domain-wide delegation** › Add the
   service account's client ID with exactly these read-only scopes:
   `admin.directory.user.readonly`, `admin.directory.domain.readonly`, `admin.directory.rolemanagement.readonly`,
   `admin.reports.audit.readonly`, `apps.alerts` (each prefixed with `https://www.googleapis.com/auth/`).
3. Create an admin user (e.g. `guardian-read@`) with a custom role that can only read users, roles and reports.
4. Settings › Connectors › Google Workspace: that user's address and the JSON key.

| Query | Looks for |
|---|---|
| users | Users and admins without 2-step verification, 2-step not enforced, suspended or inactive users |
| admins | Super admins and admin roles; too many admins, admins who never sign in |
| domains | Unverified domains |
| login_events, admin_events | Last 30 days: suspicious logins, leaked-password or hijack suspensions, admin grants, 2-step enforcement changes |
| alerts | Alert Center alerts of the last 90 days |

## Google Cloud

1. Create a service account `guardian-read` with a JSON key.
2. Grant it **Viewer** and **Security Reviewer** on the customer's organization or folder (or each project). Nothing
   that can change resources.
3. Enable the Cloud Resource Manager, Compute, Cloud Storage, Cloud SQL Admin, IAM and Logging APIs in the service
   account's project.
4. Settings › Connectors › Google Cloud: the JSON key, optionally the project IDs to check (default: up to 30 projects).

The test lists the readable projects and asks Google which of a few write permissions the account has
(testIamPermissions, which changes nothing); it warns if any is granted.

| Query | Looks for |
|---|---|
| iam_policy | allUsers / allAuthenticatedUsers, personal @gmail.com members, owners and editors, admin roles, missing audit configuration |
| service_account_keys | User-managed keys and their age |
| firewalls_open | Ingress rules from 0.0.0.0/0 or ::/0 |
| instances | Public IPs, default compute service account with full API access, serial port, OS Login, Secure Boot |
| buckets | Public members, public access prevention, uniform access, versioning, logging |
| sql_instances | Public IP with open authorized networks, SSL not required, backups off |
| log_sinks | Whether audit logs are exported |

Findings use assets like `google/<domain>` and `gcp/<project>/<resource>`. Code: `guardian/google.py`. Tested with a
stand-in for Google's APIs (JWT signature, parsing, project limits, write-permission warning); not yet against a real
tenant or project.
