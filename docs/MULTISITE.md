# Several customers in one console (multi-site)

A **site** is a customer location. Everything Guardian holds about a customer belongs to its site: assessments,
findings, the Fix plan, attack paths, compliance, connectors, the collector and where its tickets go. "This network" is
the built-in site: the network of Guardian's own server.

## Switching sites

The **Site** box under the dashboard title switches between sites; the choice is remembered in your browser. **All
sites** shows the portfolio: one row per site with its score, last assessment, open priority 1 findings, overdue
items, open findings, collector state and ticket destination. Click a row to open that site.

| Site | Scan / AI assessment | Findings from imports | Fix (remediation) | Connectors |
|---|---|---|---|---|
| This network | yes | yes | yes | yes, used by the connector agents |
| Other sites | with the collector's remote scans (phase B) | yes: **New assessment** → Fix plan → *Import results from another scanner* | with the collector (later) | stored per site, used once remote AI runs arrive |

Existing runs and connectors belong to "This network" automatically.

## Per-site settings (Settings › Sites & collectors › Settings)

| Tab | What |
|---|---|
| General | Name, customer, networks (scope; private ranges, nothing broader than /16) |
| Ticketing | **Our PSA** (your system from Settings › Ticketing, with this customer's company / board / queue / project), **Customer's own system** (their URL and secret, used only for this site), or **Off**; plus the auto-ticket priority and close-on-verify, each "same as default" or overridden |
| Access | Which operators and viewers may see the site |
| Connectors | Link to this site's connectors |
| Schedule | This network: Settings › Schedules. Remote sites: with the collector's remote scans |

Mapping fields per system when a site uses your PSA:

| System | Per-site fields |
|---|---|
| ServiceNow | Assignment group, caller, category |
| ConnectWise PSA | Customer company identifier, service board |
| Autotask PSA | Company ID, queue ID |
| HaloPSA | Customer (client) ID, ticket type ID |
| Jira Service Management | Project key, issue type |

Blank fields use the default from Settings › Ticketing. Each ticket remembers whether it went to your PSA or the
customer's system, so switching a site's mode never mixes the two.

## Access per site

- Admins always see every site.
- Operators and viewers see every site until an admin limits them on a site's **Access** tab; from then on only the
  sites ticked for them. Users › Users & access shows "All sites" or how many.
- The server enforces it: runs, reports, findings, tickets, imports, connectors and site settings of other sites answer
  "unknown". A user without "This network" can't start scans, use Fix or see the live job log.

## Stored data

| What | Where |
|---|---|
| A run's site | `runs/<run>/site` (missing = This network) |
| Site settings (scope, ticketing mode, mapping, overrides) | vault meta `site_settings` |
| Customer's own ticketing secret | vault meta `site_ticket_secrets` (like the MSP's ticketing secret: protected by file permissions, needed for scheduled runs) |
| User limits | vault meta `user_sites` |
| Connector's site | the connector record's `site` field (encrypted with the record) |

## API

| Method | Path | Role |
|---|---|---|
| GET | `/api/portfolio` | viewer |
| GET | `/api/sites/{site}/settings` | operator |
| POST | `/api/sites/{site}` (name, customer, scope) | admin |
| POST | `/api/sites/{site}/ticketing`, `/api/sites/{site}/ticketing/test` | admin |
| POST | `/api/sites/{site}/access` | admin |
| POST | `/api/sites/{site}/runs` (empty assessment for imports) | operator |
| GET | `/api/connectors?site=` | operator |

Audit events: `site-changed`, `site-ticketing-changed`, `site-access-changed`, `run-created`.
