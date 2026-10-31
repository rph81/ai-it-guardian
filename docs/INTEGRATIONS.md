# Integrations: SIEM output, GitHub, MCP server

Settings › Integrations (admins).

## SIEM output

After every run (scheduled or manual) Guardian sends one event per finding and one run summary to each destination
that is switched on. With **only new findings** on, a run that has a previous assessment sends only what's new. Decoy
hits are sent at once. Send-only: Guardian never reads from the SIEM.

| Destination | How | Needs |
|---|---|---|
| Microsoft Sentinel | Azure Monitor **Logs ingestion API** (data collection endpoint + rule) | An Entra app with *Monitoring Metrics Publisher* on the DCR; tenant ID, client ID, secret, DCE URL, DCR immutable ID, stream (e.g. `Custom-GuardianFindings`) |
| Splunk | HTTP Event Collector, `sourcetype` `guardian:finding` / `guardian:run` / `guardian:decoy` | HEC URL (https) and token; optional index |
| Syslog | RFC 5424, JSON in the message, octet-counted over TLS (default, port 6514), TCP or UDP | Host, port |

Event fields: type, run, site, site_name, id, title, severity, priority, asset, layer, kev, epss, exposure, cves,
attack (ATT&CK IDs), recommendation, first_seen, source. Secrets are stored like the alert channels' (server file
permissions, needed for scheduled runs) and never returned to the browser.

## GitHub (private repositories)

A fine-grained personal access token with **Contents: Read-only** and **Metadata: Read-only** on the repositories
Guardian should read. Stored in the vault; handed to each code scan in memory (removed from the scan's environment as
soon as it starts) and used only for api.github.com.

## MCP server

`POST https://<guardian>/mcp`, the Model Context Protocol over Streamable HTTP (JSON-RPC 2.0), protocol versions
2025-06-18, 2025-03-26 and 2024-11-05. Authentication: `Authorization: Bearer gdn_…`, one token per tool, created with
the admin's passkey and shown once (only its SHA-256 is stored). A token can be limited to one site. Requests from
browser pages of other origins are refused.

Read-only tools: `list_sites`, `portfolio`, `list_findings` (site, max_priority, limit), `get_finding` (run, id),
`attack_paths` (site), `attack_matrix` (site).

Example for Claude Code:

```
claude mcp add --transport http guardian https://guardian.example.com:8443/mcp --header "Authorization: Bearer gdn_…"
```
