# Importing other scanners' results

Many customers already run a vulnerability scanner. Guardian can take its results into a run, so everything is in one
Fix plan, report, compliance map and ticketing flow.

## Formats

| Scanner | Export to use | Read |
|---|---|---|
| **Tenable Nessus** | Scan › Export › **Nessus** (`.nessus`) | host IP, port, severity (info skipped), plugin name and ID, CVEs, synopsis, output, solution |
| **OpenVAS / Greenbone** | Report › Download › **XML** | host, port, threat / CVSS, NVT name and OID, CVE refs, description, solution (log level skipped) |
| **Qualys VM** | Scan results › Download › **XML** | IP, port, severity 1–5, QID, title, CVE list, diagnosis, result, solution |
| **Rapid7 InsightVM / Nexpose** | Report template **XML Export 2.0** | node and endpoint tests with a vulnerable status, joined to the vulnerability definitions (title, CVSS, CVEs, description, solution) |
| **Anything else** | **CSV** with a header | columns `ip` / `host` / `asset` and `title` / `name` / `vulnerability` are required; `severity` / `risk`, `cve`, `port`, `description`, `solution` are optional |

The format is recognised from the file's content. Severity becomes critical / high / medium / low (CVSS 9+, 7+, 4+).

## Pulling from a scanner's API (Tenable, Qualys, Rapid7)

Instead of exporting a file, add a scanner connector for the site (Settings › Connectors › **Scanners**) and pick it in
**Fix plan › Import results from another scanner › Or pull the open findings from a scanner connector**.

| Scanner | Account | What is pulled |
|---|---|---|
| **Tenable Vulnerability Management** (cloud.tenable.com) | A user with the **Basic** role and API keys | Open and reopened vulnerabilities, medium and above, through the export API (can take a few minutes) |
| **Qualys VMDR** | A **Reader** user with API access, limited to the customer's asset groups; your platform's API server | Confirmed detections, severity 3 to 5, with titles, CVEs and solutions from the knowledge base |
| **Rapid7 InsightVM** (security console, port 3780) | A user whose role can only view site and asset data | Vulnerabilities per asset, CVSS 4 and above, with titles, CVEs, ports and proof |

The connector test signs in with a light read and warns when the Tenable user can change things. Preview reads the
findings; Import uses what the preview read (within 15 minutes) instead of reading again. Everything after that is the
same as a file import. The credentials are read from the vault for the pull only (unlock it first), and redirects are
not followed.

## How it works

1. **Fix plan › Import results from another scanner**: choose the file, **Preview** (format, findings, devices, how many
   devices Guardian hasn't seen), then **Import**.
2. Each finding is added to the run with its source (`from Nessus`…). Devices Guardian hadn't seen are added to the
   inventory.
3. **Duplicates**: when Guardian already has an open finding on the same device naming the same CVE or with the same
   title, the imported one isn't added; the existing finding records "also reported by" the other scanner.
   Importing the same file twice adds nothing.
4. **Priority** follows the Risk analyst's rules without using AI: a CVE on the CISA KEV list → P1 (P2 when the finding
   is low severity on an internal device), a service forwarded to the internet → P1 for high / critical, otherwise
   critical and high → P2, medium → P3, low → P4. Run **Re-run AI on a scan** afterwards if you want the analysts to
   re-rank everything together and update attack paths and compliance.
5. The report is rebuilt, the import is recorded on the run and in the audit log.

## Safety

- Files up to 50 MB and 20,000 findings.
- XML with a DTD or entity declarations is refused (XXE and entity-expansion attacks).
- The file is parsed and discarded; only the findings are kept.
- Operators and admins can import; nothing is sent anywhere except the CISA KEV list download.

## Tested

28 checks: each format with a sample export, info / log entries skipped, unsafe XML refused (entities, external DTD),
unknown files and CSVs without the needed columns refused, preview not changing the run, merge of a duplicate, KEV +
internet exposure → P1, new devices added, report rebuilt, re-importing the same file adding nothing, the Fix plan
showing the source. Not yet tested with real exports from each product. The API pulls were tested against stand-ins
for each product's API (export polling, Qualys DOCTYPE handling and knowledge-base lookup, Rapid7 paging), not yet
against real accounts.
