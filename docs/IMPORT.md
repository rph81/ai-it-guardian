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
showing the source. Not yet tested with real exports from each product.
