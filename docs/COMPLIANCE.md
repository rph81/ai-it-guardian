# Compliance: evidence and the compliance PDF

After each AI assessment the **Compliance** agent maps the findings to CIS Controls v8 IG1, ISO/IEC 27001:2022 Annex A,
NIS2 Article 21(2), the Swiss revFADP / nLPD, **PCI DSS v4.0** (by requirement) and **SOC 2** (Trust Services
Criteria: common criteria, availability, confidentiality) and, when those agents ran, CIS Microsoft Azure and CIS AWS
Foundations. PCI DSS and SOC 2 control titles are paraphrased (the official texts are copyrighted): use the control
numbers to find the exact wording. A
technical assessment can't see everything (policies, training, contracts, physical security), so you can add your own
evidence and decisions, and export the result as a PDF or an evidence pack for an auditor.

Evidence and your own statuses are encrypted with the vault key: **unlock the vault** to see, add or export them.

## On a control (run › Compliance)

Click a control to open it:

- **Your status** (Met, Partly, Gap, Not assessed) and a **note for the auditor**. Leave the status on "Agent's status"
  to keep what the agent decided. Your status and note are kept for later assessments too.
- **Add evidence**: PDF, PNG, JPG, TXT, CSV, DOCX or XLSX, up to 10 MB, with an optional "valid until" date. The file
  is linked to that control; link it to more controls in **Settings › Evidence library**.
- **Rules**
  - A control the agent marked **Gap** or **Partly** because of findings that are **still open** keeps that status:
    "Met" can't hide an open finding. Your note and evidence are still shown, and the control says which findings block
    it. Fix them and re-check.
  - A "not assessed" control with valid evidence but no status from you shows as **Partly** (evidence without a
    decision).
  - **Expired** evidence stays listed (marked expired) but no longer counts.

## Evidence library (Settings)

Every file with its size, who added it and when, its SHA-256 (start shown), the controls it supports
(`framework:control`, e.g. `iso27001:6.3, cis_ig1:14.1`), its validity date and state (valid, expires within 30 days,
expired). Operators can add and change; only admins can delete.

How files are kept:
- checked by content, not by name (a PNG renamed to .pdf is refused); Word / Excel files with macros are refused;
- encrypted with the vault key (AES-GCM, bound to the file's ID) in `console/evidence/`, mode 600;
- never shown in the browser, only downloaded (`Content-Disposition: attachment`, sandboxed);
- checked against their SHA-256 on every read; a changed file is refused;
- every upload, change, download, deletion and export is in the audit log, with the file's SHA-256.

## Export (run › Compliance › Export)

Pick the frameworks and whether to include the findings appendix and the controls that stay "not assessed".

- **Download PDF**: cover; summary per framework (met / partly / gap / not assessed, most important gaps, evidence
  count); one table per framework with each control's status and basis (finding IDs, evidence files, your note,
  findings that block your status); appendix A open findings with priority and fix; appendix B evidence list with each
  file's full SHA-256.
- **Evidence pack (ZIP)**: the same PDF, the evidence files used by the chosen frameworks under `evidence/`,
  `manifest.json` (who, when, validity, controls per file) and `SHA256SUMS.txt`, so an auditor can check every file
  (`shasum -a 256 -c SHA256SUMS.txt`). A file that fails its integrity check is left out and named in the manifest.

The PDF is generated on the server with ReportLab (`reportlab` in requirements.txt).

## Tested

36 automated checks on the server (Python 3.13, ReportLab 5.1): uploads by type and content, renamed files, macro
documents, binary text files, the 10 MB limit, unknown controls, bad dates, path names stripped, encryption at rest,
file mode, download headers, the "met can't hide an open finding" rule, statuses after a finding is resolved, evidence
without a status, expiry, PDF generation (6 pages), pack contents and checksums, roles (viewer / operator / admin), a
locked vault, a tampered file, deletion and audit entries.
