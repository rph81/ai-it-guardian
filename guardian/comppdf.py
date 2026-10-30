"""Compliance report as PDF (ReportLab): cover, summary, one table per framework, findings and evidence appendices."""
import io
import time

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)
from xml.sax.saxutils import escape

INK, MUTED, LINE = colors.HexColor("#1c1d18"), colors.HexColor("#686a5f"), colors.HexColor("#dcd9cd")
ACCENT = colors.HexColor("#d35f1f")
STATUS = {"met": ("Met", colors.HexColor("#5a8429")), "partial": ("Partial", colors.HexColor("#b7801a")),
          "gap": ("Gap", colors.HexColor("#cf3a2c")), "not_assessed": ("Not assessed", colors.HexColor("#8e9286"))}

_ss = getSampleStyleSheet()
H1 = ParagraphStyle("h1", parent=_ss["Heading1"], fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=INK, spaceAfter=6)
H2 = ParagraphStyle("h2", parent=_ss["Heading2"], fontName="Helvetica-Bold", fontSize=13, leading=16, textColor=INK, spaceBefore=6, spaceAfter=6)
KICK = ParagraphStyle("k", fontName="Helvetica-Bold", fontSize=7.5, leading=10, textColor=MUTED, spaceAfter=2)
BODY = ParagraphStyle("b", fontName="Helvetica", fontSize=9, leading=12.5, textColor=INK, alignment=TA_LEFT)
SMALL = ParagraphStyle("s", parent=BODY, fontSize=7.8, leading=10)
MONO = ParagraphStyle("m", parent=SMALL, fontName="Courier", fontSize=6.6, leading=8.5)


def P(text, style=BODY):
    return Paragraph(escape(str(text or "")).replace("\n", "<br/>"), style)


def _table(rows, widths, header=True):
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    st = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
          ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("LEFTPADDING", (0, 0), (-1, -1), 3)]
    if header:
        st += [("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, 0), 7.5), ("TEXTCOLOR", (0, 0), (-1, 0), MUTED),
               ("LINEBELOW", (0, 0), (-1, 0), 0.8, INK)]
    t.setStyle(TableStyle(st))
    return t


def _status(s):
    label, col = STATUS.get(s, (s, MUTED))
    return Paragraph(f'<font color="{col.hexval()}"><b>{escape(label)}</b></font>', SMALL)


def build(meta, frameworks, findings, evidence, include_findings=True, include_evidence=True, include_na=False):
    """meta: site, run, assessed, exported_by. frameworks: {key: {title, controls (merged), counts}}.
    findings: list of open findings (id, title, severity, priority, asset, recommendation). evidence: metadata list."""
    buf = io.BytesIO()
    W = A4[0] - 36 * mm

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 12 * mm, f"Confidential · {meta['site']} · compliance report · run {meta['run']}")
        canvas.drawRightString(A4[0] - 18 * mm, 12 * mm, f"Page {doc.page}")
        canvas.setStrokeColor(ACCENT)
        canvas.setLineWidth(1.2)
        canvas.line(18 * mm, A4[1] - 14 * mm, 30 * mm, A4[1] - 14 * mm)
        canvas.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=20 * mm, bottomMargin=20 * mm,
                            title=f"Compliance report · {meta['site']}", author="AI IT Guardian", subject="Compliance report")
    s = [Spacer(1, 60 * mm), P("COMPLIANCE REPORT", KICK), P(meta["site"], H1),
         P(" · ".join(fw["title"] for fw in frameworks.values()), H2), Spacer(1, 6 * mm),
         P(f"Assessment of {meta['assessed']} (run {meta['run']}) by AI IT Guardian.\n"
           f"Exported {time.strftime('%d %b %Y %H:%M')} by {meta['exported_by']}.", BODY),
         Spacer(1, 30 * mm),
         P("This report combines an automated, read-only technical assessment with evidence and decisions provided by the "
           "organisation. Controls a technical assessment can't see (policies, training, contracts, physical security) are "
           "marked 'not assessed' unless the organisation supplied evidence or a status. A control with open findings keeps "
           "the status those findings show. Control titles follow the published frameworks; confirm the wording against the "
           "official documents before an audit.", SMALL),
         PageBreak()]

    # summary
    s += [P("SUMMARY", KICK), P("Where you stand", H1)]
    rows = [["Framework", "Controls", "Met", "Partial", "Gap", "Not assessed"]]
    for fw in frameworks.values():
        c = fw["counts"]
        rows.append([P(fw["title"], SMALL), len(fw["controls"]), c["met"], c["partial"], c["gap"], c["not_assessed"]])
    s += [_table(rows, [W * .40] + [W * .12] * 5), Spacer(1, 6 * mm)]
    gaps = [(fw["title"], c) for fw in frameworks.values() for c in fw["controls"] if c["status"] == "gap"]
    if gaps:
        s += [P("Most important gaps", H2)]
        s += [P(f"• {t.split('·')[0].strip()} {c['id']} {c['title']}" + (f" (findings {', '.join(c['findings'][:4])})" if c.get("findings") else ""), SMALL)
              for t, c in gaps[:15]]
    used = {e["id"] for fw in frameworks.values() for c in fw["controls"] for e in c.get("evidence", [])}
    exp = sum(1 for e in evidence if e["id"] in used and e.get("state") == "expired")
    s += [Spacer(1, 4 * mm), P(f"Evidence: {len(used)} file(s) supporting "
                               f"{sum(1 for fw in frameworks.values() for c in fw['controls'] if c.get('evidence'))} control(s)"
                               + (f"; {exp} expired." if exp else "."), BODY), PageBreak()]

    # per framework
    for fw in frameworks.values():
        s += [P("FRAMEWORK", KICK), P(fw["title"], H1)]
        rows = [["Control", "Status", "Basis"]]
        for c in fw["controls"]:
            if c["status"] == "not_assessed" and not include_na and not c.get("evidence") and not c.get("override"):
                continue
            basis = []
            if c.get("findings"):
                basis.append("Findings: " + ", ".join(c["findings"][:8]))
            if c.get("evidence"):
                basis.append("Evidence: " + ", ".join(e["name"] + (" (expired)" if e.get("state") == "expired" else "") for e in c["evidence"]))
            o = c.get("override") or {}
            if o.get("note"):
                basis.append("Organisation: " + o["note"])
            elif c.get("note"):
                basis.append(c["note"])
            if c.get("blocked"):
                basis.append("Organisation's status not applied while findings " + ", ".join(c["blocked"]) + " are open.")
            rows.append([Paragraph(f"<b>{escape(c['id'])}</b> {escape(c['title'])}", SMALL),
                         _status(c["status"]), P("\n".join(basis), SMALL)])
        s += [_table(rows, [W * .38, W * .12, W * .50]), PageBreak()]

    if include_findings and findings:
        s += [P("APPENDIX A", KICK), P("Open findings", H1)]
        rows = [["ID", "P", "Severity", "Finding", "Asset"]]
        for f in findings:
            rows.append([P(f["id"], SMALL), P(f"P{f.get('priority') or '-'}", SMALL), P(f.get("severity"), SMALL),
                         Paragraph(f"<b>{escape(f.get('title') or '')}</b><br/>{escape((f.get('recommendation') or '')[:400])}"
                                   + (f"<br/><font color='#666666'>ATT&amp;CK: {escape(', '.join(f['attack']))}</font>" if f.get("attack") else ""), SMALL),
                         P(f.get("asset"), SMALL)])
        s += [_table(rows, [W * .09, W * .06, W * .10, W * .55, W * .20])]
        if include_evidence:
            s.append(PageBreak())

    if include_evidence:
        s += [P("APPENDIX B", KICK), P("Evidence list", H1),
              P("Each file's SHA-256 fingerprint lets an auditor check that the files received are the ones this report lists.", SMALL),
              Spacer(1, 3 * mm)]
        rows = [["File", "Uploaded", "Valid until", "Controls"]]
        listed = [e for e in evidence if e["id"] in used] or evidence
        for e in listed:
            rows.append([[P(e["name"], SMALL), P(e["sha256"], MONO)],
                         P(f"{e['uploaded_by']}\n{time.strftime('%d %b %Y', time.localtime(e['uploaded_at']))}", SMALL),
                         P((e.get("valid_until") or "no expiry") + (" (expired)" if e.get("state") == "expired" else ""), SMALL),
                         P(", ".join(e.get("controls", []))[:300], SMALL)])
        s += [_table(rows, [W * .40, W * .18, W * .14, W * .28])] if listed else [P("No evidence uploaded.", BODY)]

    doc.build(s, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
