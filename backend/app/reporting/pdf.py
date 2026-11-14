from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from datetime import datetime


def build_pdf(path_out, scan, app, findings, score_info):
    doc = SimpleDocTemplate(
        str(path_out), pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )
    styles = getSampleStyleSheet()

    # --- styles ---
    title_style = ParagraphStyle("title", parent=styles["Title"], fontSize=28, spaceAfter=20, textColor=colors.HexColor("#0f172a"))
    subtitle = ParagraphStyle("subtitle", parent=styles["Normal"], fontSize=14, textColor=colors.grey, spaceAfter=30)
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=18, spaceBefore=20, spaceAfter=10, textColor=colors.HexColor("#0f172a"))
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=14, spaceBefore=12, spaceAfter=6, textColor=colors.HexColor("#1e293b"))
    body = styles["BodyText"]
    code = ParagraphStyle("code", parent=styles["Code"], fontSize=8, backColor=colors.HexColor("#f1f5f9"))

    SEVERITY_COLORS = {
        "critical": colors.HexColor("#dc2626"),
        "high": colors.HexColor("#ea580c"),
        "medium": colors.HexColor("#d97706"),
        "low": colors.HexColor("#ca8a04"),
        "info": colors.HexColor("#475569"),
    }

    story = []

    # ---------- COVER PAGE ----------
    story.append(Spacer(1, 3*cm))
    story.append(Paragraph("IPA SENTINEL", title_style))
    story.append(Paragraph("iOS Application Security Assessment Report", subtitle))
    story.append(Spacer(1, 1*cm))

    cover_data = [
        ["Scan ID", scan.id],
        ["File", scan.filename],
        ["SHA-256", scan.sha256],
        ["Scan Date", scan.created_at.strftime("%Y-%m-%d %H:%M:%S") if scan.created_at else "N/A"],
    ]
    cover_table = Table(cover_data, colWidths=[4*cm, 12*cm])
    cover_table.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#f1f5f9")),
        ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 9),
    ]))
    story.append(cover_table)
    story.append(PageBreak())

    # ---------- TABLE OF CONTENTS ----------
    story.append(Paragraph("Table of Contents", h1))
    toc_items = [
        "1. Executive Summary",
        "2. Application Metadata",
        "3. Security Score",
        "4. Findings Overview",
        "5. Detailed Findings",
        "6. Binary Analysis",
        "7. Entitlements & Provisioning",
        "8. Privacy Assessment",
        "9. Remediation Checklist",
        "10. Methodology & Limitations",
    ]
    for item in toc_items:
        story.append(Paragraph(item, body))
    story.append(PageBreak())

    # ---------- 1. EXECUTIVE SUMMARY ----------
    story.append(Paragraph("1. Executive Summary", h1))
    total = len(findings)
    sev_counts = score_info["counts"]

    story.append(Paragraph(
        f"This report presents the results of a static security assessment of the iOS application "
        f"<b>{scan.filename}</b>, performed by IPA Sentinel. A total of <b>{total}</b> findings were identified "
        f"across all severity levels.", body))
    story.append(Spacer(1, 0.5*cm))

    summary_data = [
        ["Severity", "Count"],
        ["Critical", str(sev_counts["critical"])],
        ["High", str(sev_counts["high"])],
        ["Medium", str(sev_counts["medium"])],
        ["Low", str(sev_counts["low"])],
        ["Info", str(sev_counts["info"])],
        ["Total", str(total)],
    ]
    summary_table = Table(summary_data, colWidths=[6*cm, 4*cm])
    summary_table.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("ALIGN", (1,1), (1,-1), "CENTER"),
        ("FONTSIZE", (0,0), (-1,-1), 10),
    ]))
    story.append(summary_table)
    story.append(PageBreak())

    # ---------- 2. APPLICATION METADATA ----------
    story.append(Paragraph("2. Application Metadata", h1))
    if app:
        meta = [
            ["Bundle ID", app.bundle_id or "-"],
            ["Name", app.name or "-"],
            ["Display Name", app.display_name or "-"],
            ["Version", app.version or "-"],
            ["Short Version", app.short_version or "-"],
            ["Executable", app.executable or "-"],
            ["Minimum OS", app.min_os or "-"],
            ["Platform", app.platform or "-"],
        ]
        meta_table = Table(meta, colWidths=[4*cm, 12*cm])
        meta_table.setStyle(TableStyle([
            ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
            ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#f1f5f9")),
            ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 9),
        ]))
        story.append(meta_table)
    story.append(PageBreak())

    # ---------- 3. SECURITY SCORE ----------
    story.append(Paragraph("3. Security Score", h1))
    score = score_info["score"]
    if score >= 90:
        verdict, color = "Well Hardened", colors.HexColor("#10b981")
    elif score >= 70:
        verdict, color = "Acceptable — Fix Issues", colors.HexColor("#f59e0b")
    elif score >= 40:
        verdict, color = "Medium Risk", colors.HexColor("#f97316")
    else:
        verdict, color = "High Risk — Immediate Remediation", colors.HexColor("#dc2626")

    score_data = [
        ["Score", f"{score} / 100"],
        ["Verdict", verdict],
        ["Penalty", f"{score_info['penalty']} (from weighted findings)"],
    ]
    score_table = Table(score_data, colWidths=[4*cm, 12*cm])
    score_table.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("BACKGROUND", (0,0), (0,-1), color),
        ("TEXTCOLOR", (0,0), (0,-1), colors.white),
        ("FONTNAME", (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 11),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(
        "<i>Note: This score is an internal IPA Sentinel metric, not an official security certification. "
        "It weights findings by severity and confidence to provide a relative risk indicator.</i>",
        ParagraphStyle("note", parent=body, fontSize=8, textColor=colors.grey)
    ))
    story.append(PageBreak())

    # ---------- 4. FINDINGS OVERVIEW ----------
    story.append(Paragraph("4. Findings Overview", h1))
    if findings:
        overview = [["Severity", "Rule ID", "Title", "File"]]
        for f in findings:
            overview.append([
                f.severity.upper(),
                f.rule_id or "-",
                (f.title or "")[:60],
                (f.file_path or "-")[:40],
            ])
        overview_table = Table(overview, colWidths=[2*cm, 3.5*cm, 7*cm, 4*cm])
        overview_style = [
            ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 7),
        ]
        # Color-code rows by severity
        for i, f in enumerate(findings, start=1):
            c = SEVERITY_COLORS.get(f.severity, colors.grey)
            overview_style.append(("TEXTCOLOR", (0,i), (0,i), c))
            overview_style.append(("FONTNAME", (0,i), (0,i), "Helvetica-Bold"))
        overview_table.setStyle(TableStyle(overview_style))
        story.append(overview_table)
    else:
        story.append(Paragraph("No findings were identified.", body))
    story.append(PageBreak())

    # ---------- 5. DETAILED FINDINGS ----------
    story.append(Paragraph("5. Detailed Findings", h1))
    for i, f in enumerate(findings, start=1):
        sev = (f.severity or "info").upper()
        sev_color = SEVERITY_COLORS.get(f.severity, colors.grey)

        story.append(Paragraph(
            f"<font color='#{sev_color.hexval()[2:]}'><b>[{sev}]</b></font> "
            f"<b>Finding #{i}: {f.title}</b>",
            h2
        ))

        detail = [["Field", "Value"]]
        detail.append(["Rule ID", f.rule_id or "-"])
        detail.append(["Severity", sev])
        detail.append(["Confidence", (f.confidence or "-").upper()])
        detail.append(["Category", f.category or "-"])
        if f.file_path:
            detail.append(["File", f.file_path])
        if f.cwe:
            detail.append(["CWE", f.cwe])

        detail_table = Table(detail, colWidths=[3*cm, 13*cm])
        detail_table.setStyle(TableStyle([
            ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
            ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#f1f5f9")),
            ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 8),
        ]))
        story.append(detail_table)

        if f.description:
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph("<b>Description:</b>", body))
            story.append(Paragraph(f.description, body))

        if f.evidence:
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph("<b>Evidence:</b>", body))
            story.append(Paragraph(f.evidence[:500], code))

        if f.impact:
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph("<b>Impact:</b>", body))
            story.append(Paragraph(f.impact, body))

        if f.remediation:
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph("<b>Remediation:</b>", body))
            story.append(Paragraph(f.remediation, body))

        story.append(Spacer(1, 0.5*cm))
    story.append(PageBreak())

    # ---------- 6-9. TECHNICAL SECTIONS ----------
    story.append(Paragraph("6. Binary Analysis", h1))
    story.append(Paragraph(
        "IPA Sentinel parses the Mach-O executable using LIEF to assess binary-level protections: "
        "PIE (Position Independent Executable), stack canary presence, encryption status, and imported libraries.",
        body))
    binary_findings = [f for f in findings if f.analyzer == "macho"]
    if binary_findings:
        for f in binary_findings:
            story.append(Paragraph(f"• <b>[{(f.severity or '').upper()}]</b> {f.title}", body))
    else:
        story.append(Paragraph("No binary-level issues detected.", body))
    story.append(PageBreak())

    story.append(Paragraph("7. Entitlements & Provisioning", h1))
    ent_findings = [f for f in findings if f.analyzer == "entitlements"]
    if ent_findings:
        for f in ent_findings:
            story.append(Paragraph(f"• <b>[{(f.severity or '').upper()}]</b> {f.title}", body))
    else:
        story.append(Paragraph("No entitlement issues detected.", body))
    story.append(PageBreak())

    story.append(Paragraph("8. Privacy Assessment", h1))
    priv_findings = [f for f in findings if f.analyzer == "privacy"]
    if priv_findings:
        for f in priv_findings:
            story.append(Paragraph(f"• <b>[{(f.severity or '').upper()}]</b> {f.title}", body))
    else:
        story.append(Paragraph("No privacy issues detected.", body))
    story.append(PageBreak())

    # ---------- 9. REMEDIATION CHECKLIST ----------
    story.append(Paragraph("9. Remediation Checklist", h1))
    story.append(Paragraph(
        "The following actions are recommended, ordered by priority. Each item addresses "
        "one or more findings from this report.", body))
    story.append(Spacer(1, 0.3*cm))

    seen_remediations = set()
    for f in findings:
        if not f.remediation:
            continue
        rem = f.remediation.strip()
        if rem in seen_remediations:
            continue
        seen_remediations.add(rem)
        story.append(Paragraph(
            f"☐ <b>[{(f.severity or '').upper()}]</b> {rem}",
            body
        ))
        story.append(Spacer(1, 0.15*cm))

    story.append(PageBreak())

    # ---------- 10. METHODOLOGY & LIMITATIONS ----------
    story.append(Paragraph("10. Methodology & Limitations", h1))
    story.append(Paragraph("<b>Methodology</b>", h2))
    story.append(Paragraph(
        "IPA Sentinel performs static analysis of the IPA package. The tool extracts the archive, "
        "parses Info.plist, inspects the Mach-O executable with LIEF, extracts embedded strings, "
        "analyzes Xamarin/.NET assemblies, applies YARA rules, and cross-references findings against "
        "a curated CVE database. All analysis runs locally — no data is sent to any external service.",
        body))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("<b>Limitations</b>", h2))
    story.append(Paragraph(
        "• This is a <b>static</b> analysis. It does not execute the application or perform runtime testing.",
        body))
    story.append(Paragraph(
        "• Cryptographic signature verification is not performed. The tool reports the presence of "
        "signature metadata, not its validity.",
        body))
    story.append(Paragraph(
        "• Findings are indicative, not definitive. Manual review by a qualified security engineer "
        "is recommended before drawing conclusions.",
        body))
    story.append(Paragraph(
        "• The CVE database is a curated subset. Zero findings does not guarantee the absence of "
        "known vulnerabilities in third-party libraries.",
        body))
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(
        f"<i>Report generated by IPA Sentinel on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</i>",
        ParagraphStyle("footer", parent=body, fontSize=8, textColor=colors.grey)
    ))

    doc.build(story)
