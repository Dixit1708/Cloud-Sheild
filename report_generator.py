"""
CloudShield PDF Report Generator
"""
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from datetime import datetime

NAVY = colors.HexColor("#0b1120")
CYAN = colors.HexColor("#22d3ee")
PURPLE = colors.HexColor("#8b5cf6")

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#ef4444"),
    "High": colors.HexColor("#f97316"),
    "Medium": colors.HexColor("#eab308"),
    "Low": colors.HexColor("#22c55e"),
}


def generate_pdf_report(output_path, user, filename, security_score, risk_level,
                         counts, findings):
    doc = SimpleDocTemplate(output_path, pagesize=letter,
                             topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle("CSTitle", parent=styles["Title"],
                                  textColor=NAVY, fontSize=26, spaceAfter=4)
    tagline_style = ParagraphStyle("CSTag", parent=styles["Normal"],
                                    textColor=colors.HexColor("#475569"), fontSize=10)
    h2 = ParagraphStyle("CSH2", parent=styles["Heading2"], textColor=NAVY, spaceBefore=16)
    body = styles["BodyText"]

    story = []
    story.append(Paragraph("CloudShield", title_style))
    story.append(Paragraph("Secure Your Cloud. Detect Risks Before They Become Threats.",
                            tagline_style))
    story.append(Spacer(1, 14))
    story.append(Paragraph(f"Security Assessment Report", styles["Heading1"]))
    story.append(Paragraph(f"Generated for: {user.full_name} ({user.email})", body))
    story.append(Paragraph(f"Report Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", body))
    story.append(Paragraph(f"Source File: {filename}", body))
    story.append(Spacer(1, 12))

    # Executive summary table
    story.append(Paragraph("Executive Summary", h2))
    summary_data = [
        ["Security Score", f"{security_score} / 100"],
        ["Overall Risk Level", risk_level],
        ["Total Findings", str(counts["total"])],
        ["Critical", str(counts["critical"])],
        ["High", str(counts["high"])],
        ["Medium", str(counts["medium"])],
        ["Low", str(counts["low"])],
    ]
    t = Table(summary_data, colWidths=[2.5 * inch, 3 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e2e8f0")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 16))

    # Findings
    story.append(Paragraph("Detailed Security Findings", h2))
    for f in findings:
        sev = f.get("severity", "Low")
        color = SEVERITY_COLORS.get(sev, colors.grey)
        sev_style = ParagraphStyle("Sev", parent=body, textColor=color,
                                    fontName="Helvetica-Bold", fontSize=11)
        story.append(Paragraph(f"[{sev}] {f.get('issue', '')}", sev_style))
        story.append(Paragraph(f"<b>Affected Resource:</b> {f.get('affected_resource', 'N/A')}", body))
        story.append(Paragraph(f"<b>Description:</b> {f.get('description', '')}", body))
        story.append(Paragraph(f"<b>Risk Impact:</b> {f.get('risk_impact', '')}", body))
        story.append(Paragraph(f"<b>Recommendation:</b> {f.get('recommendation', '')}", body))
        steps = f.get("remediation_steps", [])
        if steps:
            story.append(Paragraph("<b>Remediation Steps:</b>", body))
            for s in steps:
                story.append(Paragraph(f"&bull; {s}", body))
        story.append(Spacer(1, 10))

    story.append(PageBreak())
    story.append(Paragraph("Improvement Plan", h2))
    story.append(Paragraph(
        "1. Remediate all Critical findings within 24-48 hours.<br/>"
        "2. Resolve High severity findings within 1 week.<br/>"
        "3. Schedule Medium/Low findings into the next sprint.<br/>"
        "4. Re-run CloudShield analysis after remediation to confirm improved score.<br/>"
        "5. Establish recurring quarterly cloud security reviews.", body))

    doc.build(story)
    return output_path
