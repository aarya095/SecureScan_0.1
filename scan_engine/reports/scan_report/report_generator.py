import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_LEFT

from tkinter import Tk
from tkinter.filedialog import asksaveasfilename

from Database.db_connection import DatabaseConnection


def generate_report(scan_id: int) -> str:
    # Connect to DB
    db = DatabaseConnection()
    db.connect()

    query = "SELECT scanned_url, scan_timestamp, scan_data FROM scan_results WHERE scan_id = %s"
    result = db.fetch_one(query, (scan_id,))
    db.close()

    if not result:
        raise ValueError("Scan ID not found in database.")

    url, timestamp, scan_data = result

    if isinstance(scan_data, str):
        scan_data = json.loads(scan_data)

    root = Tk()
    root.withdraw()  
    filename = asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF files", "*.pdf")],
        title="Save Security Report As",
        initialfile=f"scan_report_{scan_id}.pdf"
    )
    root.destroy()

    if not filename:
        print("User canceled save dialog.")
        return ""

    doc = SimpleDocTemplate(filename, pagesize=A4,
                            rightMargin=50, leftMargin=50,
                            topMargin=50, bottomMargin=50)
    styles = getSampleStyleSheet()
    kv_style = ParagraphStyle(
        'kv_style',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        spaceAfter=6,
        alignment=TA_LEFT
    )

    story = []

    # Header
    story.append(Paragraph("🔐 <b>Security Scan Report</b>", styles['Title']))
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(f"<b>Scan ID:</b> {scan_id}", kv_style))
    story.append(Paragraph(f"<b>Scanned URL:</b> {url}", kv_style))
    story.append(Paragraph(f"<b>Timestamp:</b> {timestamp.strftime('%Y-%m-%d %H:%M:%S')}", kv_style))
    story.append(Spacer(1, 0.3 * inch))

    # Helper to recursively render nested data
    def render_dict(data, indent=0):
        elements = []
        indent_space = "&nbsp;" * (4 * indent)
        for key, value in data.items():
            if isinstance(value, dict):
                elements.append(Paragraph(f"{indent_space}<b>{key}:</b>", kv_style))
                elements.extend(render_dict(value, indent + 1))
            elif isinstance(value, list):
                elements.append(Paragraph(f"{indent_space}<b>{key}:</b>", kv_style))
                for i, item in enumerate(value, start=1):
                    elements.append(Paragraph(f"{indent_space}&nbsp;&nbsp;- <i>Item {i}:</i>", kv_style))
                    if isinstance(item, dict):
                        elements.extend(render_dict(item, indent + 2))
                    else:
                        elements.append(Paragraph(f"{indent_space * 2}{item}", kv_style))
            else:
                elements.append(Paragraph(f"{indent_space}<b>{key}:</b> {value}", kv_style))
        return elements

    # Body - scan results
    for section, findings in scan_data.items():
        story.append(Paragraph(f"📄 <b>{section.replace('_', ' ').title()}</b>", styles['Heading2']))
        story.append(Spacer(1, 0.1 * inch))

        if isinstance(findings, dict):
            story.extend(render_dict(findings))
        elif isinstance(findings, list):
            for idx, item in enumerate(findings, start=1):
                story.append(Paragraph(f"<b>Item {idx}</b>", kv_style))
                if isinstance(item, dict):
                    story.extend(render_dict(item))
                else:
                    story.append(Paragraph(str(item), kv_style))
        else:
            story.append(Paragraph(str(findings), kv_style))

        story.append(Spacer(1, 0.3 * inch))

    doc.build(story)

    return filename
