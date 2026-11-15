from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import Any

import pandas as pd

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
except Exception:  # pragma: no cover - optional dependency fallback
    colors = None
    A4 = None
    getSampleStyleSheet = None
    inch = None
    Paragraph = None
    SimpleDocTemplate = None
    Spacer = None
    Table = None
    TableStyle = None


def build_summary_metrics(frame: pd.DataFrame) -> dict[str, Any]:
    total_records = int(len(frame)) if not frame.empty else 0
    anomaly_count = int((frame.get("prediction", pd.Series(dtype=int)) == -1).sum()) if not frame.empty else 0
    severity_counts = frame.get("severity", pd.Series(dtype=str)).value_counts().to_dict() if not frame.empty else {}
    return {
        "total_records": total_records,
        "anomalies": anomaly_count,
        "severity_counts": severity_counts,
        "source_files": sorted(frame.get("source_file", pd.Series(dtype=str)).dropna().astype(str).unique().tolist()) if not frame.empty else [],
    }


def export_csv_bytes(frame: pd.DataFrame) -> bytes:
    return frame.to_csv(index=False).encode("utf-8")


def export_pdf_bytes(frame: pd.DataFrame, title: str = "CyberSpectra Report") -> bytes:
    if SimpleDocTemplate is None:
        return f"{title}\n\nPDF export dependency unavailable.\n".encode("utf-8")

    buffer = BytesIO()
    document = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    story = [Paragraph(title, styles["Title"]), Spacer(1, 0.2 * inch)]

    summary = build_summary_metrics(frame)
    summary_rows = [["Metric", "Value"], ["Total records", str(summary["total_records"])], ["Anomalies", str(summary["anomalies"])], ["Unique source files", str(len(summary["source_files"]))]]
    summary_table = Table(summary_rows, hAlign="LEFT")
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a3a52")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([summary_table, Spacer(1, 0.2 * inch)])

    if not frame.empty and "severity" in frame.columns:
        counts = frame["severity"].value_counts()
        severity_rows = [["Severity", "Count", "Share"]] + [
            [name, str(int(counts.get(name, 0))), f"{counts.get(name, 0) / len(frame):.1%}"] for name in ["Critical", "High", "Medium", "Low"]
        ]
        if "risk_score" in frame.columns:
            risk = pd.to_numeric(frame["risk_score"], errors="coerce")
            severity_rows.append(["Average risk score", f"{risk.mean():.1f}/100", f"max {risk.max():.1f}"])
        severity_table = Table(severity_rows, hAlign="LEFT")
        severity_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a3a52")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.extend([Paragraph("Severity distribution", styles["Heading2"]), severity_table, Spacer(1, 0.2 * inch)])

    if not frame.empty:
        columns = [column for column in ["timestamp", "severity", "risk_score", "message", "source_file"] if column in frame.columns]
        table_rows = [columns] + frame.head(10)[columns].astype(str).values.tolist()
        data_table = Table([[str(cell)[:60] for cell in row] for row in table_rows], repeatRows=1)
        data_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ef6c00")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.extend([Paragraph("Top Records", styles["Heading2"]), Spacer(1, 0.1 * inch), data_table])

    document.build(story)
    return buffer.getvalue()


def write_pdf_report(frame: pd.DataFrame, output_path: str | Path, title: str = "CyberSpectra Report") -> Path:
    path = Path(output_path)
    path.write_bytes(export_pdf_bytes(frame, title=title))
    return path
