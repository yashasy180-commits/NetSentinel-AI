"""
NetSentinel AI
Security Report Service

Provides CSV and PDF report generation from persisted alerts.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from models.alert import Alert


class ReportService:
    """Generate security reports from persisted alert data."""

    @staticmethod
    def _query_alerts(
        status: str | None = None,
        severity: str | None = None,
        limit: int = 5000,
    ) -> list[Alert]:
        """Retrieve alerts using optional filters."""

        query = Alert.query

        if status:
            query = query.filter(
                Alert.status == status.upper()
            )

        if severity:
            query = query.filter(
                Alert.severity == severity.upper()
            )

        return (
            query
            .order_by(Alert.created_at.desc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def _format_datetime(value: Any) -> str:
        """Convert datetime values into report-friendly text."""

        if value is None:
            return ""

        if isinstance(value, datetime):
            return value.isoformat(
                timespec="seconds"
            )

        return str(value)

    @classmethod
    def generate_csv(
        cls,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 5000,
    ) -> io.BytesIO:
        """Generate a CSV report containing alert records."""

        alerts = cls._query_alerts(
            status=status,
            severity=severity,
            limit=limit,
        )

        output = io.StringIO()

        writer = csv.writer(output)

        writer.writerow(
            [
                "Alert ID",
                "Created At",
                "Alert Type",
                "Title",
                "Severity",
                "Status",
                "Confidence",
                "Probability",
                "Source IP",
                "Source Port",
                "Destination IP",
                "Destination Port",
                "Protocol",
                "Prediction",
                "Risk Level",
            ]
        )

        for alert in alerts:

            detection_data = (
                alert.detection_data
                if isinstance(
                    alert.detection_data,
                    dict,
                )
                else {}
            )

            writer.writerow(
                [
                    alert.id,
                    cls._format_datetime(
                        alert.created_at
                    ),
                    alert.alert_type,
                    alert.title,
                    alert.severity,
                    alert.status,
                    alert.confidence,
                    alert.probability,
                    alert.source_ip,
                    alert.source_port,
                    alert.destination_ip,
                    alert.destination_port,
                    alert.protocol,
                    detection_data.get(
                        "prediction",
                        "",
                    ),
                    detection_data.get(
                        "risk_level",
                        "",
                    ),
                ]
            )

        data = output.getvalue().encode(
            "utf-8-sig"
        )

        buffer = io.BytesIO(data)
        buffer.seek(0)

        return buffer

    @classmethod
    def generate_pdf(
        cls,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 5000,
    ) -> io.BytesIO:
        """Generate a PDF security alert report."""

        alerts = cls._query_alerts(
            status=status,
            severity=severity,
            limit=limit,
        )

        buffer = io.BytesIO()

        document = SimpleDocTemplate(
            buffer,
            pagesize=landscape(A4),
            rightMargin=10 * mm,
            leftMargin=10 * mm,
            topMargin=10 * mm,
            bottomMargin=10 * mm,
            title="NetSentinel AI Security Report",
            author="NetSentinel AI",
        )

        styles = getSampleStyleSheet()

        title_style = styles["Title"]
        heading_style = styles["Heading2"]
        normal_style = styles["BodyText"]

        story = []

        story.append(
            Paragraph(
                "NetSentinel AI",
                title_style,
            )
        )

        story.append(
            Paragraph(
                "Security Alert Report",
                heading_style,
            )
        )

        generated_at = datetime.now().isoformat(
            timespec="seconds"
        )

        filters = []

        if status:
            filters.append(
                f"Status: {status.upper()}"
            )

        if severity:
            filters.append(
                f"Severity: {severity.upper()}"
            )

        filter_text = (
            ", ".join(filters)
            if filters
            else "All alerts"
        )

        story.append(
            Paragraph(
                f"Generated: {generated_at}",
                normal_style,
            )
        )

        story.append(
            Paragraph(
                f"Filter: {filter_text}",
                normal_style,
            )
        )

        story.append(
            Paragraph(
                f"Records: {len(alerts)}",
                normal_style,
            )
        )

        story.append(
            Spacer(
                1,
                8 * mm,
            )
        )

        table_data = [
            [
                "ID",
                "Created",
                "Severity",
                "Status",
                "Confidence",
                "Source",
                "Destination",
                "Protocol",
                "Prediction",
            ]
        ]

        for alert in alerts:

            detection_data = (
                alert.detection_data
                if isinstance(
                    alert.detection_data,
                    dict,
                )
                else {}
            )

            source = (
                f"{alert.source_ip or '-'}:"
                f"{alert.source_port or '-'}"
            )

            destination = (
                f"{alert.destination_ip or '-'}:"
                f"{alert.destination_port or '-'}"
            )

            confidence = (
                f"{float(alert.confidence):.3f}"
                if alert.confidence is not None
                else ""
            )

            table_data.append(
                [
                    str(alert.id),
                    cls._format_datetime(
                        alert.created_at
                    ),
                    str(
                        alert.severity or ""
                    ),
                    str(
                        alert.status or ""
                    ),
                    confidence,
                    source,
                    destination,
                    str(
                        alert.protocol or ""
                    ),
                    str(
                        detection_data.get(
                            "prediction",
                            "",
                        )
                    ),
                ]
            )

        table = Table(
            table_data,
            repeatRows=1,
            colWidths=[
                10 * mm,
                35 * mm,
                23 * mm,
                25 * mm,
                25 * mm,
                42 * mm,
                42 * mm,
                22 * mm,
                30 * mm,
            ],
        )

        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor(
                            "#1f2937"
                        ),
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold",
                    ),
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.grey,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE",
                    ),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [
                            colors.white,
                            colors.HexColor(
                                "#f3f4f6"
                            ),
                        ],
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                ]
            )
        )

        story.append(table)

        story.append(
            Spacer(
                1,
                6 * mm,
            )
        )

        story.append(
            Paragraph(
                "Generated by NetSentinel AI "
                "Security Monitoring System.",
                normal_style,
            )
        )

        document.build(story)

        buffer.seek(0)

        return buffer