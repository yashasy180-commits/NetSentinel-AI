"""
NetSentinel AI
Module 7 - Security Reporting Routes
"""

from __future__ import annotations

from flask import Blueprint, request, send_file
from flask_jwt_extended import jwt_required

from services.report_service import ReportService


report_bp = Blueprint(
    "report",
    __name__,
    url_prefix="/api/reports",
)


@report_bp.get("/csv")
@jwt_required()
def export_csv():
    """Export security alerts as CSV."""

    status = request.args.get(
        "status",
        default=None,
        type=str,
    )

    severity = request.args.get(
        "severity",
        default=None,
        type=str,
    )

    report = ReportService.generate_csv(
        status=status,
        severity=severity,
    )

    return send_file(
        report,
        mimetype="text/csv",
        as_attachment=True,
        download_name="netsentinel_security_report.csv",
    )


@report_bp.get("/pdf")
@jwt_required()
def export_pdf():
    """Export security alerts as PDF."""

    status = request.args.get(
        "status",
        default=None,
        type=str,
    )

    severity = request.args.get(
        "severity",
        default=None,
        type=str,
    )

    report = ReportService.generate_pdf(
        status=status,
        severity=severity,
    )

    return send_file(
        report,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="netsentinel_security_report.pdf",
    )