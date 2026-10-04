"""
NetSentinel AI
Module 7 - Security Analytics & Reporting

Authenticated analytics APIs.
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request

from security.authentication import (
    active_user_required,
)

from analytics.analytics_service import (
    analytics_service,
)


logger = logging.getLogger(__name__)


analytics_bp = Blueprint(
    "analytics",
    __name__,
    url_prefix="/api/analytics",
)


# =============================================================
# Overview
# =============================================================

@analytics_bp.get("/overview")
@active_user_required
def analytics_overview():

    return jsonify(
        {
            "success": True,
            "overview": (
                analytics_service.get_overview()
            ),
        }
    ), 200


# =============================================================
# Severity
# =============================================================

@analytics_bp.get("/severity")
@active_user_required
def analytics_severity():

    return jsonify(
        {
            "success": True,
            "distribution": (
                analytics_service
                .get_severity_distribution()
            ),
        }
    ), 200


# =============================================================
# Status
# =============================================================

@analytics_bp.get("/status")
@active_user_required
def analytics_status():

    return jsonify(
        {
            "success": True,
            "distribution": (
                analytics_service
                .get_status_distribution()
            ),
        }
    ), 200


# =============================================================
# Protocols
# =============================================================

@analytics_bp.get("/protocols")
@active_user_required
def analytics_protocols():

    return jsonify(
        {
            "success": True,
            "distribution": (
                analytics_service
                .get_protocol_distribution()
            ),
        }
    ), 200


# =============================================================
# Top Source IPs
# =============================================================

@analytics_bp.get("/top-sources")
@active_user_required
def analytics_top_sources():

    limit = request.args.get(
        "limit",
        10,
    )

    try:
        limit = int(limit)
    except (TypeError, ValueError):

        return jsonify(
            {
                "success": False,
                "message": (
                    "limit must be an integer."
                ),
            }
        ), 400

    return jsonify(
        {
            "success": True,
            "sources": (
                analytics_service
                .get_top_source_ips(
                    limit
                )
            ),
        }
    ), 200


# =============================================================
# Top Destination IPs
# =============================================================

@analytics_bp.get("/top-destinations")
@active_user_required
def analytics_top_destinations():

    limit = request.args.get(
        "limit",
        10,
    )

    try:
        limit = int(limit)
    except (TypeError, ValueError):

        return jsonify(
            {
                "success": False,
                "message": (
                    "limit must be an integer."
                ),
            }
        ), 400

    return jsonify(
        {
            "success": True,
            "destinations": (
                analytics_service
                .get_top_destination_ips(
                    limit
                )
            ),
        }
    ), 200


# =============================================================
# Threat History
# =============================================================

@analytics_bp.get("/threats")
@active_user_required
def analytics_threats():

    limit = request.args.get(
        "limit",
        100,
    )

    severity = request.args.get(
        "severity"
    )

    status = request.args.get(
        "status"
    )

    try:
        limit = int(limit)
    except (TypeError, ValueError):

        return jsonify(
            {
                "success": False,
                "message": (
                    "limit must be an integer."
                ),
            }
        ), 400

    try:

        threats = (
            analytics_service
            .get_threats(
                limit=limit,
                severity=severity,
                status=status,
            )
        )

        return jsonify(
            {
                "success": True,
                "count": len(threats),
                "threats": threats,
            }
        ), 200

    except Exception:

        logger.exception(
            "Failed to retrieve analytics threats."
        )

        return jsonify(
            {
                "success": False,
                "message": (
                    "Unable to retrieve threat analytics."
                ),
            }
        ), 500


# =============================================================
# Timeline
# =============================================================

@analytics_bp.get("/timeline")
@active_user_required
def analytics_timeline():

    hours = request.args.get(
        "hours",
        24,
    )

    try:
        hours = int(hours)
    except (TypeError, ValueError):

        return jsonify(
            {
                "success": False,
                "message": (
                    "hours must be an integer."
                ),
            }
        ), 400

    return jsonify(
        {
            "success": True,
            "hours": hours,
            "timeline": (
                analytics_service
                .get_timeline(hours)
            ),
        }
    ), 200


# =============================================================
# Dashboard
# =============================================================

@analytics_bp.get("/dashboard")
@active_user_required
def analytics_dashboard():

    timeline_hours = request.args.get(
        "hours",
        24,
    )

    top_limit = request.args.get(
        "limit",
        10,
    )

    try:

        timeline_hours = int(
            timeline_hours
        )

        top_limit = int(
            top_limit
        )

    except (TypeError, ValueError):

        return jsonify(
            {
                "success": False,
                "message": (
                    "hours and limit "
                    "must be integers."
                ),
            }
        ), 400

    return jsonify(
        {
            "success": True,
            "analytics": (
                analytics_service
                .get_dashboard_data(
                    timeline_hours=timeline_hours,
                    top_limit=top_limit,
                )
            ),
        }
    ), 200