"""
NetSentinel AI
Module 6 - Threat Detection & Alert Management API
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity

from security.authentication import active_user_required
from services.alert_service import alert_service

logger = logging.getLogger(__name__)

alert_bp = Blueprint(
    "alerts",
    __name__,
    url_prefix="/api/alerts",
)


@alert_bp.get("")
@active_user_required
def list_alerts():
    """Return security alerts with optional filters."""

    status = request.args.get("status")
    severity = request.args.get("severity")
    limit = request.args.get("limit", 100)

    try:
        limit = int(limit)
    except (TypeError, ValueError):
        return jsonify({
            "success": False,
            "message": "limit must be an integer.",
        }), 400

    if limit < 1 or limit > 500:
        return jsonify({
            "success": False,
            "message": "limit must be between 1 and 500.",
        }), 400

    if status:
        status = status.upper()

        if status not in alert_service.STATUSES:
            return jsonify({
                "success": False,
                "message": (
                    "Invalid status. Use OPEN, "
                    "ACKNOWLEDGED, or RESOLVED."
                ),
            }), 400

    if severity:
        severity = severity.upper()

        if severity not in alert_service.SEVERITIES:
            return jsonify({
                "success": False,
                "message": (
                    "Invalid severity. Use LOW, "
                    "MEDIUM, HIGH, or CRITICAL."
                ),
            }), 400

    alerts = alert_service.get_alerts(
        status=status,
        severity=severity,
        limit=limit,
    )

    return jsonify({
        "success": True,
        "count": len(alerts),
        "alerts": [
            alert.to_dict()
            for alert in alerts
        ],
    }), 200


@alert_bp.get("/statistics")
@active_user_required
def alert_statistics():
    """Return alert statistics."""

    return jsonify({
        "success": True,
        "statistics": alert_service.get_statistics(),
    }), 200


@alert_bp.get("/<int:alert_id>")
@active_user_required
def get_alert(alert_id: int):
    """Return a single alert."""

    alert = alert_service.get_alert(alert_id)

    if alert is None:
        return jsonify({
            "success": False,
            "message": "Alert not found.",
        }), 404

    return jsonify({
        "success": True,
        "alert": alert.to_dict(),
    }), 200


@alert_bp.post("/<int:alert_id>/acknowledge")
@active_user_required
def acknowledge_alert(alert_id: int):
    """Acknowledge an alert."""

    user_id = get_jwt_identity()

    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        return jsonify({
            "success": False,
            "message": "Invalid authenticated user.",
        }), 401

    try:
        alert = alert_service.acknowledge_alert(
            alert_id=alert_id,
            user_id=user_id,
        )

        if alert is None:
            return jsonify({
                "success": False,
                "message": "Alert not found.",
            }), 404

        return jsonify({
            "success": True,
            "message": "Alert acknowledged.",
            "alert": alert.to_dict(),
        }), 200

    except ValueError as exc:
        return jsonify({
            "success": False,
            "message": str(exc),
        }), 409

    except Exception:
        logger.exception(
            "Failed to acknowledge alert %s.",
            alert_id,
        )

        return jsonify({
            "success": False,
            "message": "Unable to acknowledge alert.",
        }), 500


@alert_bp.post("/<int:alert_id>/resolve")
@active_user_required
def resolve_alert(alert_id: int):
    """Resolve an alert."""

    user_id = get_jwt_identity()

    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        return jsonify({
            "success": False,
            "message": "Invalid authenticated user.",
        }), 401

    try:
        alert = alert_service.resolve_alert(
            alert_id=alert_id,
            user_id=user_id,
        )

        if alert is None:
            return jsonify({
                "success": False,
                "message": "Alert not found.",
            }), 404

        return jsonify({
            "success": True,
            "message": "Alert resolved.",
            "alert": alert.to_dict(),
        }), 200

    except Exception:
        logger.exception(
            "Failed to resolve alert %s.",
            alert_id,
        )

        return jsonify({
            "success": False,
            "message": "Unable to resolve alert.",
        }), 500