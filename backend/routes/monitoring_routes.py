"""
NetSentinel AI
Module 5 - Real-Time Monitoring API Routes

Authenticated endpoints for starting, stopping,
and inspecting the network monitoring engine.

Monitoring is observational only.
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request

from monitoring.monitor import network_monitor
from security.authentication import active_user_required


logger = logging.getLogger(__name__)


monitoring_bp = Blueprint(
    "monitoring",
    __name__,
    url_prefix="/api/monitoring",
)


# ============================================================
# Status
# ============================================================

@monitoring_bp.get("/status")
@active_user_required
def monitoring_status():

    return jsonify(
        {
            "success": True,
            "status": network_monitor.get_status(),
        }
    ), 200


# ============================================================
# Start Monitoring
# ============================================================

@monitoring_bp.post("/start")
@active_user_required
def start_monitoring():

    data = request.get_json(
        silent=True
    )

    if data is None:
        data = {}

    if not isinstance(data, dict):

        return jsonify(
            {
                "success": False,
                "message": (
                    "JSON request body "
                    "must be an object."
                ),
            }
        ), 400

    interface = data.get(
        "interface"
    )

    packet_filter = data.get(
        "packet_filter"
    )

    if interface is not None:

        if not isinstance(
            interface,
            str,
        ):

            return jsonify(
                {
                    "success": False,
                    "message": (
                        "interface must "
                        "be a string."
                    ),
                }
            ), 400

        interface = interface.strip()

        if not interface:
            interface = None

    if packet_filter is not None:

        if not isinstance(
            packet_filter,
            str,
        ):

            return jsonify(
                {
                    "success": False,
                    "message": (
                        "packet_filter must "
                        "be a string."
                    ),
                }
            ), 400

        packet_filter = (
            packet_filter.strip()
        )

        if not packet_filter:
            packet_filter = None

    result = network_monitor.start(
        interface=interface,
        packet_filter=packet_filter,
    )

    status_code = (
        200
        if result.get("success")
        else 409
    )

    return jsonify(result), status_code


# ============================================================
# Stop Monitoring
# ============================================================

@monitoring_bp.post("/stop")
@active_user_required
def stop_monitoring():

    result = network_monitor.stop()

    status_code = (
        200
        if result.get("success")
        else 409
    )

    return jsonify(result), status_code