"""
NetSentinel AI
Module 2 + Module 4 - Network Traffic & AI Detection API

Provides defensive API endpoints for:
- Network interface discovery
- Capture status
- Safe synthetic traffic analysis
- AI intrusion detection on sample traffic
- PCAP analysis
- AI intrusion detection on PCAP flows

No offensive traffic generation or packet injection is performed.
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request

from network.flow_builder import flow_builder
from network.packet_capture import packet_capture
from network.pcap_reader import pcap_reader
from network.protocol_analyzer import protocol_analyzer

from ml.detector import intrusion_detector
from services.alert_service import alert_service

from security.authentication import active_user_required


logger = logging.getLogger(__name__)


traffic_bp = Blueprint(
    "traffic",
    __name__,
    url_prefix="/api/traffic",
)


# ============================================================
# Network Interfaces
# ============================================================

@traffic_bp.get("/interfaces")
@active_user_required
def get_interfaces():

    interfaces = packet_capture.list_interfaces()

    return jsonify(
        {
            "success": True,
            "interfaces": interfaces,
            "count": len(interfaces),
        }
    ), 200


# ============================================================
# Capture Status
# ============================================================

@traffic_bp.get("/status")
@active_user_required
def capture_status():

    return jsonify(
        {
            "success": True,
            "capturing": packet_capture.is_capturing,
        }
    ), 200


# ============================================================
# Safe Sample Traffic Analysis
# ============================================================

@traffic_bp.post("/sample")
@active_user_required
def analyze_sample_traffic():

    try:

        from scapy.all import (
            IP,
            TCP,
            UDP,
            Raw,
        )

        packets = [

            IP(
                src="192.168.1.10",
                dst="192.168.1.20",
            )
            / TCP(
                sport=50000,
                dport=443,
                flags="S",
            ),

            IP(
                src="192.168.1.20",
                dst="192.168.1.10",
            )
            / TCP(
                sport=443,
                dport=50000,
                flags="SA",
            ),

            IP(
                src="192.168.1.10",
                dst="192.168.1.20",
            )
            / UDP(
                sport=53000,
                dport=53,
            )
            / Raw(
                load=b"sample-dns-data"
            ),

            IP(
                src="192.168.1.10",
                dst="192.168.1.30",
            )
            / TCP(
                sport=51000,
                dport=80,
                flags="S",
            ),
        ]

        flows = flow_builder.build_flows(
            packets
        )

        summary = (
            protocol_analyzer
            .build_traffic_summary(
                packets,
                flows,
            )
        )

        return jsonify(
            {
                "success": True,
                "mode": "SAFE_SAMPLE",
                "summary": summary,
            }
        ), 200

    except Exception:

        logger.exception(
            "Safe sample traffic analysis failed."
        )

        return jsonify(
            {
                "success": False,
                "message": (
                    "Unable to analyze "
                    "sample traffic."
                ),
            }
        ), 500


# ============================================================
# AI Detection on Safe Sample Traffic
# ============================================================

@traffic_bp.post("/detect-sample")
@active_user_required
def detect_sample_traffic():

    try:

        from scapy.all import (
            IP,
            TCP,
            UDP,
            Raw,
        )

        packets = [

            IP(
                src="192.168.1.10",
                dst="192.168.1.20",
            )
            / TCP(
                sport=50000,
                dport=443,
                flags="S",
            ),

            IP(
                src="192.168.1.20",
                dst="192.168.1.10",
            )
            / TCP(
                sport=443,
                dport=50000,
                flags="SA",
            ),

            IP(
                src="192.168.1.10",
                dst="192.168.1.20",
            )
            / UDP(
                sport=53000,
                dport=53,
            )
            / Raw(
                load=b"sample-dns-data"
            ),

            IP(
                src="192.168.1.10",
                dst="192.168.1.30",
            )
            / TCP(
                sport=51000,
                dport=80,
                flags="S",
            ),
        ]

        flows = flow_builder.build_flows(
            packets
        )

        detections = (
            intrusion_detector.detect_flows(
                flows
            )
        )

        threat_count = sum(
            1
            for result in detections
            if result["prediction"]
            == "INTRUSION"
        )

        return jsonify(
            {
                "success": True,
                "mode": "SAFE_SAMPLE_AI",
                "packet_count": len(
                    packets
                ),
                "flow_count": len(
                    flows
                ),
                "threat_count": threat_count,
                "detections": detections,
            }
        ), 200

    except Exception:

        logger.exception(
            "AI sample detection failed."
        )

        return jsonify(
            {
                "success": False,
                "message": (
                    "Unable to perform "
                    "AI traffic detection."
                ),
            }
        ), 500


# ============================================================
# Safe Synthetic Intrusion Simulation
# ============================================================

@traffic_bp.post("/simulate-intrusion")
@active_user_required
def simulate_intrusion():
    """
    Run the trained intrusion detector against an in-memory
    synthetic flow that resembles the controlled intrusion-like
    patterns used by the project's training dataset.

    No packets are transmitted and no network attack is performed.
    This endpoint exists only to validate the ML detection pipeline.
    """

    try:

        simulated_features = {
            "duration": 1.0,
            "total_packets": 1200,
            "total_bytes": 600000,
            "packets_per_second": 1200.0,
            "bytes_per_second": 600000.0,
            "source_port": 55000,
            "destination_port": 445,
            "protocol": "TCP",
            "forward_packets": 1100,
            "reverse_packets": 100,
            "forward_bytes": 550000,
            "reverse_bytes": 50000,
            "tcp_syn_count": 40,
            "tcp_ack_count": 5,
            "tcp_fin_count": 0,
            "tcp_rst_count": 3,
        }

        detection = intrusion_detector.detect_features(
            simulated_features
        )

        # -----------------------------------------------------
        # Persist an alert only if the real ML engine
        # classifies the controlled synthetic flow as INTRUSION.
        # No packets are transmitted.
        # -----------------------------------------------------

        alert = None

        if detection.get("prediction") == "INTRUSION":
            alert = alert_service.create_alert(
                detection=detection,
                source_ip="192.168.1.100",
                destination_ip="192.168.1.20",
            )

        return jsonify(
            {
                "success": True,
                "mode": "SAFE_SYNTHETIC_INTRUSION",
                "simulation": {
                    "packets_transmitted": False,
                    "network_traffic_generated": False,
                    "purpose": (
                        "ML detection and alert pipeline validation"
                    ),
                },
                "detection": detection,
                "alert_created": alert is not None,
                "alert": (
                    alert.to_dict()
                    if alert is not None
                    else None
                ),
                "features": simulated_features,
            }
        ), 200

    except Exception:

        logger.exception(
            "Safe synthetic intrusion simulation failed."
        )

        return jsonify(
            {
                "success": False,
                "message": (
                    "Unable to run the safe synthetic "
                    "intrusion simulation."
                ),
            }
        ), 500


# ============================================================
# PCAP Analysis
# ============================================================

@traffic_bp.post("/pcap/analyze")
@active_user_required
def analyze_pcap():

    data = request.get_json(
        silent=True
    )

    if not isinstance(
        data,
        dict,
    ):

        return jsonify(
            {
                "success": False,
                "message": (
                    "JSON request body "
                    "is required."
                ),
            }
        ), 400

    file_path = data.get(
        "file_path"
    )

    packet_limit = data.get(
        "packet_limit"
    )

    if not file_path:

        return jsonify(
            {
                "success": False,
                "message": (
                    "file_path is required."
                ),
            }
        ), 400

    if packet_limit is not None:

        if (
            not isinstance(
                packet_limit,
                int,
            )
            or isinstance(
                packet_limit,
                bool,
            )
            or packet_limit <= 0
        ):

            return jsonify(
                {
                    "success": False,
                    "message": (
                        "packet_limit must "
                        "be a positive integer."
                    ),
                }
            ), 400

    try:

        result = pcap_reader.read(
            file_path=file_path,
            packet_limit=packet_limit,
        )

        if not result["success"]:

            return jsonify(
                {
                    "success": False,
                    "message": result[
                        "error"
                    ],
                }
            ), 400

        packets = result[
            "packets"
        ]

        flows = flow_builder.build_flows(
            packets
        )

        summary = (
            protocol_analyzer
            .build_traffic_summary(
                packets,
                flows,
            )
        )

        return jsonify(
            {
                "success": True,
                "mode": "PCAP",
                "file_path": result[
                    "file_path"
                ],
                "packet_count": result[
                    "packet_count"
                ],
                "flow_count": len(
                    flows
                ),
                "summary": summary,
            }
        ), 200

    except Exception:

        logger.exception(
            "PCAP analysis API failed."
        )

        return jsonify(
            {
                "success": False,
                "message": (
                    "Unable to analyze "
                    "the PCAP file."
                ),
            }
        ), 500


# ============================================================
# AI Detection on PCAP
# ============================================================

@traffic_bp.post("/pcap/detect")
@active_user_required
def detect_pcap():

    data = request.get_json(
        silent=True
    )

    if not isinstance(
        data,
        dict,
    ):

        return jsonify(
            {
                "success": False,
                "message": (
                    "JSON request body "
                    "is required."
                ),
            }
        ), 400

    file_path = data.get(
        "file_path"
    )

    packet_limit = data.get(
        "packet_limit"
    )

    if not file_path:

        return jsonify(
            {
                "success": False,
                "message": (
                    "file_path is required."
                ),
            }
        ), 400

    if packet_limit is not None:

        if (
            not isinstance(
                packet_limit,
                int,
            )
            or isinstance(
                packet_limit,
                bool,
            )
            or packet_limit <= 0
        ):

            return jsonify(
                {
                    "success": False,
                    "message": (
                        "packet_limit must "
                        "be a positive integer."
                    ),
                }
            ), 400

    try:

        result = pcap_reader.read(
            file_path=file_path,
            packet_limit=packet_limit,
        )

        if not result["success"]:

            return jsonify(
                {
                    "success": False,
                    "message": result[
                        "error"
                    ],
                }
            ), 400

        packets = result[
            "packets"
        ]

        flows = flow_builder.build_flows(
            packets
        )

        detections = (
            intrusion_detector.detect_flows(
                flows
            )
        )

        threat_count = sum(
            1
            for detection in detections
            if detection[
                "prediction"
            ] == "INTRUSION"
        )

        return jsonify(
            {
                "success": True,
                "mode": "PCAP_AI",
                "file_path": result[
                    "file_path"
                ],
                "packet_count": result[
                    "packet_count"
                ],
                "flow_count": len(
                    flows
                ),
                "threat_count": threat_count,
                "detections": detections,
            }
        ), 200

    except Exception:

        logger.exception(
            "AI PCAP detection failed."
        )

        return jsonify(
            {
                "success": False,
                "message": (
                    "Unable to perform "
                    "AI detection on "
                    "the PCAP file."
                ),
            }
        ), 500
