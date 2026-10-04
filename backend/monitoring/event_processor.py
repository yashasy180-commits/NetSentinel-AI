"""
NetSentinel AI
Module 5 - Monitoring Event Processor

Processes captured packets into flows and sends them
through the AI detection engine.

This component is observational only.
"""

from __future__ import annotations

from typing import Iterable

from network.flow_builder import flow_builder
from network.protocol_analyzer import protocol_analyzer
from ml.detector import intrusion_detector


class MonitoringEventProcessor:
    """Convert captured packets into monitoring events."""

    def process_packets(
        self,
        packets: Iterable,
    ) -> dict:
        """
        Process one packet batch.

        Pipeline:

            packets
                ↓
            flow builder
                ↓
            protocol analyzer
                ↓
            AI detector
        """

        packets = list(packets)

        if not packets:
            return {
                "success": True,
                "packet_count": 0,
                "flow_count": 0,
                "threat_count": 0,
                "detections": [],
                "flows": [],
                "summary": {
                    "packets": {},
                    "flows": {},
                },
            }

        # -----------------------------------------------------
        # Build network flows
        # -----------------------------------------------------

        flows = flow_builder.build_flows(
            packets
        )

        # -----------------------------------------------------
        # Analyze traffic
        # -----------------------------------------------------

        summary = (
            protocol_analyzer
            .build_traffic_summary(
                packets,
                flows,
            )
        )

        # -----------------------------------------------------
        # AI detection
        # -----------------------------------------------------

        detections = (
            intrusion_detector.detect_flows(
                flows
            )
        )

        threat_count = sum(
            1
            for detection in detections
            if detection.get(
                "prediction"
            ) == "INTRUSION"
        )

        return {
            "success": True,
            "packet_count": len(
                packets
            ),
            "flow_count": len(
                flows
            ),
            "threat_count": threat_count,
            "detections": detections,
            "flows": flows,
            "summary": summary,
        }


# Shared processor instance.
event_processor = MonitoringEventProcessor()