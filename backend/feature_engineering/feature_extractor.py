"""
NetSentinel AI
Module 3 - Feature Extraction

Converts NetworkFlow objects from Module 2 into
standardized machine-learning feature dictionaries.
"""

from __future__ import annotations

from typing import Iterable

from feature_engineering.feature_schema import FEATURE_NAMES


class FeatureExtractor:
    """Extract ML-ready features from network flows."""

    @staticmethod
    def _safe_int(value, default: int = 0) -> int:
        """Safely convert a value to an integer."""
        try:
            if value is None:
                return default
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _safe_float(value, default: float = 0.0) -> float:
        """Safely convert a value to a float."""
        try:
            if value is None:
                return default
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _safe_rate(value: float, duration: float) -> float:
        """Calculate a rate safely."""
        if duration <= 0:
            return 0.0

        return value / duration

    def extract_from_flow(self, flow) -> dict:
        """
        Convert a NetworkFlow object into a standardized
        machine-learning feature dictionary.

        Directional packet and byte values are taken directly
        from the NetworkFlow produced by Module 2.
        """

        # ---------------------------------------------------------
        # Basic flow information
        # ---------------------------------------------------------

        start_time = self._safe_float(
            getattr(flow, "start_time", 0.0)
        )

        end_time = self._safe_float(
            getattr(flow, "end_time", 0.0)
        )

        duration = max(
            end_time - start_time,
            0.0,
        )

        total_packets = self._safe_int(
            getattr(flow, "packet_count", 0)
        )

        total_bytes = self._safe_int(
            getattr(flow, "byte_count", 0)
        )

        # ---------------------------------------------------------
        # Network information
        # ---------------------------------------------------------

        source_port = self._safe_int(
            getattr(flow, "src_port", 0)
        )

        destination_port = self._safe_int(
            getattr(flow, "dst_port", 0)
        )

        protocol = str(
            getattr(flow, "protocol", "OTHER")
            or "OTHER"
        ).upper()

        # ---------------------------------------------------------
        # Directional traffic information
        # ---------------------------------------------------------

        forward_packets = self._safe_int(
            getattr(
                flow,
                "forward_packets",
                total_packets,
            )
        )

        reverse_packets = self._safe_int(
            getattr(
                flow,
                "reverse_packets",
                0,
            )
        )

        forward_bytes = self._safe_int(
            getattr(
                flow,
                "forward_bytes",
                total_bytes,
            )
        )

        reverse_bytes = self._safe_int(
            getattr(
                flow,
                "reverse_bytes",
                0,
            )
        )

        # ---------------------------------------------------------
        # TCP statistics
        # ---------------------------------------------------------

        tcp_syn_count = self._safe_int(
            getattr(
                flow,
                "tcp_syn_count",
                0,
            )
        )

        tcp_ack_count = self._safe_int(
            getattr(
                flow,
                "tcp_ack_count",
                0,
            )
        )

        tcp_fin_count = self._safe_int(
            getattr(
                flow,
                "tcp_fin_count",
                0,
            )
        )

        tcp_rst_count = self._safe_int(
            getattr(
                flow,
                "tcp_rst_count",
                0,
            )
        )

        # ---------------------------------------------------------
        # Derived traffic rates
        # ---------------------------------------------------------

        packets_per_second = self._safe_rate(
            total_packets,
            duration,
        )

        bytes_per_second = self._safe_rate(
            total_bytes,
            duration,
        )

        # ---------------------------------------------------------
        # Final standardized feature dictionary
        # ---------------------------------------------------------

        features = {
            "duration": duration,

            "total_packets": total_packets,

            "total_bytes": total_bytes,

            "packets_per_second": packets_per_second,

            "bytes_per_second": bytes_per_second,

            "source_port": source_port,

            "destination_port": destination_port,

            "protocol": protocol,

            "forward_packets": forward_packets,

            "reverse_packets": reverse_packets,

            "forward_bytes": forward_bytes,

            "reverse_bytes": reverse_bytes,

            "tcp_syn_count": tcp_syn_count,

            "tcp_ack_count": tcp_ack_count,

            "tcp_fin_count": tcp_fin_count,

            "tcp_rst_count": tcp_rst_count,
        }

        # ---------------------------------------------------------
        # Guarantee exact feature schema and ordering
        # ---------------------------------------------------------

        return {
            feature_name: features.get(
                feature_name,
                0,
            )
            for feature_name in FEATURE_NAMES
        }

    def extract_from_flows(
        self,
        flows: Iterable,
    ) -> list[dict]:
        """
        Extract features from multiple network flows.
        """

        return [
            self.extract_from_flow(flow)
            for flow in flows
        ]


# Shared extractor instance
feature_extractor = FeatureExtractor()