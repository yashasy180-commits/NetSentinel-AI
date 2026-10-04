"""
NetSentinel AI
Module 3 - Feature Schema

Defines the standardized network-flow features used by the
preprocessing and machine-learning pipeline.
"""

from __future__ import annotations

FEATURE_NAMES = [
    "duration",
    "total_packets",
    "total_bytes",
    "packets_per_second",
    "bytes_per_second",
    "source_port",
    "destination_port",
    "protocol",
    "forward_packets",
    "reverse_packets",
    "forward_bytes",
    "reverse_bytes",
    "tcp_syn_count",
    "tcp_ack_count",
    "tcp_fin_count",
    "tcp_rst_count",
]

NUMERIC_FEATURES = [
    "duration",
    "total_packets",
    "total_bytes",
    "packets_per_second",
    "bytes_per_second",
    "source_port",
    "destination_port",
    "forward_packets",
    "reverse_packets",
    "forward_bytes",
    "reverse_bytes",
    "tcp_syn_count",
    "tcp_ack_count",
    "tcp_fin_count",
    "tcp_rst_count",
]

CATEGORICAL_FEATURES = [
    "protocol",
]


def validate_feature_dictionary(features: dict) -> tuple[bool, list[str]]:
    """
    Validate that a feature dictionary contains every required feature.

    Returns:
        (True, []) when valid.
        (False, missing_features) when required features are missing.
    """
    missing = [
        feature
        for feature in FEATURE_NAMES
        if feature not in features
    ]

    return len(missing) == 0, missing


def get_feature_names() -> list[str]:
    """Return a copy of the complete ordered feature list."""
    return FEATURE_NAMES.copy()