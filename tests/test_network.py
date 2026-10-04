"""
NetSentinel AI
Module 2 - Network Traffic Collection Integration Tests

Tests the complete safe pipeline:

Synthetic packets
        ↓
Flow Builder
        ↓
Protocol Analyzer
        ↓
Traffic statistics
"""

from scapy.all import IP, TCP, UDP, Raw

from network.flow_builder import flow_builder
from network.protocol_analyzer import protocol_analyzer


def create_sample_packets():
    """Create safe synthetic packets for testing."""

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

    return packets


def test_flow_builder():
    """Verify packets are converted into network flows."""

    packets = create_sample_packets()

    flows = flow_builder.build_flows(
        packets
    )

    assert len(flows) > 0

    total_packets = sum(
        flow.packet_count
        for flow in flows
    )

    assert total_packets == len(packets)

    print()
    print("========== FLOW BUILDER ==========")
    print(f"Packets: {len(packets)}")
    print(f"Flows:   {len(flows)}")

    for flow in flows:
        print(flow.to_dict())


def test_protocol_analyzer():
    """Verify protocol statistics."""

    packets = create_sample_packets()

    statistics = protocol_analyzer.analyze_packets(
        packets
    )

    assert statistics["packet_count"] == len(
        packets
    )

    assert (
        statistics["protocol_distribution"]["TCP"]
        == 3
    )

    assert (
        statistics["protocol_distribution"]["UDP"]
        == 1
    )

    assert statistics["total_bytes"] > 0

    print()
    print("======= PROTOCOL ANALYZER ========")
    print(
        f"Packet count: {statistics['packet_count']}"
    )
    print(
        f"Total bytes:  {statistics['total_bytes']}"
    )
    print(
        "Protocols:",
        statistics["protocol_distribution"],
    )
    print(
        "Top source IPs:",
        statistics["top_source_ips"],
    )
    print(
        "Top destination ports:",
        statistics["top_destination_ports"],
    )


def test_flow_analysis():
    """Verify flow-level traffic statistics."""

    packets = create_sample_packets()

    flows = flow_builder.build_flows(
        packets
    )

    statistics = protocol_analyzer.analyze_flows(
        flows
    )

    assert statistics["flow_count"] == len(
        flows
    )

    assert statistics["total_packets"] == len(
        packets
    )

    assert statistics["total_bytes"] > 0

    print()
    print("========== FLOW ANALYSIS =========")
    print(
        f"Flow count:    {statistics['flow_count']}"
    )
    print(
        f"Total packets: {statistics['total_packets']}"
    )
    print(
        f"Total bytes:   {statistics['total_bytes']}"
    )
    print(
        "Protocols:",
        statistics["protocol_distribution"],
    )


def test_complete_network_pipeline():
    """
    Verify the complete Module 2 pipeline.
    """

    packets = create_sample_packets()

    flows = flow_builder.build_flows(
        packets
    )

    summary = protocol_analyzer.build_traffic_summary(
        packets,
        flows,
    )

    assert summary["packets"]["packet_count"] == 4

    assert summary["flows"]["flow_count"] > 0

    assert (
        summary["flows"]["total_packets"]
        == 4
    )

    print()
    print("==========================================")
    print("   NETSENTINEL AI - MODULE 2 PIPELINE")
    print("==========================================")
    print(
        f"Packets captured: {summary['packets']['packet_count']}"
    )
    print(
        f"Flows generated:  {summary['flows']['flow_count']}"
    )
    print(
        f"Total bytes:      {summary['packets']['total_bytes']}"
    )
    print(
        "Protocols:",
        summary["packets"]["protocol_distribution"],
    )
    print("==========================================")