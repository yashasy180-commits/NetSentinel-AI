from scapy.all import IP, TCP, UDP, Raw

from network.flow_builder import flow_builder
from network.protocol_analyzer import protocol_analyzer


def create_sample_packets():
    return [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="S"),

        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=443, dport=50000, flags="SA"),

        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=53000, dport=53)
        / Raw(load=b"sample-dns-data"),

        IP(src="192.168.1.10", dst="192.168.1.30")
        / TCP(sport=51000, dport=80, flags="S"),
    ]


def test_flow_builder():
    packets = create_sample_packets()

    flows = flow_builder.build_flows(packets)

    assert len(flows) > 0

    total_packets = sum(
        flow.packet_count
        for flow in flows
    )

    assert total_packets == len(packets)


def test_protocol_analyzer():
    packets = create_sample_packets()

    statistics = protocol_analyzer.analyze_packets(
        packets
    )

    assert statistics["packet_count"] == 4
    assert statistics["protocol_distribution"]["TCP"] == 3
    assert statistics["protocol_distribution"]["UDP"] == 1
    assert statistics["total_bytes"] > 0


def test_flow_analysis():
    packets = create_sample_packets()

    flows = flow_builder.build_flows(packets)

    statistics = protocol_analyzer.analyze_flows(
        flows
    )

    assert statistics["flow_count"] == len(flows)
    assert statistics["total_packets"] == 4
    assert statistics["total_bytes"] > 0


def test_complete_network_pipeline():
    packets = create_sample_packets()

    flows = flow_builder.build_flows(packets)

    summary = protocol_analyzer.build_traffic_summary(
        packets,
        flows,
    )

    assert summary["packets"]["packet_count"] == 4
    assert summary["flows"]["flow_count"] > 0
    assert summary["flows"]["total_packets"] == 4
