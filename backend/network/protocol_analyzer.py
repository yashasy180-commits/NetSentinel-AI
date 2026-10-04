"""
NetSentinel AI
Module 2 - Protocol Analyzer

Analyzes observed packets and network flows.
This module is observational only.
"""

from __future__ import annotations

from collections import Counter
from typing import Iterable


class ProtocolAnalyzer:
    """Analyze network protocols, packets, and flows."""

    @staticmethod
    def identify_protocol(packet) -> str:
        """Identify the protocol represented by a packet."""

        from scapy.layers.inet import IP, TCP, UDP, ICMP

        if packet.haslayer(TCP):
            return "TCP"

        if packet.haslayer(UDP):
            return "UDP"

        if packet.haslayer(ICMP):
            return "ICMP"

        if packet.haslayer(IP):
            return "IP"

        return "OTHER"

    def analyze_packets(self, packets: Iterable) -> dict:
        """Analyze packet-level statistics."""

        packets = list(packets)

        protocol_counter = Counter()
        source_ips = Counter()
        destination_ips = Counter()
        source_ports = Counter()
        destination_ports = Counter()
        tcp_flags = Counter()

        total_bytes = 0
        ip_packet_count = 0

        for packet in packets:

            protocol = self.identify_protocol(packet)
            protocol_counter[protocol] += 1

            try:
                total_bytes += len(packet)
            except Exception:
                try:
                    total_bytes += len(bytes(packet))
                except Exception:
                    pass

            if packet.haslayer("IP"):

                ip_packet_count += 1

                ip_layer = packet["IP"]

                source_ips[str(ip_layer.src)] += 1
                destination_ips[str(ip_layer.dst)] += 1

            if packet.haslayer("TCP"):

                tcp_layer = packet["TCP"]

                source_ports[int(tcp_layer.sport)] += 1
                destination_ports[int(tcp_layer.dport)] += 1

                try:
                    flags = str(tcp_layer.flags)

                    for flag in flags:
                        tcp_flags[flag] += 1

                except Exception:
                    pass

            elif packet.haslayer("UDP"):

                udp_layer = packet["UDP"]

                source_ports[int(udp_layer.sport)] += 1
                destination_ports[int(udp_layer.dport)] += 1

        return {
            "packet_count": len(packets),
            "ip_packet_count": ip_packet_count,
            "total_bytes": total_bytes,
            "protocol_distribution": dict(protocol_counter),
            "top_source_ips": self._top_items(source_ips),
            "top_destination_ips": self._top_items(
                destination_ips
            ),
            "top_source_ports": self._top_items(
                source_ports
            ),
            "top_destination_ports": self._top_items(
                destination_ports
            ),
            "tcp_flags": dict(tcp_flags),
        }

    def analyze_flows(self, flows: Iterable) -> dict:
        """Analyze already-built NetworkFlow objects."""

        flows = list(flows)

        protocol_counter = Counter()
        source_ips = Counter()
        destination_ips = Counter()
        source_ports = Counter()
        destination_ports = Counter()

        total_packets = 0
        total_bytes = 0

        for flow in flows:

            protocol = str(
                getattr(flow, "protocol", "OTHER")
            ).upper()

            protocol_counter[protocol] += 1

            total_packets += int(
                getattr(
                    flow,
                    "packet_count",
                    0,
                )
            )

            # NetworkFlow uses byte_count.
            # Keep this explicit so the analyzer cannot
            # accidentally read a non-existent field.
            total_bytes += int(
                getattr(
                    flow,
                    "byte_count",
                    0,
                )
            )

            src_ip = getattr(
                flow,
                "src_ip",
                None,
            )

            dst_ip = getattr(
                flow,
                "dst_ip",
                None,
            )

            src_port = getattr(
                flow,
                "src_port",
                None,
            )

            dst_port = getattr(
                flow,
                "dst_port",
                None,
            )

            if src_ip:
                source_ips[str(src_ip)] += 1

            if dst_ip:
                destination_ips[str(dst_ip)] += 1

            if src_port is not None:
                source_ports[int(src_port)] += 1

            if dst_port is not None:
                destination_ports[int(dst_port)] += 1

        return {
            "flow_count": len(flows),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "protocol_distribution": dict(
                protocol_counter
            ),
            "top_source_ips": self._top_items(
                source_ips
            ),
            "top_destination_ips": self._top_items(
                destination_ips
            ),
            "top_source_ports": self._top_items(
                source_ports
            ),
            "top_destination_ports": self._top_items(
                destination_ports
            ),
        }

    def build_traffic_summary(
        self,
        packets: Iterable,
        flows: Iterable,
    ) -> dict:
        """Build combined packet and flow traffic summary."""

        packets = list(packets)
        flows = list(flows)

        return {
            "packets": self.analyze_packets(
                packets
            ),
            "flows": self.analyze_flows(
                flows
            ),
        }

    @staticmethod
    def _top_items(
        counter: Counter,
        limit: int = 10,
    ) -> list[dict]:
        """Convert Counter results to API-friendly dictionaries."""

        return [
            {
                "value": value,
                "count": count,
            }
            for value, count in counter.most_common(
                limit
            )
        ]


protocol_analyzer = ProtocolAnalyzer()