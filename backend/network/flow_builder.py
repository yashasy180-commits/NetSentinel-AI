"""
NetSentinel AI
Module 2 - Network Flow Builder

Builds bidirectional network flows from observed packets.
This module is observational only and does not generate traffic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class NetworkFlow:
    """Represents a bidirectional network flow."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    packet_count: int = 0
    byte_count: int = 0

    start_time: float = 0.0
    end_time: float = 0.0

    forward_packets: int = 0
    reverse_packets: int = 0

    forward_bytes: int = 0
    reverse_bytes: int = 0

    tcp_flags: str = ""

    tcp_syn_count: int = 0
    tcp_ack_count: int = 0
    tcp_fin_count: int = 0
    tcp_rst_count: int = 0

    _seen_flags: list[str] = field(
        default_factory=list,
        repr=False,
    )

    @property
    def duration(self) -> float:
        """Return the duration of the flow in seconds."""
        return max(
            self.end_time - self.start_time,
            0.0,
        )


class FlowBuilder:
    """Builds bidirectional flows from IPv4 TCP/UDP packets."""

    @staticmethod
    def _get_protocol(packet) -> str | None:
        """Identify supported transport protocol."""

        from scapy.layers.inet import IP, TCP, UDP

        if not packet.haslayer(IP):
            return None

        if packet.haslayer(TCP):
            return "TCP"

        if packet.haslayer(UDP):
            return "UDP"

        return None

    @staticmethod
    def _get_endpoints(packet):
        """Extract IP addresses, ports and protocol."""

        from scapy.layers.inet import IP, TCP, UDP

        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        protocol = FlowBuilder._get_protocol(packet)

        if protocol == "TCP":
            transport = packet[TCP]
        elif protocol == "UDP":
            transport = packet[UDP]
        else:
            return None

        return (
            str(ip_layer.src),
            str(ip_layer.dst),
            int(transport.sport),
            int(transport.dport),
            protocol,
        )

    @staticmethod
    def _flow_key(
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
    ):
        """
        Create a bidirectional flow key.

        Traffic between the same two endpoints belongs to
        the same flow regardless of direction.
        """

        endpoint_a = (
            src_ip,
            src_port,
        )

        endpoint_b = (
            dst_ip,
            dst_port,
        )

        if endpoint_a <= endpoint_b:
            return (
                endpoint_a,
                endpoint_b,
                protocol,
            )

        return (
            endpoint_b,
            endpoint_a,
            protocol,
        )

    @staticmethod
    def _packet_size(packet) -> int:
        """
        Safely determine the packet size.

        Scapy normally supports len(packet). The bytes(packet)
        fallback handles synthetic/minimal packets where the
        normal length calculation may not provide a useful value.
        """

        try:
            size = int(len(packet))

            if size > 0:
                return size

        except Exception:
            pass

        try:
            return len(bytes(packet))
        except Exception:
            return 0

    @staticmethod
    def _packet_time(packet) -> float:
        """Safely retrieve the packet timestamp."""

        try:
            return float(packet.time)
        except Exception:
            return 0.0

    @staticmethod
    def _tcp_flags(packet) -> str:
        """Return TCP flags as a string."""

        from scapy.layers.inet import TCP

        if not packet.haslayer(TCP):
            return ""

        try:
            return str(packet[TCP].flags)
        except Exception:
            return ""

    def build_flows(
        self,
        packets: Iterable,
    ) -> list[NetworkFlow]:
        """
        Build bidirectional flows from packets.

        Only IPv4 TCP and UDP packets are converted into flows.
        """

        flows: dict = {}

        for packet in packets:

            endpoints = self._get_endpoints(packet)

            if endpoints is None:
                continue

            (
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
            ) = endpoints

            key = self._flow_key(
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
            )

            packet_size = self._packet_size(packet)
            packet_time = self._packet_time(packet)

            if key not in flows:

                flows[key] = NetworkFlow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    start_time=packet_time,
                    end_time=packet_time,
                )

            flow = flows[key]

            # -------------------------------------------------
            # General flow statistics
            # -------------------------------------------------

            flow.packet_count += 1
            flow.byte_count += packet_size

            if flow.packet_count == 1:
                flow.start_time = packet_time

            flow.end_time = max(
                flow.end_time,
                packet_time,
            )

            # -------------------------------------------------
            # Directional statistics
            # -------------------------------------------------

            is_forward = (
                src_ip == flow.src_ip
                and dst_ip == flow.dst_ip
                and src_port == flow.src_port
                and dst_port == flow.dst_port
            )

            if is_forward:

                flow.forward_packets += 1
                flow.forward_bytes += packet_size

            else:

                flow.reverse_packets += 1
                flow.reverse_bytes += packet_size

            # -------------------------------------------------
            # TCP statistics
            # -------------------------------------------------

            if protocol == "TCP":

                flags = self._tcp_flags(packet)

                if flags:

                    flow._seen_flags.append(flags)

                    if "S" in flags:
                        flow.tcp_syn_count += 1

                    if "A" in flags:
                        flow.tcp_ack_count += 1

                    if "F" in flags:
                        flow.tcp_fin_count += 1

                    if "R" in flags:
                        flow.tcp_rst_count += 1

        # -----------------------------------------------------
        # Finalize flow objects
        # -----------------------------------------------------

        result: list[NetworkFlow] = []

        for flow in flows.values():

            flow.tcp_flags = "".join(
                flow._seen_flags
            )

            flow._seen_flags.clear()

            result.append(flow)

        return result

    def analyze_flows(
        self,
        packets: Iterable,
    ) -> dict:
        """
        Build flows and return aggregate statistics.
        """

        flows = self.build_flows(packets)

        total_packets = sum(
            flow.packet_count
            for flow in flows
        )

        total_bytes = sum(
            flow.byte_count
            for flow in flows
        )

        protocol_distribution: dict[str, int] = {}

        for flow in flows:

            protocol_distribution[
                flow.protocol
            ] = (
                protocol_distribution.get(
                    flow.protocol,
                    0,
                )
                + 1
            )

        return {
            "flow_count": len(flows),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "protocol_distribution": protocol_distribution,
            "flows": flows,
        }


# Shared FlowBuilder instance
flow_builder = FlowBuilder()