"""
NetSentinel AI
Network Traffic Collection - Packet Capture

Provides safe network packet capture using Scapy.

The capture service:
- Discovers available interfaces
- Maps Npcap devices to Windows adapter names
- Captures packets for a controlled duration
- Supports packet count limits
- Can save captures to PCAP
- Provides safe error handling
- Does not generate or send attack traffic
"""

from __future__ import annotations

import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from scapy.all import (
    AsyncSniffer,
    get_if_list,
    wrpcap,
)


logger = logging.getLogger(__name__)


@dataclass
class CaptureResult:
    """Represents the result of a packet capture session."""

    success: bool
    packet_count: int = 0
    duration_seconds: float = 0.0
    interface: Optional[str] = None
    pcap_path: Optional[str] = None
    error: Optional[str] = None
    packets: list[Any] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Return a JSON-friendly representation."""

        return {
            "success": self.success,
            "packet_count": self.packet_count,
            "duration_seconds": round(
                self.duration_seconds,
                3,
            ),
            "interface": self.interface,
            "pcap_path": self.pcap_path,
            "error": self.error,
        }


class PacketCapture:
    """
    Controlled network packet capture service.

    This class only observes network traffic. It does not
    generate, inject, modify, or transmit packets.
    """

    def __init__(self):
        self._sniffer: Optional[AsyncSniffer] = None
        self._lock = threading.Lock()
        self._capturing = False
        self._packets: list[Any] = []
        self._started_at: Optional[float] = None

    # --------------------------------------------------
    # Windows adapter discovery
    # --------------------------------------------------

    @staticmethod
    def _get_windows_adapters() -> dict[str, dict]:
        """
        Read Windows network adapter information.

        Returns a dictionary keyed by normalized interface GUID.

        Example:

        {
            "732f42de-f091-44ae-8f76-f9ae05a03199": {
                "name": "Wi-Fi",
                "description": "Realtek RTL8822CE 802.11ac PCIe Adapter",
                "status": "Up",
                "mac": "AA-BB-CC-DD-EE-FF"
            }
        }
        """

        adapters: dict[str, dict] = {}

        powershell_command = """
Get-NetAdapter |
    Select-Object Name, InterfaceDescription, InterfaceGuid, Status, MacAddress, LinkSpeed |
    ConvertTo-Json -Compress
"""

        try:
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    powershell_command,
                ],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW
                    if hasattr(
                        subprocess,
                        "CREATE_NO_WINDOW",
                    )
                    else 0
                ),
            )

            if result.returncode != 0:
                logger.warning(
                    "Windows adapter discovery failed: %s",
                    result.stderr.strip(),
                )
                return adapters

            output = result.stdout.strip()

            if not output:
                return adapters

            import json

            data = json.loads(output)

            if isinstance(data, dict):
                data = [data]

            if not isinstance(data, list):
                return adapters

            for adapter in data:

                if not isinstance(adapter, dict):
                    continue

                guid = str(
                    adapter.get(
                        "InterfaceGuid",
                        "",
                    )
                ).strip()

                if not guid:
                    continue

                # Remove Windows { } around GUID.
                normalized_guid = (
                    guid
                    .strip("{}")
                    .lower()
                )

                adapters[normalized_guid] = {
                    "name": str(
                        adapter.get(
                            "Name",
                            "",
                        )
                        or ""
                    ).strip(),

                    "description": str(
                        adapter.get(
                            "InterfaceDescription",
                            "",
                        )
                        or ""
                    ).strip(),

                    "status": str(
                        adapter.get(
                            "Status",
                            "",
                        )
                        or ""
                    ).strip(),

                    "mac": str(
                        adapter.get(
                            "MacAddress",
                            "",
                        )
                        or ""
                    ).strip(),

                    "link_speed": str(
                        adapter.get(
                            "LinkSpeed",
                            "",
                        )
                        or ""
                    ).strip(),
                }

            logger.info(
                "Windows network adapters discovered: %s",
                len(adapters),
            )

        except subprocess.TimeoutExpired:
            logger.warning(
                "Windows adapter discovery timed out."
            )

        except Exception:
            logger.exception(
                "Unable to discover Windows network adapters."
            )

        return adapters

    @staticmethod
    def _extract_npcap_guid(
        device: str,
    ) -> Optional[str]:
        """
        Extract a Windows adapter GUID from an Npcap device.

        Example:

        \\Device\\NPF_{732F42DE-F091-44AE-8F76-F9AE05A03199}

        becomes:

        732f42de-f091-44ae-8f76-f9ae05a03199
        """

        if not device:
            return None

        match = re.search(
            r"NPF_\{?([0-9A-Fa-f-]{36})\}?",
            device,
        )

        if not match:
            return None

        return match.group(1).lower()

    # --------------------------------------------------
    # Interface classification
    # --------------------------------------------------

    @staticmethod
    def _classify_interface(
        name: str,
        description: str,
        device: str,
    ) -> str:
        """
        Classify a network interface for UI display.
        """

        text = " ".join(
            [
                name or "",
                description or "",
                device or "",
            ]
        ).lower()

        if (
            "wi-fi" in text
            or "wifi" in text
            or "wireless" in text
            or "802.11" in text
            or "wlan" in text
        ):
            return "Wi-Fi"

        if (
            name.lower() == "ethernet"
            or "ethernet" in text
            or "gigabit" in text
            or "realtek pcie gbe" in text
        ):
            return "Ethernet"

        if (
            "loopback" in text
            or "npcap_loopback" in text
        ):
            return "Loopback"

        if (
            "virtual" in text
            or "vmware" in text
            or "virtualbox" in text
            or "hyper-v" in text
            or "wsl" in text
            or "vpn" in text
            or "tunnel" in text
        ):
            return "Virtual"

        return "Other"

    # --------------------------------------------------
    # Interface discovery
    # --------------------------------------------------

    @staticmethod
    def list_interfaces() -> list[dict]:
        """
        Return available network interfaces.

        The returned object contains both:

        - name  -> friendly Windows adapter name
        - device -> actual Npcap device used by Scapy

        This separation is important because the frontend
        should display "Wi-Fi" while the capture engine must
        receive the real Npcap device path.
        """

        try:
            raw_interfaces = get_if_list()

            windows_adapters = (
                PacketCapture
                ._get_windows_adapters()
            )

            results: list[dict] = []

            for device in raw_interfaces:

                if not device:
                    continue

                guid = (
                    PacketCapture
                    ._extract_npcap_guid(device)
                )

                adapter = (
                    windows_adapters.get(guid, {})
                    if guid
                    else {}
                )

                adapter_name = str(
                    adapter.get(
                        "name",
                        "",
                    )
                    or ""
                ).strip()

                description = str(
                    adapter.get(
                        "description",
                        "",
                    )
                    or ""
                ).strip()

                status = str(
                    adapter.get(
                        "status",
                        "",
                    )
                    or ""
                ).strip()

                mac = str(
                    adapter.get(
                        "mac",
                        "",
                    )
                    or ""
                ).strip()

                link_speed = str(
                    adapter.get(
                        "link_speed",
                        "",
                    )
                    or ""
                ).strip()

                interface_type = (
                    PacketCapture
                    ._classify_interface(
                        adapter_name,
                        description,
                        device,
                    )
                )

                # Prefer the actual Windows adapter name.
                # If Windows cannot resolve it, keep the
                # Npcap device as a fallback.
                friendly_name = (
                    adapter_name
                    or description
                    or device
                )

                # Special case for Npcap loopback.
                if device.lower().endswith(
                    "npf_loopback"
                ):
                    friendly_name = "Npcap Loopback"
                    interface_type = "Loopback"

                results.append(
                    {
                        "name": friendly_name,
                        "device": device,
                        "description": description,
                        "ipv4": "",
                        "mac": mac,
                        "type": interface_type,
                        "status": status,
                        "link_speed": link_speed,
                        "guid": guid,
                    }
                )

            logger.info(
                "Network interfaces discovered: %s",
                len(results),
            )

            return results

        except Exception:
            logger.exception(
                "Unable to discover network interfaces."
            )
            return []

    # --------------------------------------------------
    # Capture state
    # --------------------------------------------------

    @property
    def is_capturing(self) -> bool:
        """Return whether a capture is currently active."""

        with self._lock:
            return self._capturing

    # --------------------------------------------------
    # Packet callback
    # --------------------------------------------------

    def _packet_callback(
        self,
        packet: Any,
    ) -> None:
        """Store a captured packet."""

        with self._lock:
            self._packets.append(packet)

    # --------------------------------------------------
    # Start capture
    # --------------------------------------------------

    def start_capture(
        self,
        interface: Optional[str] = None,
        duration: int = 10,
        packet_count: Optional[int] = None,
        packet_filter: Optional[str] = None,
    ) -> CaptureResult:
        """
        Capture network packets.

        Args:
            interface:
                Npcap device path. If omitted, Scapy's
                default interface is used.

            duration:
                Maximum capture duration in seconds.

            packet_count:
                Optional maximum number of packets.

            packet_filter:
                Optional BPF filter such as:
                "tcp"
                "udp"
                "port 80"

        Returns:
            CaptureResult
        """

        if self.is_capturing:
            return CaptureResult(
                success=False,
                interface=interface,
                error=(
                    "A packet capture is already running."
                ),
            )

        if duration <= 0:
            return CaptureResult(
                success=False,
                interface=interface,
                error=(
                    "Capture duration must be greater "
                    "than zero."
                ),
            )

        if (
            packet_count is not None
            and packet_count <= 0
        ):
            return CaptureResult(
                success=False,
                interface=interface,
                error=(
                    "Packet count must be greater "
                    "than zero."
                ),
            )

        with self._lock:
            self._packets = []
            self._capturing = True
            self._started_at = time.monotonic()

        logger.info(
            "Starting packet capture | interface=%s | "
            "duration=%s | packet_count=%s | filter=%s",
            interface,
            duration,
            packet_count,
            packet_filter,
        )

        try:
            self._sniffer = AsyncSniffer(
                iface=interface,
                filter=packet_filter,
                prn=self._packet_callback,
                store=False,
                count=packet_count or 0,
            )

            self._sniffer.start()

            deadline = (
                time.monotonic()
                + duration
            )

            while time.monotonic() < deadline:

                if not self.is_capturing:
                    break

                if (
                    packet_count is not None
                    and len(self._packets)
                    >= packet_count
                ):
                    break

                time.sleep(0.05)

            self.stop_capture()

            elapsed = (
                time.monotonic()
                - self._started_at
                if self._started_at is not None
                else 0
            )

            with self._lock:
                packets = list(
                    self._packets
                )

            logger.info(
                "Packet capture completed | "
                "packets=%s | duration=%.3f",
                len(packets),
                elapsed,
            )

            return CaptureResult(
                success=True,
                packet_count=len(packets),
                duration_seconds=elapsed,
                interface=interface,
                packets=packets,
            )

        except PermissionError:
            self.stop_capture()

            return CaptureResult(
                success=False,
                interface=interface,
                error=(
                    "Permission denied while starting "
                    "packet capture. Run the terminal "
                    "with appropriate Windows permissions "
                    "or use safe sample traffic mode."
                ),
            )

        except Exception as exc:
            logger.exception(
                "Packet capture failed."
            )

            self.stop_capture()

            return CaptureResult(
                success=False,
                interface=interface,
                error=str(exc),
            )

    # --------------------------------------------------
    # Stop capture
    # --------------------------------------------------

    def stop_capture(self) -> None:
        """Stop an active packet capture."""

        with self._lock:
            sniffer = self._sniffer
            self._capturing = False
            self._sniffer = None

        if sniffer is not None:

            try:
                if sniffer.running:
                    sniffer.stop()

            except Exception:
                logger.exception(
                    "Error while stopping packet capture."
                )

        logger.info(
            "Packet capture stopped."
        )

    # --------------------------------------------------
    # Save PCAP
    # --------------------------------------------------

    def save_pcap(
        self,
        packets: Optional[list[Any]] = None,
        output_path: Optional[str] = None,
    ) -> Optional[str]:
        """
        Save captured packets to a PCAP file.

        Args:
            packets:
                Packet list. If omitted, the most recent
                capture is used.

            output_path:
                Destination PCAP path.

        Returns:
            Absolute PCAP path or None on failure.
        """

        if packets is None:
            with self._lock:
                packets = list(
                    self._packets
                )

        if not packets:
            logger.warning(
                "No packets available to save."
            )
            return None

        if not output_path:
            timestamp = time.strftime(
                "%Y%m%d_%H%M%S"
            )

            output_path = (
                Path("captures")
                / f"capture_{timestamp}.pcap"
            )

        destination = Path(
            output_path
        ).resolve()

        try:
            destination.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            wrpcap(
                str(destination),
                packets,
            )

            logger.info(
                "PCAP saved successfully: %s",
                destination,
            )

            return str(destination)

        except Exception:
            logger.exception(
                "Unable to save PCAP file."
            )
            return None


# ------------------------------------------------------
# Module-level service instance
# ------------------------------------------------------

packet_capture = PacketCapture()