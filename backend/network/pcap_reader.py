"""
NetSentinel AI
Network Traffic Collection - PCAP Reader

Provides safe reading and inspection of PCAP files.

The reader:
- Validates PCAP paths
- Reads packets using Scapy
- Provides packet metadata
- Supports packet limits
- Handles malformed/unreadable PCAP files safely
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from scapy.all import PcapReader


logger = logging.getLogger(__name__)


class PCAPReader:
    """Read and inspect packets from PCAP files."""

    SUPPORTED_EXTENSIONS = {
        ".pcap",
        ".pcapng",
        ".cap",
    }

    def __init__(self):
        self._packets: list[Any] = []

    # --------------------------------------------------
    # File validation
    # --------------------------------------------------

    @classmethod
    def validate_path(
        cls,
        file_path: str,
    ) -> tuple[bool, Optional[str]]:
        """
        Validate a PCAP file path.

        Returns:
            (True, None) when valid.
            (False, error_message) otherwise.
        """

        if not file_path:
            return False, "PCAP file path is required."

        path = Path(file_path)

        if not path.exists():
            return False, "PCAP file does not exist."

        if not path.is_file():
            return False, "The supplied PCAP path is not a file."

        if path.suffix.lower() not in cls.SUPPORTED_EXTENSIONS:
            return (
                False,
                "Unsupported file type. "
                "Supported formats: .pcap, .pcapng, .cap",
            )

        return True, None

    # --------------------------------------------------
    # Read packets
    # --------------------------------------------------

    def read(
        self,
        file_path: str,
        packet_limit: Optional[int] = None,
    ) -> dict:
        """
        Read packets from a PCAP file.

        Args:
            file_path:
                Path to PCAP/PCAPNG/CAP file.

            packet_limit:
                Optional maximum number of packets to read.

        Returns:
            Dictionary containing read status and packets.
        """

        valid, error = self.validate_path(file_path)

        if not valid:
            return {
                "success": False,
                "file_path": file_path,
                "packet_count": 0,
                "packets": [],
                "error": error,
            }

        if packet_limit is not None and packet_limit <= 0:
            return {
                "success": False,
                "file_path": file_path,
                "packet_count": 0,
                "packets": [],
                "error": "packet_limit must be greater than zero.",
            }

        path = Path(file_path).resolve()

        packets: list[Any] = []

        logger.info(
            "Reading PCAP file: %s",
            path,
        )

        reader = None

        try:
            reader = PcapReader(str(path))

            for packet in reader:

                packets.append(packet)

                if (
                    packet_limit is not None
                    and len(packets) >= packet_limit
                ):
                    break

            self._packets = packets

            logger.info(
                "PCAP read completed | file=%s | packets=%s",
                path,
                len(packets),
            )

            return {
                "success": True,
                "file_path": str(path),
                "packet_count": len(packets),
                "packets": packets,
                "error": None,
            }

        except Exception as exc:
            logger.exception(
                "Unable to read PCAP file: %s",
                path,
            )

            return {
                "success": False,
                "file_path": str(path),
                "packet_count": len(packets),
                "packets": packets,
                "error": str(exc),
            }

        finally:
            if reader is not None:

                try:
                    reader.close()

                except Exception:
                    logger.exception(
                        "Unable to close PCAP reader."
                    )

    # --------------------------------------------------
    # Packet summary
    # --------------------------------------------------

    @staticmethod
    def packet_summary(packet: Any) -> dict:
        """
        Convert a Scapy packet into basic metadata.

        This intentionally extracts only safe observational
        information. It does not modify or transmit packets.
        """

        summary = {
            "length": len(packet),
            "timestamp": getattr(
                packet,
                "time",
                None,
            ),
            "layers": [],
        }

        try:
            current_layer = packet

            while current_layer is not None:

                layer_name = current_layer.__class__.__name__

                summary["layers"].append(
                    layer_name
                )

                current_layer = getattr(
                    current_layer,
                    "payload",
                    None,
                )

                if (
                    current_layer is None
                    or current_layer.__class__.__name__ == "NoPayload"
                ):
                    break

        except Exception:
            logger.exception(
                "Unable to extract packet layer summary."
            )

        return summary

    # --------------------------------------------------
    # Packet summaries
    # --------------------------------------------------

    def get_summaries(
        self,
        packets: Optional[list[Any]] = None,
    ) -> list[dict]:
        """
        Generate metadata summaries for packets.
        """

        if packets is None:
            packets = self._packets

        return [
            self.packet_summary(packet)
            for packet in packets
        ]

    # --------------------------------------------------
    # Last loaded packets
    # --------------------------------------------------

    @property
    def packets(self) -> list[Any]:
        """Return the most recently loaded packets."""

        return list(self._packets)


# ------------------------------------------------------
# Module-level service instance
# ------------------------------------------------------

pcap_reader = PCAPReader()