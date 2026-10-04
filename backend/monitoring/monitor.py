"""
NetSentinel AI
Module 5 - Real-Time Network Monitoring

Provides safe background packet monitoring.

The monitor:
- Captures observed network packets
- Groups packets into processing windows
- Builds network flows
- Runs AI detection
- Creates security alerts for detected intrusions
- Emits monitoring events through Socket.IO
- Supports clean start/stop
- Does NOT inject, modify, or block traffic
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from scapy.all import AsyncSniffer

from extensions.socket import socketio

from monitoring.event_processor import (
    event_processor,
)

from monitoring.monitor_config import (
    MAX_PACKETS_PER_WINDOW,
    WINDOW_SECONDS,
    TRAFFIC_EVENT,
    THREAT_EVENT,
    MONITOR_STATUS_EVENT,
)

from services.alert_service import (
    alert_service,
)


logger = logging.getLogger(__name__)


class NetworkMonitor:
    """Background network monitoring engine."""

    def __init__(
        self,
        window_seconds: int = WINDOW_SECONDS,
        max_packets: int = MAX_PACKETS_PER_WINDOW,
    ) -> None:

        self.window_seconds = max(
            1,
            int(window_seconds),
        )

        self.max_packets = max(
            1,
            int(max_packets),
        )

        self.sniffer: AsyncSniffer | None = None

        self.interface: str | None = None

        self._running = False

        self._lock = threading.Lock()

        self._worker_thread: threading.Thread | None = None

        self._packet_buffer: list[Any] = []

        self._last_error: str | None = None

        self._started_at: float | None = None

        self._packets_processed = 0

        self._flows_processed = 0

        self._threats_detected = 0

        self._alerts_created = 0

    # =========================================================
    # Status
    # =========================================================

    @property
    def is_running(self) -> bool:
        """Return whether monitoring is active."""

        return self._running

    def get_status(self) -> dict:
        """Return current monitoring status."""

        return {
            "running": self._running,
            "interface": self.interface,
            "window_seconds": self.window_seconds,
            "max_packets_per_window": self.max_packets,
            "started_at": self._started_at,
            "packets_processed": (
                self._packets_processed
            ),
            "flows_processed": (
                self._flows_processed
            ),
            "threats_detected": (
                self._threats_detected
            ),
            "alerts_created": (
                self._alerts_created
            ),
            "last_error": self._last_error,
        }

    # =========================================================
    # Start
    # =========================================================

    def start(
        self,
        interface: str | None = None,
        packet_filter: str | None = None,
    ) -> dict:
        """
        Start background packet monitoring.

        Monitoring is observational only.
        """

        with self._lock:

            if self._running:

                return {
                    "success": False,
                    "message": (
                        "Network monitoring "
                        "is already running."
                    ),
                    "status": self.get_status(),
                }

            self.interface = interface

            self._packet_buffer = []

            self._last_error = None

            self._packets_processed = 0

            self._flows_processed = 0

            self._threats_detected = 0

            self._alerts_created = 0

            self._started_at = time.time()

            self._running = True

            try:

                self.sniffer = AsyncSniffer(
                    iface=self.interface,
                    filter=packet_filter,
                    prn=self._packet_callback,
                    store=False,
                )

                self.sniffer.start()

                self._worker_thread = (
                    threading.Thread(
                        target=self._processing_loop,
                        name="NetSentinel-Monitor",
                        daemon=True,
                    )
                )

                self._worker_thread.start()

                self._emit_status()

                logger.info(
                    "Network monitoring started. "
                    "interface=%s",
                    self.interface,
                )

                return {
                    "success": True,
                    "message": (
                        "Network monitoring "
                        "started."
                    ),
                    "status": self.get_status(),
                }

            except Exception as exc:

                self._running = False

                self._last_error = str(
                    exc
                )

                self.sniffer = None

                logger.exception(
                    "Unable to start network monitoring."
                )

                return {
                    "success": False,
                    "message": (
                        "Unable to start "
                        "network monitoring."
                    ),
                    "error": str(exc),
                }

    # =========================================================
    # Stop
    # =========================================================

    def stop(self) -> dict:
        """Stop network monitoring safely."""

        with self._lock:

            if not self._running:

                return {
                    "success": False,
                    "message": (
                        "Network monitoring "
                        "is not running."
                    ),
                    "status": self.get_status(),
                }

            self._running = False

            sniffer = self.sniffer

            self.sniffer = None

        try:

            if sniffer is not None:

                sniffer.stop()

        except Exception:

            logger.exception(
                "Error while stopping packet sniffer."
            )

        # Process remaining packets.
        try:

            self._process_current_buffer()

        except Exception:

            logger.exception(
                "Error processing final "
                "monitoring buffer."
            )

        self._emit_status()

        logger.info(
            "Network monitoring stopped."
        )

        return {
            "success": True,
            "message": (
                "Network monitoring stopped."
            ),
            "status": self.get_status(),
        }

    # =========================================================
    # Packet Callback
    # =========================================================

    def _packet_callback(
        self,
        packet,
    ) -> None:
        """Receive an observed packet."""

        if not self._running:
            return

        with self._lock:

            if (
                len(self._packet_buffer)
                < self.max_packets
            ):

                self._packet_buffer.append(
                    packet
                )

    # =========================================================
    # Processing Loop
    # =========================================================

    def _processing_loop(self) -> None:
        """Process packet windows in the background."""

        logger.info(
            "Monitoring processing loop started."
        )

        while self._running:

            time.sleep(
                self.window_seconds
            )

            if not self._running:
                break

            try:

                self._process_current_buffer()

            except Exception as exc:

                self._last_error = str(
                    exc
                )

                logger.exception(
                    "Monitoring processing "
                    "window failed."
                )

                self._emit_status()

        logger.info(
            "Monitoring processing loop stopped."
        )

    # =========================================================
    # Process Buffer
    # =========================================================

    def _process_current_buffer(self) -> None:
        """Process the current packet window."""

        with self._lock:

            packets = list(
                self._packet_buffer
            )

            self._packet_buffer.clear()

        if not packets:

            return

        result = (
            event_processor.process_packets(
                packets
            )
        )

        self._packets_processed += int(
            result.get(
                "packet_count",
                0,
            )
        )

        self._flows_processed += int(
            result.get(
                "flow_count",
                0,
            )
        )

        self._threats_detected += int(
            result.get(
                "threat_count",
                0,
            )
        )

        # -----------------------------------------------------
        # Emit traffic event
        # -----------------------------------------------------

        traffic_payload = {
            "event": TRAFFIC_EVENT,
            "timestamp": time.time(),
            "packet_count": result.get(
                "packet_count",
                0,
            ),
            "flow_count": result.get(
                "flow_count",
                0,
            ),
            "threat_count": result.get(
                "threat_count",
                0,
            ),
            "summary": result.get(
                "summary",
                {},
            ),
        }

        socketio.emit(
            TRAFFIC_EVENT,
            traffic_payload,
        )

        # -----------------------------------------------------
        # Process threat detections
        # -----------------------------------------------------

        detections = result.get(
            "detections",
            [],
        )

        flows = result.get(
            "flows",
            [],
        )

        for index, detection in enumerate(
            detections
        ):

            if (
                detection.get(
                    "prediction"
                )
                != "INTRUSION"
            ):
                continue

            # -------------------------------------------------
            # Match detection to original flow
            # -------------------------------------------------

            flow = (
                flows[index]
                if index < len(flows)
                else None
            )

            source_ip = None
            destination_ip = None

            if flow is not None:

                source_ip = getattr(
                    flow,
                    "src_ip",
                    None,
                )

                destination_ip = getattr(
                    flow,
                    "dst_ip",
                    None,
                )

            # -------------------------------------------------
            # Create persistent security alert
            # -------------------------------------------------

            try:

                alert = (
                    alert_service.create_alert(
                        detection=detection,
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                    )
                )

                if alert is not None:

                    self._alerts_created += 1

                    logger.warning(
                        "Security alert created. "
                        "alert_id=%s severity=%s "
                        "source=%s destination=%s",
                        alert.id,
                        alert.severity,
                        alert.source_ip,
                        alert.destination_ip,
                    )

            except Exception:

                # Alert persistence must never
                # terminate network monitoring.
                logger.exception(
                    "Failed to create security "
                    "alert from AI detection."
                )

            # -------------------------------------------------
            # Emit real-time threat event
            # -------------------------------------------------

            threat_payload = {
                "event": THREAT_EVENT,
                "timestamp": time.time(),
                "detection": detection,
                "flow": {
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "source_port": (
                        getattr(
                            flow,
                            "src_port",
                            None,
                        )
                        if flow is not None
                        else None
                    ),
                    "destination_port": (
                        getattr(
                            flow,
                            "dst_port",
                            None,
                        )
                        if flow is not None
                        else None
                    ),
                    "protocol": (
                        getattr(
                            flow,
                            "protocol",
                            None,
                        )
                        if flow is not None
                        else None
                    ),
                },
            }

            socketio.emit(
                THREAT_EVENT,
                threat_payload,
            )

        self._emit_status()

    # =========================================================
    # Socket Status
    # =========================================================

    def _emit_status(self) -> None:
        """Emit current monitoring status."""

        socketio.emit(
            MONITOR_STATUS_EVENT,
            {
                "event": MONITOR_STATUS_EVENT,
                "timestamp": time.time(),
                "status": self.get_status(),
            },
        )


# Shared monitor instance.
network_monitor = NetworkMonitor()