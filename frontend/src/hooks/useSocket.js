import { useEffect, useRef, useState } from "react";
import {
  connectSocket,
  disconnectSocket,
} from "../services/socket";

export default function useSocket() {
  const socketRef = useRef(null);

  const [connected, setConnected] = useState(false);
  const [trafficEvent, setTrafficEvent] = useState(null);
  const [threatEvent, setThreatEvent] = useState(null);
  const [monitorStatus, setMonitorStatus] = useState(null);
  const [lastEvent, setLastEvent] = useState(null);

  useEffect(() => {
    const socket = connectSocket();

    socketRef.current = socket;

    const handleConnect = () => {
      console.log("[NetSentinel Socket] CONNECTED");
      setConnected(true);
    };

    const handleDisconnect = (reason) => {
      console.log(
        "[NetSentinel Socket] DISCONNECTED:",
        reason
      );

      setConnected(false);
    };

    const handleTraffic = (data) => {
      console.log(
        "[NetSentinel Socket] TRAFFIC EVENT:",
        data
      );

      setTrafficEvent(data);

      setLastEvent({
        type: "traffic",
        timestamp: Date.now(),
        data,
      });
    };

    const handleThreat = (data) => {
      console.log(
        "[NetSentinel Socket] THREAT EVENT:",
        data
      );

      setThreatEvent(data);

      setLastEvent({
        type: "threat",
        timestamp: Date.now(),
        data,
      });
    };

    const handleMonitorStatus = (data) => {
      console.log(
        "[NetSentinel Socket] MONITOR STATUS:",
        data
      );

      setMonitorStatus(data);

      setLastEvent({
        type: "status",
        timestamp: Date.now(),
        data,
      });
    };

    socket.on("connect", handleConnect);

    socket.on(
      "disconnect",
      handleDisconnect
    );

    socket.on(
      "traffic_event",
      handleTraffic
    );

    socket.on(
      "threat_event",
      handleThreat
    );

    socket.on(
      "monitor_status",
      handleMonitorStatus
    );

    /*
     * Diagnostic listener.
     *
     * This lets us see if the backend is sending an
     * event with a different name than expected.
     */

    const handleAnyEvent = (
      eventName,
      ...args
    ) => {
      console.log(
        "[NetSentinel Socket] EVENT:",
        eventName,
        args
      );
    };

    socket.onAny(handleAnyEvent);

    setConnected(socket.connected);

    return () => {
      socket.off(
        "connect",
        handleConnect
      );

      socket.off(
        "disconnect",
        handleDisconnect
      );

      socket.off(
        "traffic_event",
        handleTraffic
      );

      socket.off(
        "threat_event",
        handleThreat
      );

      socket.off(
        "monitor_status",
        handleMonitorStatus
      );

      socket.offAny(handleAnyEvent);

      disconnectSocket();
    };
  }, []);

  return {
    socket: socketRef.current,
    connected,
    trafficEvent,
    threatEvent,
    monitorStatus,
    lastEvent,
  };
}
