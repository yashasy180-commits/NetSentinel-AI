import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Network,
  Play,
  RefreshCw,
  Square,
  Wifi,
} from "lucide-react";

import axios from "axios";
import useSocket from "../hooks/useSocket";

import { API_BASE } from "../config";

/* =========================================================
   INTERFACE HELPERS
   ========================================================= */

function getInterfaceValue(item) {
  return (
    item.device ||
    item.interface ||
    item.name ||
    item.id ||
    ""
  );
}

function isNpcapPath(value) {
  return (
    typeof value === "string" &&
    value.toLowerCase().startsWith("\\device\\npf_")
  );
}

function getFriendlyInterfaceName(item, index) {
  const candidates = [
    item.description,
    item.friendly_name,
    item.display_name,
    item.adapter_name,
    item.interface_name,
    item.name,
  ];

  for (const candidate of candidates) {
    if (
      typeof candidate === "string" &&
      candidate.trim() &&
      !isNpcapPath(candidate)
    ) {
      return candidate.trim();
    }
  }

  const value = getInterfaceValue(item);

  if (
    typeof value === "string" &&
    value.toLowerCase().includes("loopback")
  ) {
    return "Npcap Loopback";
  }

  if (isNpcapPath(value)) {
    return `Network Adapter ${index + 1}`;
  }

  return value || `Network Interface ${index + 1}`;
}

/* =========================================================
   STAT CARD
   ========================================================= */

function StatCard({
  title,
  value,
  description,
  icon: Icon,
  tone,
}) {
  return (
    <div className="monitor-stat-card">

      <div className={`monitor-stat-icon ${tone}`}>
        <Icon size={19} />
      </div>

      <div>
        <span>{title}</span>

        <strong>
          {value ?? 0}
        </strong>

        <small>
          {description}
        </small>
      </div>

    </div>
  );
}

/* =========================================================
   STATUS ROW
   ========================================================= */

function StatusRow({
  label,
  value,
  active,
  error = false,
}) {
  return (
    <div className="monitor-status-row">

      <span>
        {label}
      </span>

      <strong
        className={
          error
            ? "status-error"
            : ""
        }
      >
        {value}
      </strong>

      <span
        className={`status-indicator ${
          error
            ? "error"
            : active
              ? "active"
              : "idle"
        }`}
      />

    </div>
  );
}

/* =========================================================
   PIPELINE STEP
   ========================================================= */

function PipelineStep({
  number,
  title,
  description,
  active,
}) {
  return (
    <div
      className={`pipeline-step ${
        active ? "active" : ""
      }`}
    >

      <div className="pipeline-number">
        {number}
      </div>

      <div>

        <strong>
          {title}
        </strong>

        <span>
          {description}
        </span>

      </div>

    </div>
  );
}

/* =========================================================
   PIPELINE LINE
   ========================================================= */

function PipelineLine({ active }) {
  return (
    <div
      className={`pipeline-line ${
        active ? "active" : ""
      }`}
    />
  );
}

/* =========================================================
   MAIN COMPONENT
   ========================================================= */

export default function NetworkMonitor() {

  const [interfaces, setInterfaces] =
    useState([]);

  const [selectedInterface, setSelectedInterface] =
    useState("");

  const [selectedInterfaceLabel, setSelectedInterfaceLabel] =
    useState("");

  const [status, setStatus] =
    useState(null);

  const [loading, setLoading] =
    useState(true);

  const [starting, setStarting] =
    useState(false);

  const [stopping, setStopping] =
    useState(false);

  const [error, setError] =
    useState("");

  /* =======================================================
     SOCKET.IO
     ======================================================= */

  const {
    connected: socketConnected,
    trafficEvent,
    threatEvent,
    monitorStatus,
  } = useSocket();

  const token =
    localStorage.getItem(
      "access_token"
    );

  const headers = useMemo(
    () => ({
      Authorization: `Bearer ${token}`,
    }),
    [token]
  );

  /* =======================================================
     LOAD INTERFACES
     ======================================================= */

  async function loadInterfaces() {

    try {

      const response =
        await axios.get(
          `${API_BASE}/traffic/interfaces`,
          {
            headers,
          }
        );

      const data =
        response.data.interfaces || [];

      setInterfaces(data);

      if (
        !selectedInterface &&
        data.length > 0
      ) {

        const preferred =
          data.find((item, index) => {

            const label =
              getFriendlyInterfaceName(
                item,
                index
              ).toLowerCase();

            return (
              label.includes("wi-fi") ||
              label.includes("wifi") ||
              label.includes("wireless") ||
              label.includes("realtek rtl8822")
            );
          }) || data[0];

        const preferredIndex =
          data.indexOf(preferred);

        const value =
          getInterfaceValue(
            preferred
          );

        const label =
          getFriendlyInterfaceName(
            preferred,
            preferredIndex
          );

        setSelectedInterface(value);
        setSelectedInterfaceLabel(label);
      }

    } catch (err) {

      console.error(
        "Interface loading error:",
        err
      );

      setError(
        err.response?.data?.message ||
        "Unable to load network interfaces."
      );
    }
  }

  /* =======================================================
     LOAD STATUS
     ======================================================= */

  async function loadStatus() {

    try {

      const response =
        await axios.get(
          `${API_BASE}/monitoring/status`,
          {
            headers,
          }
        );

      const currentStatus =
        response.data.status ||
        response.data;

      setStatus(currentStatus);

    } catch (err) {

      console.error(
        "Monitoring status error:",
        err
      );

      setError(
        err.response?.data?.message ||
        "Unable to retrieve monitoring status."
      );
    }
  }

  /* =======================================================
     INITIAL DATA
     ======================================================= */

  async function loadData() {

    try {

      setError("");

      await loadInterfaces();
      await loadStatus();

    } finally {

      setLoading(false);
    }
  }

  useEffect(() => {

    loadData();

    const interval =
      setInterval(() => {
        loadStatus();
      }, 3000);

    return () => {
      clearInterval(interval);
    };

  }, []);

  /* =======================================================
     SOCKET MONITOR STATUS
     ======================================================= */

  useEffect(() => {

    if (!monitorStatus?.status) {
      return;
    }

    setStatus(
      monitorStatus.status
    );

  }, [monitorStatus]);

  /* =======================================================
     START MONITORING
     ======================================================= */

  async function handleStart() {

    if (!selectedInterface) {

      setError(
        "Select a network interface before starting."
      );

      return;
    }

    try {

      setStarting(true);
      setError("");

      const response =
        await axios.post(
          `${API_BASE}/monitoring/start`,
          {
            interface:
              selectedInterface,
          },
          {
            headers,
          }
        );

      const currentStatus =
        response.data.status ||
        response.data;

      setStatus(
        currentStatus
      );

      await loadStatus();

    } catch (err) {

      console.error(
        "Monitoring start error:",
        err
      );

      const message =
        err.response?.data?.message ||
        "Unable to start network monitoring.";

      if (
        message
          .toLowerCase()
          .includes("already running")
      ) {

        await loadStatus();

        setError(
          "Monitoring was already running. The console has been synchronized."
        );

      } else {

        setError(message);
      }

    } finally {

      setStarting(false);
    }
  }

  /* =======================================================
     STOP MONITORING
     ======================================================= */

  async function handleStop() {

    try {

      setStopping(true);
      setError("");

      const response =
        await axios.post(
          `${API_BASE}/monitoring/stop`,
          {},
          {
            headers,
          }
        );

      const currentStatus =
        response.data.status;

      if (currentStatus) {
        setStatus(currentStatus);
      }

      await loadStatus();

    } catch (err) {

      console.error(
        "Monitoring stop error:",
        err
      );

      const message =
        err.response?.data?.message ||
        "Unable to stop network monitoring.";

      /*
       * If the backend says it is already stopped,
       * that is effectively the desired state.
       */

      if (
        message
          .toLowerCase()
          .includes("not running")
      ) {

        await loadStatus();

        setError("");

      } else {

        setError(message);
      }

    } finally {

      setStopping(false);
    }
  }

  /* =======================================================
     NORMALIZED STATUS
     ======================================================= */

  const isRunning =
    status?.running ??
    status?.is_running ??
    false;

  const packets =
    status?.packets_processed ??
    status?.packet_count ??
    status?.stats?.packets_processed ??
    0;

  const flows =
    status?.flows_processed ??
    status?.flow_count ??
    status?.stats?.flows_processed ??
    0;

  const threats =
    status?.threats_detected ??
    status?.threat_count ??
    status?.stats?.threats_detected ??
    0;

  const alerts =
    status?.alerts_created ??
    status?.alert_count ??
    status?.stats?.alerts_created ??
    0;

  const lastError =
    status?.last_error ||
    status?.error ||
    null;

  const displayedInterface =
    selectedInterfaceLabel ||
    selectedInterface ||
    "Not selected";

  const hasProcessedTraffic =
    packets > 0 ||
    flows > 0;

  /* =======================================================
     LOADING
     ======================================================= */

  if (loading) {

    return (
      <div className="monitor-page">

        <div className="dashboard-loading">

          Loading network monitoring console

        </div>

      </div>
    );
  }

  /* =======================================================
     PAGE
     ======================================================= */

  return (
    <div className="monitor-page">

      {/* ===================================================
          HEADER
          =================================================== */}

      <div className="page-header">

        <div>

          <div className="eyebrow">

            <span
              className={
                isRunning
                  ? "live-indicator"
                  : "monitor-idle-dot"
              }
            />

            NETWORK OPERATIONS

          </div>

          <h1 className="page-title">
            Network Monitor
          </h1>

          <p className="page-description">
            Capture network traffic, build flows and monitor
            AI-powered intrusion detection in real time.
          </p>

        </div>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
          }}
        >

          <div
            className={`socket-status ${
              socketConnected
                ? "connected"
                : "disconnected"
            }`}
          >

            <span />

            {socketConnected
              ? "LIVE CONNECTION"
              : "RECONNECTING"}

          </div>

          <button
            className="btn btn-secondary"
            onClick={loadData}
            disabled={
              starting ||
              stopping
            }
          >

            <RefreshCw size={15} />

            Refresh

          </button>

        </div>

      </div>

      {/* ===================================================
          ERROR
          =================================================== */}

      {error && (

        <div className="dashboard-error monitor-error">

          <AlertTriangle size={19} />

          <div>

            <strong>
              Monitoring operation
            </strong>

            <p>
              {error}
            </p>

          </div>

          <button
            className="btn btn-secondary"
            onClick={() =>
              setError("")
            }
          >
            Dismiss
          </button>

        </div>

      )}

      {/* ===================================================
          CAPTURE CONTROL
          =================================================== */}

      <section className="monitor-control-grid">

        <div className="panel monitor-control-panel">

          <div className="panel-header">

            <div>

              <h2 className="panel-title">
                Capture Control
              </h2>

              <div className="panel-subtitle">
                Configure the interface used for live traffic
                collection.
              </div>

            </div>

            <div
              className={`monitor-state ${
                isRunning
                  ? "running"
                  : "stopped"
              }`}
            >

              <span />

              {isRunning
                ? "MONITORING ACTIVE"
                : "MONITORING STOPPED"}

            </div>

          </div>

          {/* NETWORK INTERFACE */}

          <div className="monitor-interface-section">

            <label>
              Network Interface
            </label>

            <div className="monitor-select-row">

              <div className="monitor-select">

                <Network size={17} />

                <select
                  value={selectedInterface}
                  onChange={(event) => {

                    const value =
                      event.target.value;

                    setSelectedInterface(
                      value
                    );

                    const index =
                      interfaces.findIndex(
                        (item) =>
                          getInterfaceValue(
                            item
                          ) === value
                      );

                    if (index >= 0) {

                      setSelectedInterfaceLabel(
                        getFriendlyInterfaceName(
                          interfaces[index],
                          index
                        )
                      );

                    } else {

                      setSelectedInterfaceLabel(
                        value
                      );
                    }
                  }}
                  disabled={isRunning}
                >

                  <option value="">
                    Select network interface
                  </option>

                  {interfaces.map(
                    (item, index) => {

                      const value =
                        getInterfaceValue(
                          item
                        );

                      const label =
                        getFriendlyInterfaceName(
                          item,
                          index
                        );

                      return (
                        <option
                          key={`${value}-${index}`}
                          value={value}
                        >
                          {label}
                        </option>
                      );
                    }
                  )}

                </select>

              </div>

              {!isRunning ? (

                <button
                  className="btn btn-primary monitor-action-button"
                  onClick={handleStart}
                  disabled={
                    starting ||
                    !selectedInterface
                  }
                >

                  {starting ? (

                    <RefreshCw
                      size={15}
                      className="spin"
                    />

                  ) : (

                    <Play size={15} />

                  )}

                  {starting
                    ? "Starting..."
                    : "Start Monitoring"}

                </button>

              ) : (

                <button
                  className="btn btn-danger monitor-action-button"
                  onClick={handleStop}
                  disabled={stopping}
                >

                  {stopping ? (

                    <RefreshCw
                      size={15}
                      className="spin"
                    />

                  ) : (

                    <Square size={14} />

                  )}

                  {stopping
                    ? "Stopping..."
                    : "Stop Monitoring"}

                </button>

              )}

            </div>

          </div>

          {/* INTERFACE INFORMATION */}

          <div className="monitor-interface-info">

            <div>

              <span>
                Interface
              </span>

              <strong
                title={displayedInterface}
              >
                {displayedInterface}
              </strong>

            </div>

            <div>

              <span>
                Engine
              </span>

              <strong
                className={
                  isRunning
                    ? "interface-online"
                    : ""
                }
              >
                {isRunning
                  ? "ONLINE"
                  : "STANDBY"}
              </strong>

            </div>

            <div>

              <span>
                Socket
              </span>

              <strong
                className={
                  socketConnected
                    ? "interface-online"
                    : ""
                }
              >
                {socketConnected
                  ? "CONNECTED"
                  : "RECONNECTING"}
              </strong>

            </div>

          </div>

          {/* SECURITY NOTE */}

          <div className="monitor-security-note">

            <div className="monitor-note-icon">
              <CheckCircle2 size={16} />
            </div>

            <div>

              <strong>
                Passive monitoring
              </strong>

              <span>
                NetSentinel observes traffic for detection and
                does not modify network packets.
              </span>

            </div>

          </div>

        </div>

      </section>

      {/* ===================================================
          STATISTICS
          =================================================== */}

      <section className="monitor-stat-grid">

        <StatCard
          title="Packets Processed"
          value={packets.toLocaleString()}
          description="Captured network packets"
          icon={Wifi}
          tone="blue"
        />

        <StatCard
          title="Flows Processed"
          value={flows.toLocaleString()}
          description="Constructed network flows"
          icon={Network}
          tone="cyan"
        />

        <StatCard
          title="Threats Detected"
          value={threats}
          description="AI intrusion detections"
          icon={AlertTriangle}
          tone="red"
        />

        <StatCard
          title="Alerts Created"
          value={alerts}
          description="Security alerts generated"
          icon={CheckCircle2}
          tone="green"
        />

      </section>

      {/* ===================================================
          MAIN GRID
          =================================================== */}

      <section className="monitor-main-grid">

        {/* STATUS PANEL */}

        <div className="panel monitor-status-panel">

          <div className="panel-header">

            <div>

              <h2 className="panel-title">
                Monitoring Status
              </h2>

              <div className="panel-subtitle">
                Current network collection state
              </div>

            </div>

          </div>

          <div className="monitor-status-list">

            <StatusRow
              label="Engine"
              value={
                isRunning
                  ? "ACTIVE"
                  : "STANDBY"
              }
              active={isRunning}
            />

            <StatusRow
              label="Interface"
              value={displayedInterface}
              active={Boolean(
                selectedInterface
              )}
            />

            <StatusRow
              label="Packets"
              value={packets.toLocaleString()}
              active={isRunning}
            />

            <StatusRow
              label="Flows"
              value={flows.toLocaleString()}
              active={isRunning}
            />

            <StatusRow
              label="Socket"
              value={
                socketConnected
                  ? "CONNECTED"
                  : "RECONNECTING"
              }
              active={socketConnected}
              error={!socketConnected}
            />

            <StatusRow
              label="Last error"
              value={
                lastError ||
                "None"
              }
              active={!lastError}
              error={Boolean(lastError)}
            />

          </div>

        </div>

        {/* DETECTION PIPELINE */}

        <div className="panel monitor-engine-panel">

          <div className="panel-header">

            <div>

              <h2 className="panel-title">
                Detection Pipeline
              </h2>

              <div className="panel-subtitle">
                Traffic processing workflow
              </div>

            </div>

          </div>

          <div className="pipeline">

            <PipelineStep
              number="01"
              title="Packet Capture"
              description="Collect traffic"
              active={isRunning}
            />

            <PipelineLine
              active={isRunning}
            />

            <PipelineStep
              number="02"
              title="Flow Builder"
              description="Build network flows"
              active={isRunning}
            />

            <PipelineLine
              active={isRunning}
            />

            <PipelineStep
              number="03"
              title="Feature Engine"
              description="Extract ML features"
              active={isRunning}
            />

            <PipelineLine
              active={isRunning}
            />

            <PipelineStep
              number="04"
              title="AI Detection"
              description="Classify threats"
              active={isRunning}
            />

          </div>

          <div className="monitor-engine-footer">

            <Cpu size={16} />

            <span>
              Random Forest intrusion detection engine
            </span>

            <span className="engine-status">
              READY
            </span>

          </div>

        </div>

      </section>

      {/* ===================================================
          REAL-TIME SECURITY FEED
          =================================================== */}

      <section className="panel monitor-realtime-panel">

        <div className="panel-header">

          <div>

            <h2 className="panel-title">
              Real-Time Security Feed
            </h2>

            <div className="panel-subtitle">
              Live events received from the monitoring engine
            </div>

          </div>

          <div
            className={`socket-status ${
              socketConnected
                ? "connected"
                : "disconnected"
            }`}
          >

            <span />

            {socketConnected
              ? "STREAMING"
              : "OFFLINE"}

          </div>

        </div>

        <div className="monitor-live-feed">

          {/* THREAT EVENT */}

          {threatEvent ? (

            <div className="monitor-threat-event">

              <div className="monitor-threat-icon">

                <AlertTriangle size={18} />

              </div>

              <div className="monitor-threat-content">

                <strong>
                  INTRUSION DETECTED
                </strong>

                <span>
                  A real-time threat event was received
                  from the AI monitoring engine.
                </span>

              </div>

              <div className="monitor-threat-time">
                LIVE
              </div>

            </div>

          ) : trafficEvent ? (

            /* TRAFFIC EVENT */

            <div className="monitor-traffic-event">

              <Activity size={18} />

              <div>

                <strong>
                  Traffic processing window received
                </strong>

                <span>
                  {trafficEvent.packet_count || 0} packets
                  {" · "}
                  {trafficEvent.flow_count || 0} flows
                  {" · "}
                  {trafficEvent.threat_count || 0} threats
                </span>

              </div>

              <span className="monitor-event-live">
                LIVE
              </span>

            </div>

          ) : isRunning && hasProcessedTraffic ? (

            /* ACTIVE MONITORING */

            <div className="monitor-traffic-event">

              <Activity size={18} />

              <div>

                <strong>
                  Network monitoring is active
                </strong>

                <span>
                  {packets.toLocaleString()} packets
                  {" · "}
                  {flows.toLocaleString()} flows
                  {" · "}
                  {threats} threats detected
                </span>

              </div>

              <span className="monitor-event-live">
                ACTIVE
              </span>

            </div>

          ) : isRunning ? (

            /* WAITING */

            <div className="monitor-traffic-event">

              <Activity size={18} />

              <div>

                <strong>
                  Monitoring engine is active
                </strong>

                <span>
                  Waiting for the first processed traffic
                  window.
                </span>

              </div>

              <span className="monitor-event-live">
                ACTIVE
              </span>

            </div>

          ) : (

            /* STOPPED */

            <div className="monitor-empty-feed">

              <Activity size={20} />

              <div>

                <strong>
                  Waiting for network events
                </strong>

                <span>
                  Start monitoring to receive real-time
                  traffic events.
                </span>

              </div>

            </div>

          )}

        </div>

      </section>

    </div>
  );
}

