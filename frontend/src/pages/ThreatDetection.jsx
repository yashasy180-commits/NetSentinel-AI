import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  Clock3,
  RefreshCw,
  ShieldAlert,
  Target,
  Zap,
} from "lucide-react";
import axios from "axios";

import { API_BASE } from "../config";

/* =========================================================
   HELPERS
   ========================================================= */

function formatNumber(value) {
  return new Intl.NumberFormat("en-US").format(
    Number(value) || 0
  );
}

function formatDateTime(value) {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString([], {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function getSeverityClass(severity) {
  return (
    severity?.toLowerCase() || "low"
  );
}

/* =========================================================
   STAT CARD
   ========================================================= */

function DetectionStat({
  icon: Icon,
  label,
  value,
  description,
  tone,
}) {
  return (
    <div className="detection-stat-card">

      <div
        className={`detection-stat-icon ${tone}`}
      >
        <Icon size={19} />
      </div>

      <div className="detection-stat-content">

        <span>
          {label}
        </span>

        <strong>
          {formatNumber(value)}
        </strong>

        <small>
          {description}
        </small>

      </div>

    </div>
  );
}

/* =========================================================
   THREAT DETECTION PAGE
   ========================================================= */

export default function ThreatDetection() {

  const [alerts, setAlerts] =
    useState([]);

  const [statistics, setStatistics] =
    useState(null);

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] =
    useState("");

  const [filter, setFilter] =
    useState("ALL");

  const [simulationLoading, setSimulationLoading] =
    useState(false);

  const [simulationResult, setSimulationResult] =
    useState(null);

  const [simulationError, setSimulationError] =
    useState("");

  const token =
    localStorage.getItem(
      "access_token"
    );

  /* =======================================================
     AUTH HEADERS
     ======================================================= */

  const headers = useMemo(
    () => ({
      Authorization: `Bearer ${token}`,
    }),
    [token]
  );

  /* =======================================================
     LOAD DETECTION DATA
     ======================================================= */

  async function loadDetectionData(
    showRefresh = false
  ) {

    try {

      if (showRefresh) {
        setRefreshing(true);
      }

      setError("");

      const [
        alertsResponse,
        statisticsResponse,
      ] = await Promise.all([
        axios.get(
          `${API_BASE}/alerts?limit=50`,
          {
            headers,
          }
        ),

        axios.get(
          `${API_BASE}/alerts/statistics`,
          {
            headers,
          }
        ),
      ]);

      setAlerts(
        alertsResponse.data.alerts || []
      );

      setStatistics(
        statisticsResponse.data
      );

    } catch (err) {

      console.error(
        "Threat detection loading error:",
        err
      );

      setError(
        err.response?.data?.message ||
        "Unable to load threat detection data."
      );

    } finally {

      setLoading(false);
      setRefreshing(false);
    }
  }

  /* =======================================================
     SAFE SYNTHETIC INTRUSION SIMULATION
     ======================================================= */

  async function runSafeIntrusionSimulation() {

    try {

      setSimulationLoading(true);
      setSimulationError("");
      setSimulationResult(null);

      const response = await axios.post(
        `${API_BASE}/traffic/simulate-intrusion`,
        {},
        {
          headers,
        }
      );

      setSimulationResult(
        response.data?.detection || null
      );

    } catch (err) {

      console.error(
        "Safe intrusion simulation error:",
        err
      );

      setSimulationError(
        err.response?.data?.message ||
        "Unable to run the safe intrusion simulation."
      );

    } finally {

      setSimulationLoading(false);
    }
  }

  /* =======================================================
     INITIAL LOAD + AUTO REFRESH
     ======================================================= */

  useEffect(() => {

    loadDetectionData();

    const interval =
      setInterval(() => {
        loadDetectionData();
      }, 15000);

    return () =>
      clearInterval(interval);

  }, []);

  /* =======================================================
     FILTERED ALERTS
     ======================================================= */

  const filteredAlerts =
    filter === "ALL"
      ? alerts
      : alerts.filter(
          (alert) =>
            alert.severity?.toUpperCase() ===
            filter
        );

  /* =======================================================
     STATISTICS
     ======================================================= */

  const totalAlerts =
    statistics?.total ??
    statistics?.total_alerts ??
    alerts.length ??
    0;

  const openAlerts =
    statistics?.open ??
    statistics?.open_alerts ??
    alerts.filter(
      (alert) =>
        alert.status?.toUpperCase() ===
        "OPEN"
    ).length;

  const resolvedAlerts =
    statistics?.resolved ??
    statistics?.resolved_alerts ??
    alerts.filter(
      (alert) =>
        alert.status?.toUpperCase() ===
        "RESOLVED"
    ).length;

  const criticalAlerts =
    statistics?.critical ??
    statistics?.severity?.critical ??
    alerts.filter(
      (alert) =>
        alert.severity?.toUpperCase() ===
        "CRITICAL"
    ).length;

  /* =======================================================
     LOADING
     ======================================================= */

  if (loading) {

    return (
      <div className="threat-detection-page">

        <div className="dashboard-loading">

          Loading AI threat detection console

        </div>

      </div>
    );
  }

  /* =======================================================
     PAGE
     ======================================================= */

  return (
    <div className="threat-detection-page">

      {/* =================================================
          HEADER
          ================================================= */}

      <div className="page-header">

        <div>

          <div className="eyebrow">

            <span className="live-indicator" />

            AI SECURITY ENGINE

          </div>

          <h1 className="page-title">
            Threat Detection
          </h1>

          <p className="page-description">
            Review AI-powered intrusion detections,
            threat classifications and detection confidence.
          </p>

        </div>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
          }}
        >

          <div className="detection-engine-status">

            <span />

            AI ENGINE READY

          </div>

          <button
            className="btn btn-secondary"
            onClick={runSafeIntrusionSimulation}
            disabled={simulationLoading}
          >

            <ShieldAlert
              size={15}
            />

            {simulationLoading
              ? "Running Test"
              : "Safe Intrusion Test"}

          </button>

          <button
            className="btn btn-secondary"
            onClick={() =>
              loadDetectionData(true)
            }
            disabled={refreshing}
          >

            <RefreshCw
              size={15}
              className={
                refreshing
                  ? "dashboard-spin"
                  : ""
              }
            />

            {refreshing
              ? "Refreshing"
              : "Refresh"}

          </button>

        </div>

      </div>

      {/* =================================================
          ERROR
          ================================================= */}

      {error && (

        <div className="dashboard-error">

          <AlertTriangle size={19} />

          <div>

            <strong>
              Detection data unavailable
            </strong>

            <p>
              {error}
            </p>

          </div>

          <button
            className="btn btn-secondary"
            onClick={() =>
              loadDetectionData(true)
            }
          >
            Retry
          </button>

        </div>

      )}

      {/* =================================================
          SAFE SIMULATION RESULT
          ================================================= */}

      {(simulationResult || simulationError) && (

        <section className="panel detection-simulation-panel">

          <div className="panel-header">

            <div>

              <div className="dashboard-section-kicker">
                SAFE ML VALIDATION
              </div>

              <h2 className="panel-title">
                Synthetic Intrusion Simulation
              </h2>

              <div className="panel-subtitle">
                In-memory validation only — no packets are transmitted.
              </div>

            </div>

            {simulationResult && (
              <div className="detection-live-badge">
                <span />
                TEST COMPLETE
              </div>
            )}

          </div>

          {simulationError ? (

            <div className="dashboard-error">
              <AlertTriangle size={19} />
              <div>
                <strong>Simulation failed</strong>
                <p>{simulationError}</p>
              </div>
            </div>

          ) : simulationResult ? (

            <div
              style={{
                display: "grid",
                gridTemplateColumns:
                  "repeat(auto-fit, minmax(160px, 1fr))",
                gap: "12px",
              }}
            >

              <div className="detection-stat-card">
                <div className="detection-stat-icon blue">
                  <BrainCircuit size={19} />
                </div>
                <div className="detection-stat-content">
                  <span>PREDICTION</span>
                  <strong>
                    {simulationResult.prediction || "—"}
                  </strong>
                  <small>Model classification</small>
                </div>
              </div>

              <div className="detection-stat-card">
                <div className="detection-stat-icon orange">
                  <Target size={19} />
                </div>
                <div className="detection-stat-content">
                  <span>PROBABILITY</span>
                  <strong>
                    {simulationResult.probability != null
                      ? `${Math.round(
                          Number(simulationResult.probability) * 100
                        )}%`
                      : "—"}
                  </strong>
                  <small>Intrusion probability</small>
                </div>
              </div>

              <div className="detection-stat-card">
                <div className="detection-stat-icon green">
                  <CheckCircle2 size={19} />
                </div>
                <div className="detection-stat-content">
                  <span>CONFIDENCE</span>
                  <strong>
                    {simulationResult.confidence != null
                      ? `${Math.round(
                          Number(simulationResult.confidence) * 100
                        )}%`
                      : "—"}
                  </strong>
                  <small>Classification confidence</small>
                </div>
              </div>

              <div className="detection-stat-card">
                <div className="detection-stat-icon red">
                  <AlertTriangle size={19} />
                </div>
                <div className="detection-stat-content">
                  <span>RISK LEVEL</span>
                  <strong>
                    {simulationResult.risk_level || "—"}
                  </strong>
                  <small>Calculated by detector</small>
                </div>
              </div>

            </div>

          ) : null}

        </section>

      )}

      {/* =================================================
          ENGINE OVERVIEW
          ================================================= */}

      <section className="detection-engine-panel">

        <div className="detection-engine-main">

          <div className="detection-engine-icon">
            <BrainCircuit size={25} />
          </div>

          <div>

            <div className="detection-kicker">
              MACHINE LEARNING DETECTION
            </div>

            <h2>
              Random Forest Intrusion Detection Engine
            </h2>

            <p>
              Network flows are transformed into engineered
              features and classified by the trained
              intrusion detection model.
            </p>

          </div>

        </div>

        <div className="detection-engine-meta">

          <div>
            <span>
              STATUS
            </span>

            <strong className="engine-online">
              OPERATIONAL
            </strong>
          </div>

          <div>
            <span>
              MODE
            </span>

            <strong>
              AI CLASSIFICATION
            </strong>
          </div>

          <div>
            <span>
              RESPONSE
            </span>

            <strong>
              ALERT GENERATION
            </strong>
          </div>

        </div>

      </section>

      {/* =================================================
          KPI CARDS
          ================================================= */}

      <section className="detection-stat-grid">

        <DetectionStat
          icon={ShieldAlert}
          label="Total Detections"
          value={totalAlerts}
          description="Security events classified"
          tone="blue"
        />

        <DetectionStat
          icon={AlertTriangle}
          label="Active Threats"
          value={openAlerts}
          description="Currently unresolved"
          tone="red"
        />

        <DetectionStat
          icon={Target}
          label="Critical Detections"
          value={criticalAlerts}
          description="Highest risk classification"
          tone="orange"
        />

        <DetectionStat
          icon={CheckCircle2}
          label="Resolved"
          value={resolvedAlerts}
          description="Threat events closed"
          tone="green"
        />

      </section>

      {/* =================================================
          DETECTION PIPELINE
          ================================================= */}

      <section className="panel detection-pipeline-panel">

        <div className="panel-header">

          <div>

            <div className="dashboard-section-kicker">
              AI PROCESSING
            </div>

            <h2 className="panel-title">
              Detection Pipeline
            </h2>

            <div className="panel-subtitle">
              How NetSentinel processes network activity
            </div>

          </div>

          <div className="detection-live-badge">

            <span />

            READY

          </div>

        </div>

        <div className="detection-pipeline">

          <div className="detection-pipeline-step active">

            <div className="detection-step-number">
              01
            </div>

            <div>

              <strong>
                Network Traffic
              </strong>

              <span>
                Packet capture
              </span>

            </div>

          </div>

          <div className="detection-pipeline-line" />

          <div className="detection-pipeline-step active">

            <div className="detection-step-number">
              02
            </div>

            <div>

              <strong>
                Flow Construction
              </strong>

              <span>
                Session aggregation
              </span>

            </div>

          </div>

          <div className="detection-pipeline-line" />

          <div className="detection-pipeline-step active">

            <div className="detection-step-number">
              03
            </div>

            <div>

              <strong>
                Feature Extraction
              </strong>

              <span>
                ML preprocessing
              </span>

            </div>

          </div>

          <div className="detection-pipeline-line" />

          <div className="detection-pipeline-step active">

            <div className="detection-step-number">
              04
            </div>

            <div>

              <strong>
                AI Classification
              </strong>

              <span>
                Threat prediction
              </span>

            </div>

          </div>

          <div className="detection-pipeline-line" />

          <div className="detection-pipeline-step active">

            <div className="detection-step-number">
              05
            </div>

            <div>

              <strong>
                Alert Generation
              </strong>

              <span>
                Security response
              </span>

            </div>

          </div>

        </div>

      </section>

      {/* =================================================
          DETECTION HISTORY
          ================================================= */}

      <section className="panel detection-history-panel">

        <div className="panel-header">

          <div>

            <div className="dashboard-section-kicker">
              DETECTION HISTORY
            </div>

            <h2 className="panel-title">
              AI Detection Results
            </h2>

            <div className="panel-subtitle">
              Latest classifications generated by the
              detection engine
            </div>

          </div>

          <div className="detection-count">

            {formatNumber(
              filteredAlerts.length
            )}

            <span>
              results
            </span>

          </div>

        </div>

        {/* FILTERS */}

        <div className="detection-filters">

          {[
            "ALL",
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
          ].map((level) => (

            <button
              key={level}
              className={
                filter === level
                  ? "detection-filter active"
                  : "detection-filter"
              }
              onClick={() =>
                setFilter(level)
              }
            >
              {level}
            </button>

          ))}

        </div>

        {/* RESULTS */}

        <div className="detection-results">

          {filteredAlerts.length === 0 ? (

            <div className="detection-empty">

              <CheckCircle2 size={24} />

              <div>

                <strong>
                  No detections found
                </strong>

                <span>
                  There are no detection results
                  matching the selected filter.
                </span>

              </div>

            </div>

          ) : (

            filteredAlerts.map((alert) => {

              const severity =
                getSeverityClass(
                  alert.severity
                );

              return (

                <div
                  className="detection-result-row"
                  key={alert.id}
                >

                  <div
                    className={`detection-severity-marker ${severity}`}
                  />

                  <div className="detection-result-icon">

                    <AlertTriangle size={17} />

                  </div>

                  <div className="detection-result-main">

                    <div className="detection-result-title">

                      {alert.title ||
                        alert.alert_type ||
                        "Security threat detected"}

                    </div>

                    <div className="detection-result-meta">

                      <span>
                        {alert.source_ip ||
                          "Unknown source"}
                      </span>

                      <span>
                        →
                      </span>

                      <span>
                        {alert.destination_ip ||
                          "Unknown destination"}
                      </span>

                      {alert.destination_port && (
                        <span>
                          :
                          {alert.destination_port}
                        </span>
                      )}

                      {alert.protocol && (
                        <span className="detection-protocol">
                          {alert.protocol}
                        </span>
                      )}

                    </div>

                  </div>

                  <div className="detection-confidence">

                    <span>
                      CONFIDENCE
                    </span>

                    <strong>
                      {alert.confidence != null
                        ? `${Math.round(
                            Number(
                              alert.confidence
                            ) * 100
                          )}%`
                        : alert.probability != null
                          ? `${Math.round(
                              Number(
                                alert.probability
                              ) * 100
                            )}%`
                          : "—"}
                    </strong>

                  </div>

                  <div className="detection-result-time">

                    <Clock3 size={13} />

                    {formatDateTime(
                      alert.created_at
                    )}

                  </div>

                  <span
                    className={`severity-badge ${severity}`}
                  >
                    {alert.severity ||
                      "LOW"}
                  </span>

                  <span
                    className={`status-badge ${
                      alert.status?.toLowerCase() ||
                      "open"
                    }`}
                  >
                    {alert.status ||
                      "OPEN"}
                  </span>

                </div>

              );
            })

          )}

        </div>

      </section>

      {/* =================================================
          DETECTION INFORMATION
          ================================================= */}

      <section className="detection-info-grid">

        <div className="panel detection-info-card">

          <div className="detection-info-icon">
            <Zap size={18} />
          </div>

          <div>

            <h3>
              Automated Detection
            </h3>

            <p>
              Network flows are continuously evaluated
              when live monitoring is active. Suspicious
              classifications can generate security alerts.
            </p>

          </div>

        </div>

        <div className="panel detection-info-card">

          <div className="detection-info-icon">
            <Activity size={18} />
          </div>

          <div>

            <h3>
              Real-Time Monitoring
            </h3>

            <p>
              Detection results are integrated with the
              monitoring engine and can be delivered to
              the security console through real-time events.
            </p>

          </div>

        </div>

      </section>

    </div>
  );
}

