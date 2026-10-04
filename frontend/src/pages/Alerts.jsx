import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  RefreshCw,
  Search,
  ShieldAlert,
} from "lucide-react";
import axios from "axios";

import { API_BASE } from "../config";

const severityOptions = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];
const statusOptions = ["ALL", "OPEN", "ACKNOWLEDGED", "RESOLVED"];

function formatDate(value) {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function formatPercent(value) {
  if (value === null || value === undefined) {
    return "—";
  }

  return `${(Number(value) * 100).toFixed(1)}%`;
}

function severityClass(severity) {
  return (severity || "LOW").toLowerCase();
}

function statusClass(status) {
  return (status || "OPEN").toLowerCase();
}

function AlertCard({ alert, onAcknowledge, onResolve, actionId }) {
  const severity = severityClass(alert.severity);
  const status = statusClass(alert.status);

  const isActionRunning = actionId === alert.id;

  return (
    <article className="alert-page-card">
      <div className={`alert-card-severity ${severity}`} />

      <div className="alert-card-body">
        <div className="alert-card-top">
          <div className="alert-card-heading">
            <div className={`alert-card-icon ${severity}`}>
              <ShieldAlert size={18} />
            </div>

            <div>
              <h3>
                {alert.title ||
                  alert.alert_type ||
                  "Security alert"}
              </h3>

              <span className="alert-card-id">
                Alert #{alert.id}
              </span>
            </div>
          </div>

          <div className="alert-card-badges">
            <span className={`severity-badge ${severity}`}>
              {alert.severity || "LOW"}
            </span>

            <span className={`status-badge ${status}`}>
              {alert.status || "OPEN"}
            </span>
          </div>
        </div>

        <div className="alert-card-description">
          {alert.description ||
            "AI security engine detected suspicious network activity."}
        </div>

        <div className="alert-network-flow">
          <div>
            <span>Source</span>
            <strong>
              {alert.source_ip || "Unknown"}
              {alert.source_port
                ? `:${alert.source_port}`
                : ""}
            </strong>
          </div>

          <div className="flow-arrow">→</div>

          <div>
            <span>Destination</span>
            <strong>
              {alert.destination_ip || "Unknown"}
              {alert.destination_port
                ? `:${alert.destination_port}`
                : ""}
            </strong>
          </div>

          <div>
            <span>Protocol</span>
            <strong>{alert.protocol || "—"}</strong>
          </div>
        </div>

        <div className="alert-card-metrics">
          <div>
            <span>Confidence</span>
            <strong>{formatPercent(alert.confidence)}</strong>
          </div>

          <div>
            <span>Probability</span>
            <strong>{formatPercent(alert.probability)}</strong>
          </div>

          <div>
            <span>Prediction</span>
            <strong>
              {alert.detection_data?.prediction ||
                alert.prediction ||
                "—"}
            </strong>
          </div>

          <div>
            <span>Detected</span>
            <strong>{formatDate(alert.created_at)}</strong>
          </div>
        </div>

        <div className="alert-card-footer">
          <div className="alert-engine-state">
            {severity === "critical" ? (
              <AlertTriangle size={15} />
            ) : (
              <CheckCircle2 size={15} />
            )}

            <span>
              AI intrusion detection engine
            </span>
          </div>

          <div className="alert-actions">
            {status === "open" && (
              <button
                className="btn btn-secondary btn-small"
                disabled={isActionRunning}
                onClick={() => onAcknowledge(alert.id)}
              >
                {isActionRunning ? (
                  <RefreshCw size={14} className="spin" />
                ) : (
                  <Clock3 size={14} />
                )}

                Acknowledge
              </button>
            )}

            {status !== "resolved" && (
              <button
                className="btn btn-primary btn-small"
                disabled={isActionRunning}
                onClick={() => onResolve(alert.id)}
              >
                {isActionRunning ? (
                  <RefreshCw size={14} className="spin" />
                ) : (
                  <CheckCircle2 size={14} />
                )}

                Resolve
              </button>
            )}
          </div>
        </div>
      </div>
    </article>
  );
}

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [status, setStatus] = useState("ALL");
  const [actionId, setActionId] = useState(null);

  const token = localStorage.getItem("access_token");

  const headers = useMemo(
    () => ({
      Authorization: `Bearer ${token}`,
    }),
    [token]
  );

  async function loadAlerts(showRefresh = false) {
    try {
      if (showRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError("");

      const response = await axios.get(
        `${API_BASE}/alerts?limit=100`,
        { headers }
      );

      setAlerts(response.data.alerts || []);
    } catch (err) {
      console.error("Alerts loading error:", err);

      setError(
        err.response?.data?.message ||
          "Unable to load security alerts."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadAlerts();

    const interval = setInterval(() => {
      loadAlerts(true);
    }, 15000);

    return () => clearInterval(interval);
  }, []);

  async function handleAcknowledge(alertId) {
    try {
      setActionId(alertId);

      await axios.post(
        `${API_BASE}/alerts/${alertId}/acknowledge`,
        {},
        { headers }
      );

      await loadAlerts(true);
    } catch (err) {
      console.error("Acknowledge error:", err);

      setError(
        err.response?.data?.message ||
          "Unable to acknowledge the alert."
      );
    } finally {
      setActionId(null);
    }
  }

  async function handleResolve(alertId) {
    try {
      setActionId(alertId);

      await axios.post(
        `${API_BASE}/alerts/${alertId}/resolve`,
        {},
        { headers }
      );

      await loadAlerts(true);
    } catch (err) {
      console.error("Resolve error:", err);

      setError(
        err.response?.data?.message ||
          "Unable to resolve the alert."
      );
    } finally {
      setActionId(null);
    }
  }

  const filteredAlerts = alerts.filter((alert) => {
    const matchesSeverity =
      severity === "ALL" ||
      alert.severity?.toUpperCase() === severity;

    const matchesStatus =
      status === "ALL" ||
      alert.status?.toUpperCase() === status;

    const query = search.trim().toLowerCase();

    const matchesSearch =
      !query ||
      String(alert.id).includes(query) ||
      alert.title?.toLowerCase().includes(query) ||
      alert.source_ip?.toLowerCase().includes(query) ||
      alert.destination_ip?.toLowerCase().includes(query) ||
      alert.protocol?.toLowerCase().includes(query);

    return (
      matchesSeverity &&
      matchesStatus &&
      matchesSearch
    );
  });

  const counts = {
    total: alerts.length,
    open: alerts.filter(
      (alert) => alert.status?.toUpperCase() === "OPEN"
    ).length,
    acknowledged: alerts.filter(
      (alert) =>
        alert.status?.toUpperCase() === "ACKNOWLEDGED"
    ).length,
    resolved: alerts.filter(
      (alert) =>
        alert.status?.toUpperCase() === "RESOLVED"
    ).length,
  };

  if (loading) {
    return (
      <div className="alerts-page">
        <div className="page-header">
          <div>
            <div className="eyebrow">
              <span className="live-indicator" />
              SECURITY ALERT CENTER
            </div>

            <h1 className="page-title">
              Security Alerts
            </h1>

            <p className="page-description">
              Loading alerts from the AI security engine...
            </p>
          </div>
        </div>

        <div className="dashboard-loading">
          Loading security alerts
        </div>
      </div>
    );
  }

  return (
    <div className="alerts-page">
      <div className="page-header">
        <div>
          <div className="eyebrow">
            <span className="live-indicator" />
            SECURITY ALERT CENTER
          </div>

          <h1 className="page-title">
            Security Alerts
          </h1>

          <p className="page-description">
            Investigate, acknowledge and resolve detected
            security events.
          </p>
        </div>

        <button
          className="btn btn-secondary"
          onClick={() => loadAlerts(true)}
          disabled={refreshing}
        >
          <RefreshCw
            size={15}
            className={refreshing ? "spin" : ""}
          />
          Refresh
        </button>
      </div>

      <section className="alert-summary-grid">
        <div className="alert-summary-card">
          <span>Total Alerts</span>
          <strong>{counts.total}</strong>
        </div>

        <div className="alert-summary-card alert-summary-open">
          <span>Open</span>
          <strong>{counts.open}</strong>
        </div>

        <div className="alert-summary-card alert-summary-ack">
          <span>Acknowledged</span>
          <strong>{counts.acknowledged}</strong>
        </div>

        <div className="alert-summary-card alert-summary-resolved">
          <span>Resolved</span>
          <strong>{counts.resolved}</strong>
        </div>
      </section>

      <section className="panel alert-toolbar">
        <div className="alert-search">
          <Search size={17} />

          <input
            type="text"
            placeholder="Search alerts, IP addresses or protocols..."
            value={search}
            onChange={(event) =>
              setSearch(event.target.value)
            }
          />
        </div>

        <div className="alert-filter-group">
          <select
            value={severity}
            onChange={(event) =>
              setSeverity(event.target.value)
            }
          >
            {severityOptions.map((option) => (
              <option
                key={option}
                value={option}
              >
                {option === "ALL"
                  ? "All Severities"
                  : option}
              </option>
            ))}
          </select>

          <select
            value={status}
            onChange={(event) =>
              setStatus(event.target.value)
            }
          >
            {statusOptions.map((option) => (
              <option
                key={option}
                value={option}
              >
                {option === "ALL"
                  ? "All Statuses"
                  : option}
              </option>
            ))}
          </select>
        </div>
      </section>

      {error && (
        <div className="dashboard-error alert-page-error">
          <AlertTriangle size={20} />

          <div>
            <strong>Alert operation failed</strong>
            <p>{error}</p>
          </div>

          <button
            className="btn btn-secondary"
            onClick={() => loadAlerts(true)}
          >
            Retry
          </button>
        </div>
      )}

      <div className="alert-results-header">
        <div>
          <strong>
            {filteredAlerts.length}
          </strong>{" "}
          security event
          {filteredAlerts.length !== 1 ? "s" : ""}
        </div>

        <span>
          Automatically refreshed every 15 seconds
        </span>
      </div>

      <section className="alert-card-list">
        {filteredAlerts.length === 0 ? (
          <div className="panel alert-empty">
            <CheckCircle2 size={28} />

            <h3>No alerts found</h3>

            <p>
              No security events match the current
              filters.
            </p>
          </div>
        ) : (
          filteredAlerts.map((alert) => (
            <AlertCard
              key={alert.id}
              alert={alert}
              onAcknowledge={handleAcknowledge}
              onResolve={handleResolve}
              actionId={actionId}
            />
          ))
        )}
      </section>
    </div>
  );
}

