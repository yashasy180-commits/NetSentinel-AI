import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  Clock3,
  Cpu,
  Radio,
  ShieldAlert,
  Wifi,
  RefreshCw,
} from "lucide-react";

import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import axios from "axios";

import { API_BASE } from "../config";

const severityOrder = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
];

/* =========================================================
   HELPERS
   ========================================================= */

function formatNumber(value) {
  return new Intl.NumberFormat("en-US").format(
    Number(value) || 0
  );
}

function formatHour(value) {
  if (!value) return "";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value).slice(11, 16);
  }

  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
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

/* =========================================================
   STAT CARD
   ========================================================= */

function StatCard({
  title,
  value,
  description,
  icon: Icon,
  tone = "blue",
}) {
  return (
    <div
      className={`dashboard-stat-card dashboard-stat-${tone}`}
    >
      <div className={`stat-icon stat-icon-${tone}`}>
        <Icon size={18} strokeWidth={1.8} />
      </div>

      <div className="stat-content">
        <span className="stat-label">
          {title}
        </span>

        <strong className="stat-value">
          {formatNumber(value)}
        </strong>

        <span className="stat-description">
          {description}
        </span>
      </div>

      <ArrowUpRight
        className="stat-arrow"
        size={16}
        strokeWidth={1.7}
      />
    </div>
  );
}

/* =========================================================
   SEVERITY ROW
   ========================================================= */

function SeverityRow({
  severity,
  count,
  total,
}) {
  const severityClass =
    severity.toLowerCase();

  const percentage =
    total > 0
      ? Math.round((count / total) * 100)
      : 0;

  return (
    <div className="severity-row">
      <div className="severity-row-top">

        <div className="severity-name">
          <span
            className={`severity-dot ${severityClass}`}
          />

          <span>{severity}</span>
        </div>

        <div className="severity-value">
          <strong>{count}</strong>
          <span>{percentage}%</span>
        </div>

      </div>

      <div className="severity-progress">
        <span
          className={`severity-progress-fill ${severityClass}`}
          style={{
            width: `${percentage}%`,
          }}
        />
      </div>
    </div>
  );
}

/* =========================================================
   SYSTEM STATUS
   ========================================================= */

function StatusIndicator({
  label,
  status = "Operational",
  icon: Icon,
}) {
  return (
    <div className="dashboard-status-item">

      <div className="dashboard-status-icon">
        <Icon size={15} />
      </div>

      <div>
        <span>{label}</span>
        <strong>{status}</strong>
      </div>

      <div className="dashboard-status-dot" />

    </div>
  );
}

/* =========================================================
   PROTOCOL ROW
   ========================================================= */

function ProtocolRow({
  protocol,
  count,
  total,
}) {
  const percentage =
    total > 0
      ? Math.round((count / total) * 100)
      : 0;

  return (
    <div className="protocol-row">

      <div className="protocol-row-header">

        <div className="protocol-name">
          <span className="protocol-indicator" />

          <strong>
            {protocol}
          </strong>
        </div>

        <div className="protocol-value">
          <strong>
            {formatNumber(count)}
          </strong>

          <span>
            {percentage}%
          </span>
        </div>

      </div>

      <div className="protocol-progress">
        <span
          style={{
            width: `${percentage}%`,
          }}
        />
      </div>

    </div>
  );
}

/* =========================================================
   DASHBOARD
   ========================================================= */

function Dashboard() {
  const [dashboard, setDashboard] =
    useState(null);

  const [alerts, setAlerts] =
    useState([]);

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] =
    useState("");

  const [lastUpdated, setLastUpdated] =
    useState(null);

  const token =
    localStorage.getItem(
      "access_token"
    );

  const authHeaders = useMemo(
    () => ({
      Authorization: `Bearer ${token}`,
    }),
    [token]
  );

  /* =======================================================
     LOAD DATA
     ======================================================= */

  async function loadDashboard(
    showRefreshState = false
  ) {
    try {
      if (showRefreshState) {
        setRefreshing(true);
      }

      setError("");

      const [
        dashboardResponse,
        alertsResponse,
      ] = await Promise.all([
        axios.get(
          `${API_BASE}/analytics/dashboard`,
          {
            headers: authHeaders,
          }
        ),

        axios.get(
          `${API_BASE}/alerts?limit=5`,
          {
            headers: authHeaders,
          }
        ),
      ]);

      setDashboard(
        dashboardResponse.data
      );

      setAlerts(
        alertsResponse.data.alerts || []
      );

      setLastUpdated(new Date());

    } catch (err) {
      console.error(
        "Dashboard loading error:",
        err
      );

      setError(
        err.response?.data?.message ||
          "Unable to load security dashboard."
      );

    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  /* =======================================================
     AUTO REFRESH
     ======================================================= */

  useEffect(() => {
    loadDashboard();

    const interval =
      setInterval(() => {
        loadDashboard();
      }, 15000);

    return () =>
      clearInterval(interval);
  }, []);

  /* =======================================================
     LOADING
     ======================================================= */

  if (loading) {
    return (
      <div className="dashboard-page">

        <div className="dashboard-loading-screen">

          <div className="dashboard-loading-icon">
            <ShieldAlert size={25} />
          </div>

          <strong>
            Initializing Security Operations Center
          </strong>

          <span>
            Loading threat intelligence and
            network telemetry...
          </span>

          <div className="dashboard-loading-bar">
            <span />
          </div>

        </div>

      </div>
    );
  }

  /* =======================================================
     ERROR
     ======================================================= */

  if (error) {
    return (
      <div className="dashboard-page">

        <div className="page-header">

          <div>

            <div className="eyebrow">
              <span className="live-indicator" />
              SECURITY OPERATIONS CENTER
            </div>

            <h1 className="page-title">
              Security Overview
            </h1>

            <p className="page-description">
              Network activity, threat detection
              and security intelligence.
            </p>

          </div>

        </div>

        <div className="dashboard-error">

          <AlertTriangle size={20} />

          <div>

            <strong>
              Dashboard unavailable
            </strong>

            <p>{error}</p>

          </div>

          <button
            className="btn btn-secondary"
            onClick={() =>
              loadDashboard(true)
            }
          >
            <RefreshCw size={15} />
            Retry
          </button>

        </div>

      </div>
    );
  }

  /* =======================================================
     ANALYTICS DATA
     ======================================================= */

  const analytics =
    dashboard?.analytics || {};

  const overview =
    analytics.overview || {};

  const severity =
    overview.severity ||
    analytics.severity_distribution ||
    {};

  const timeline =
    analytics.timeline || [];

  const protocolDistribution =
    analytics.protocol_distribution || {};

  /* =======================================================
     KPI DATA
     ======================================================= */

  const networkActivity =
    Object.values(
      protocolDistribution
    ).reduce(
      (total, value) =>
        total + (Number(value) || 0),
      0
    );

  const totalAlerts =
    overview.total_alerts ??
    overview.total ??
    0;

  const activeThreats =
    overview.active_alerts ??
    overview.open_alerts ??
    0;

  const resolvedAlerts =
    overview.resolved_alerts ??
    overview.resolved ??
    0;

  /* =======================================================
     SEVERITY DATA
     ======================================================= */

  const severityCounts =
    severityOrder.map(
      (level) => ({
        level,

        count:
          severity[level] ??
          severity[
            level.toLowerCase()
          ] ??
          0,
      })
    );

  const severityTotal =
    severityCounts.reduce(
      (sum, item) =>
        sum + Number(item.count || 0),
      0
    );

  /* =======================================================
     PROTOCOL DATA
     ======================================================= */

  const protocolEntries =
    Object.entries(
      protocolDistribution
    ).sort(
      (a, b) =>
        Number(b[1]) -
        Number(a[1])
    );

  /* =======================================================
     THREAT CHART DATA
     ======================================================= */

  const chartData =
    timeline.map((item) => ({
      time: formatHour(
        item.timestamp ||
          item.hour ||
          item.time ||
          item.created_at ||
          item.bucket ||
          item.date
      ),

      attacks:
        Number(
          item.count ??
            item.attacks ??
            item.total ??
            item.value ??
            0
        ),
    }));

  /*
   * Only show the graph when there is
   * actual threat activity.
   *
   * A timeline containing only zero values
   * should not look like meaningful activity.
   */

  const hasThreatActivity =
    chartData.some(
      (item) => item.attacks > 0
    );

  /* =======================================================
     RENDER
     ======================================================= */

  return (
    <div className="dashboard-page">

      {/* =================================================
          HEADER
          ================================================= */}

      <div className="dashboard-hero">

        <div>

          <div className="eyebrow">
            <span className="live-indicator" />
            LIVE SECURITY OPERATIONS
          </div>

          <h1 className="page-title">
            Security Overview
          </h1>

          <p className="page-description">
            Network activity, threat detection
            and security intelligence at a glance.
          </p>

        </div>

        <div className="dashboard-header-actions">

          <div className="dashboard-last-update">

            <Clock3 size={14} />

            <span>
              {lastUpdated
                ? `Updated ${lastUpdated.toLocaleTimeString(
                    [],
                    {
                      hour: "2-digit",
                      minute: "2-digit",
                    }
                  )}`
                : "Updating..."}
            </span>

          </div>

          <button
            className="btn btn-secondary dashboard-refresh-btn"
            onClick={() =>
              loadDashboard(true)
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
          SYSTEM STATUS
          ================================================= */}

      <section className="dashboard-status-strip">

        <StatusIndicator
          label="Detection Engine"
          status="Operational"
          icon={Cpu}
        />

        <StatusIndicator
          label="Network Telemetry"
          status="Available"
          icon={Radio}
        />

        <StatusIndicator
          label="Alert Pipeline"
          status="Operational"
          icon={ShieldAlert}
        />

        <StatusIndicator
          label="Security API"
          status="Connected"
          icon={Activity}
        />

      </section>

      {/* =================================================
          KPI CARDS
          ================================================= */}

      <section className="dashboard-stat-grid">

        <StatCard
          title="Total Alerts"
          value={totalAlerts}
          description="Recorded security events"
          icon={ShieldAlert}
          tone="blue"
        />

        <StatCard
          title="Active Threats"
          value={activeThreats}
          description="Currently unresolved"
          icon={AlertTriangle}
          tone="red"
        />

        <StatCard
          title="Resolved"
          value={resolvedAlerts}
          description="Successfully closed"
          icon={CheckCircle2}
          tone="green"
        />

        <StatCard
          title="Network Activity"
          value={networkActivity}
          description="Protocol activity recorded"
          icon={Wifi}
          tone="cyan"
        />

      </section>

      {/* =================================================
          THREAT + SEVERITY
          ================================================= */}

      <section className="dashboard-main-grid">

        {/* THREAT ACTIVITY */}

        <div className="panel dashboard-chart-panel">

          <div className="panel-header">

            <div>

              <div className="dashboard-section-kicker">
                THREAT TELEMETRY
              </div>

              <h2 className="panel-title">
                Threat Activity
              </h2>

              <div className="panel-subtitle">
                Security events across the current
                monitoring window
              </div>

            </div>

            <div className="chart-status">

              <span className="chart-status-dot" />

              Live data

            </div>

          </div>

          <div className="chart-container">

            {hasThreatActivity ? (

              <ResponsiveContainer
                width="100%"
                height="100%"
              >

                <AreaChart
                  data={chartData}
                  margin={{
                    top: 10,
                    right: 10,
                    left: 0,
                    bottom: 0,
                  }}
                >

                  <defs>

                    <linearGradient
                      id="threatGradient"
                      x1="0"
                      y1="0"
                      x2="0"
                      y2="1"
                    >

                      <stop
                        offset="0%"
                        stopColor="#3b82f6"
                        stopOpacity={0.3}
                      />

                      <stop
                        offset="100%"
                        stopColor="#3b82f6"
                        stopOpacity={0}
                      />

                    </linearGradient>

                  </defs>

                  <CartesianGrid
                    stroke="rgba(255,255,255,0.045)"
                    vertical={false}
                  />

                  <XAxis
                    dataKey="time"
                    axisLine={false}
                    tickLine={false}
                    tick={{
                      fill: "#64748b",
                      fontSize: 10,
                    }}
                    minTickGap={25}
                  />

                  <YAxis
                    allowDecimals={false}
                    axisLine={false}
                    tickLine={false}
                    width={28}
                    tick={{
                      fill: "#64748b",
                      fontSize: 10,
                    }}
                  />

                  <Tooltip
                    cursor={{
                      stroke:
                        "rgba(96,165,250,0.35)",
                      strokeWidth: 1,
                    }}
                    contentStyle={{
                      background: "#0d131b",
                      border:
                        "1px solid rgba(96,165,250,0.18)",
                      borderRadius: "8px",
                      color: "#edf3fa",
                      fontSize: "12px",
                      padding: "10px 12px",
                    }}
                    labelStyle={{
                      color: "#94a3b8",
                      marginBottom: "4px",
                    }}
                    formatter={(value) => [
                      `${value} event${
                        value === 1
                          ? ""
                          : "s"
                      }`,
                      "Threat activity",
                    ]}
                  />

                  <Area
                    type="monotone"
                    dataKey="attacks"
                    stroke="#3b82f6"
                    strokeWidth={2}
                    fill="url(#threatGradient)"
                    dot={false}
                    activeDot={{
                      r: 4,
                      strokeWidth: 2,
                      stroke: "#0d131b",
                      fill: "#60a5fa",
                    }}
                  />

                </AreaChart>

              </ResponsiveContainer>

            ) : (

              <div className="chart-empty">

                <Clock3 size={22} />

                <strong>
                  No threat activity in this period
                </strong>

                <span>
                  The detection engine has not
                  recorded security events during
                  the current analytics window.
                </span>

              </div>

            )}

          </div>

        </div>

        {/* SEVERITY */}

        <div className="panel severity-panel">

          <div className="panel-header">

            <div>

              <div className="dashboard-section-kicker">
                RISK CLASSIFICATION
              </div>

              <h2 className="panel-title">
                Severity Distribution
              </h2>

              <div className="panel-subtitle">
                Current alert classification
              </div>

            </div>

          </div>

          <div className="severity-list">

            {severityCounts.map(
              (item) => (
                <SeverityRow
                  key={item.level}
                  severity={item.level}
                  count={Number(item.count) || 0}
                  total={severityTotal}
                />
              )
            )}

          </div>

          <div className="severity-total">

            <span>
              Total classified alerts
            </span>

            <strong>
              {formatNumber(
                severityTotal
              )}
            </strong>

          </div>

        </div>

      </section>

      {/* =================================================
          PROTOCOL DISTRIBUTION
          ================================================= */}

      <section className="panel protocol-distribution-panel">

        <div className="panel-header">

          <div>

            <div className="dashboard-section-kicker">
              NETWORK TELEMETRY
            </div>

            <h2 className="panel-title">
              Protocol Distribution
            </h2>

            <div className="panel-subtitle">
              Network activity grouped by protocol
            </div>

          </div>

          <div className="protocol-total">

            {formatNumber(
              networkActivity
            )}

            <span>
              events
            </span>

          </div>

        </div>

        <div className="protocol-list">

          {protocolEntries.length === 0 ? (

            <div className="protocol-empty">

              <Wifi size={20} />

              <span>
                No protocol activity available
              </span>

            </div>

          ) : (

            protocolEntries.map(
              ([protocol, value]) => (

                <ProtocolRow
                  key={protocol}
                  protocol={protocol}
                  count={Number(value) || 0}
                  total={networkActivity}
                />

              )
            )

          )}

        </div>

      </section>

      {/* =================================================
          RECENT SECURITY EVENTS
          ================================================= */}

      <section className="panel recent-alerts-panel">

        <div className="panel-header">

          <div>

            <div className="dashboard-section-kicker">
              SECURITY EVENTS
            </div>

            <h2 className="panel-title">
              Recent Security Events
            </h2>

            <div className="panel-subtitle">
              Latest detections from the AI
              security engine
            </div>

          </div>

          <a
            href="/alerts"
            className="panel-link"
          >
            View all
            <ArrowUpRight size={14} />
          </a>

        </div>

        <div className="alert-list">

          {alerts.length === 0 ? (

            <div className="dashboard-empty">

              <CheckCircle2 size={22} />

              <div>

                <strong>
                  No recent security alerts
                </strong>

                <span>
                  The security engine has not
                  reported any recent alerts.
                </span>

              </div>

            </div>

          ) : (

            alerts.map((alert) => {

              const severityName =
                alert.severity?.toLowerCase() ||
                "low";

              return (

                <div
                  className="dashboard-alert-row"
                  key={alert.id}
                >

                  <div
                    className={`alert-severity-bar ${severityName}`}
                  />

                  <div className="dashboard-alert-main">

                    <div className="dashboard-alert-title">
                      {alert.title ||
                        alert.alert_type ||
                        "Security alert"}
                    </div>

                    <div className="dashboard-alert-meta">

                      <span>
                        {alert.source_ip ||
                          "Unknown source"}
                      </span>

                      <span className="alert-route-arrow">
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
                        <span className="alert-protocol">
                          {alert.protocol}
                        </span>
                      )}

                    </div>

                  </div>

                  <div className="dashboard-alert-time">
                    {formatDateTime(
                      alert.created_at
                    )}
                  </div>

                  <span
                    className={`severity-badge ${severityName}`}
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

    </div>
  );
}

export default Dashboard;

