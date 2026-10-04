import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Clock3,
  RefreshCw,
  ShieldAlert,
  Target,
  TrendingUp,
  Wifi,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
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

function formatHour(value) {
  if (!value) return "";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value).slice(0, 16);
  }

  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatDate(value) {
  if (!value) return "";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleDateString([], {
    day: "2-digit",
    month: "short",
  });
}

/* =========================================================
   TOOLTIP
   ========================================================= */

function AnalyticsTooltip({
  active,
  payload,
  label,
}) {
  if (!active || !payload?.length) {
    return null;
  }

  return (
    <div className="analytics-tooltip">
      <div className="analytics-tooltip-label">
        {label}
      </div>

      {payload.map((item, index) => (
        <div
          className="analytics-tooltip-row"
          key={`${item.dataKey}-${index}`}
        >
          <span>
            {item.name || item.dataKey}
          </span>

          <strong>
            {formatNumber(item.value)}
          </strong>
        </div>
      ))}
    </div>
  );
}

/* =========================================================
   STAT CARD
   ========================================================= */

function AnalyticsStat({
  icon: Icon,
  label,
  value,
  description,
  tone,
}) {
  return (
    <div className="analytics-stat-card">

      <div
        className={`analytics-stat-icon ${tone}`}
      >
        <Icon size={18} />
      </div>

      <div className="analytics-stat-content">

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
   ANALYTICS PAGE
   ========================================================= */

export default function Analytics() {

  const [dashboard, setDashboard] =
    useState(null);

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

  const headers = useMemo(
    () => ({
      Authorization: `Bearer ${token}`,
    }),
    [token]
  );

  /* =======================================================
     LOAD ANALYTICS
     ======================================================= */

  async function loadAnalytics(
    showRefresh = false
  ) {

    try {

      if (showRefresh) {
        setRefreshing(true);
      }

      setError("");

      const response =
        await axios.get(
          `${API_BASE}/analytics/dashboard`,
          {
            headers,
          }
        );

      setDashboard(
        response.data
      );

      setLastUpdated(
        new Date()
      );

    } catch (err) {

      console.error(
        "Analytics loading error:",
        err
      );

      setError(
        err.response?.data?.message ||
        "Unable to load security analytics."
      );

    } finally {

      setLoading(false);
      setRefreshing(false);
    }
  }

  /* =======================================================
     INITIAL LOAD
     ======================================================= */

  useEffect(() => {

    loadAnalytics();

    const interval =
      setInterval(() => {
        loadAnalytics();
      }, 30000);

    return () =>
      clearInterval(interval);

  }, []);

  /* =======================================================
     DATA NORMALIZATION
     ======================================================= */

  const analytics =
    dashboard?.analytics || {};

  const overview =
    analytics.overview || {};

  const severity =
    overview.severity ||
    analytics.severity_distribution ||
    {};

  const statusDistribution =
    analytics.status_distribution ||
    analytics.status ||
    {};

  const protocolDistribution =
    analytics.protocol_distribution ||
    {};

  const topSources =
    analytics.top_sources ||
    analytics.top_source_ips ||
    [];

  const topDestinations =
    analytics.top_destinations ||
    analytics.top_destination_ips ||
    [];

  const timeline =
    analytics.timeline || [];

  /* =======================================================
     KPI VALUES
     ======================================================= */

  const totalAlerts =
    overview.total_alerts ??
    overview.total ??
    0;

  const activeAlerts =
    overview.active_alerts ??
    overview.open_alerts ??
    overview.open ??
    0;

  const resolvedAlerts =
    overview.resolved_alerts ??
    overview.resolved ??
    0;

  const acknowledgedAlerts =
    overview.acknowledged_alerts ??
    overview.acknowledged ??
    0;

  /* =======================================================
     SEVERITY DATA
     ======================================================= */

  const severityData = [
    {
      name: "Critical",
      value:
        Number(
          severity.critical ??
          severity.CRITICAL ??
          0
        ),
      className: "critical",
    },
    {
      name: "High",
      value:
        Number(
          severity.high ??
          severity.HIGH ??
          0
        ),
      className: "high",
    },
    {
      name: "Medium",
      value:
        Number(
          severity.medium ??
          severity.MEDIUM ??
          0
        ),
      className: "medium",
    },
    {
      name: "Low",
      value:
        Number(
          severity.low ??
          severity.LOW ??
          0
        ),
      className: "low",
    },
  ];

  const severityTotal =
    severityData.reduce(
      (sum, item) =>
        sum + item.value,
      0
    );

  /* =======================================================
     STATUS DATA
     ======================================================= */

  const statusData = [
    {
      name: "Open",
      value:
        Number(
          statusDistribution.OPEN ??
          statusDistribution.open ??
          overview.open_alerts ??
          overview.open ??
          0
        ),
    },
    {
      name: "Acknowledged",
      value:
        Number(
          statusDistribution.ACKNOWLEDGED ??
          statusDistribution.acknowledged ??
          overview.acknowledged_alerts ??
          overview.acknowledged ??
          0
        ),
    },
    {
      name: "Resolved",
      value:
        Number(
          statusDistribution.RESOLVED ??
          statusDistribution.resolved ??
          overview.resolved_alerts ??
          overview.resolved ??
          0
        ),
    },
  ];

  /* =======================================================
     PROTOCOL DATA
     ======================================================= */

  const protocolData =
    Object.entries(
      protocolDistribution
    )
      .map(
        ([name, value]) => ({
          name,
          value: Number(value) || 0,
        })
      )
      .sort(
        (a, b) =>
          b.value - a.value
      );

  /* =======================================================
     TOP SOURCE DATA
     ======================================================= */

  const normalizeRanking =
    (items) => {

      if (!Array.isArray(items)) {
        return Object.entries(
          items || {}
        ).map(
          ([name, value]) => ({
            name,
            value:
              Number(value) || 0,
          })
        );
      }

      return items.map(
        (item) => ({
          name:
            item.ip ||
            item.source_ip ||
            item.destination_ip ||
            item.name ||
            item.address ||
            "Unknown",
          value:
            Number(
              item.count ??
              item.total ??
              item.value ??
              0
            ),
        })
      );
    };

  const sourceData =
    normalizeRanking(
      topSources
    ).slice(0, 5);

  const destinationData =
    normalizeRanking(
      topDestinations
    ).slice(0, 5);

  /* =======================================================
     TIMELINE
     ======================================================= */

  const timelineData =
    timeline.map(
      (item) => ({
        time:
          formatHour(
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
      })
    );

  const hasTimelineActivity =
    timelineData.some(
      (item) =>
        item.attacks > 0
    );

  /* =======================================================
     CHART COLORS
     ======================================================= */

  const severityColors = {
    critical: "#f43f5e",
    high: "#f97316",
    medium: "#eab308",
    low: "#22c55e",
  };

  /* =======================================================
     LOADING
     ======================================================= */

  if (loading) {

    return (
      <div className="analytics-page">

        <div className="dashboard-loading">
          Loading security analytics console
        </div>

      </div>
    );
  }

  /* =======================================================
     PAGE
     ======================================================= */

  return (
    <div className="analytics-page">

      {/* =================================================
          HEADER
          ================================================= */}

      <div className="page-header">

        <div>

          <div className="eyebrow">

            <span className="live-indicator" />

            SECURITY INTELLIGENCE

          </div>

          <h1 className="page-title">
            Security Analytics
          </h1>

          <p className="page-description">
            Analyze threat activity, alert patterns,
            network protocols and security trends.
          </p>

        </div>

        <div className="analytics-header-actions">

          <div className="analytics-updated">

            <Clock3 size={13} />

            {lastUpdated
              ? `Updated ${lastUpdated.toLocaleTimeString(
                  [],
                  {
                    hour: "2-digit",
                    minute: "2-digit",
                  }
                )}`
              : "Updating..."}

          </div>

          <button
            className="btn btn-secondary"
            onClick={() =>
              loadAnalytics(true)
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
              Analytics unavailable
            </strong>

            <p>
              {error}
            </p>

          </div>

          <button
            className="btn btn-secondary"
            onClick={() =>
              loadAnalytics(true)
            }
          >
            Retry
          </button>

        </div>

      )}

      {/* =================================================
          KPI CARDS
          ================================================= */}

      <section className="analytics-stat-grid">

        <AnalyticsStat
          icon={ShieldAlert}
          label="Total Alerts"
          value={totalAlerts}
          description="Recorded security events"
          tone="blue"
        />

        <AnalyticsStat
          icon={AlertTriangle}
          label="Active Threats"
          value={activeAlerts}
          description="Currently unresolved"
          tone="red"
        />

        <AnalyticsStat
          icon={Target}
          label="Acknowledged"
          value={acknowledgedAlerts}
          description="Reviewed by analysts"
          tone="orange"
        />

        <AnalyticsStat
          icon={TrendingUp}
          label="Resolved"
          value={resolvedAlerts}
          description="Successfully closed"
          tone="green"
        />

      </section>

      {/* =================================================
          THREAT TIMELINE
          ================================================= */}

      <section className="panel analytics-timeline-panel">

        <div className="panel-header">

          <div>

            <div className="dashboard-section-kicker">
              THREAT TELEMETRY
            </div>

            <h2 className="panel-title">
              Threat Activity Timeline
            </h2>

            <div className="panel-subtitle">
              Security events across the current
              analytics window
            </div>

          </div>

          <div className="analytics-live-badge">

            <span />

            LIVE DATA

          </div>

        </div>

        <div className="analytics-timeline-chart">

          {hasTimelineActivity ? (

            <ResponsiveContainer
              width="100%"
              height="100%"
            >

              <AreaChart
                data={timelineData}
                margin={{
                  top: 10,
                  right: 10,
                  left: 0,
                  bottom: 0,
                }}
              >

                <defs>

                  <linearGradient
                    id="analyticsThreatGradient"
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
                  minTickGap={25}
                  tick={{
                    fill: "#64748b",
                    fontSize: 10,
                  }}
                />

                <YAxis
                  allowDecimals={false}
                  axisLine={false}
                  tickLine={false}
                  width={30}
                  tick={{
                    fill: "#64748b",
                    fontSize: 10,
                  }}
                />

                <Tooltip
                  content={
                    <AnalyticsTooltip />
                  }
                />

                <Area
                  type="monotone"
                  dataKey="attacks"
                  name="Threats"
                  stroke="#3b82f6"
                  strokeWidth={2}
                  fill="url(#analyticsThreatGradient)"
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

            <div className="analytics-chart-empty">

              <Activity size={22} />

              <strong>
                No threat activity in this period
              </strong>

              <span>
                No security events were recorded
                during the current analytics window.
              </span>

            </div>

          )}

        </div>

      </section>

      {/* =================================================
          DISTRIBUTION ROW
          ================================================= */}

      <section className="analytics-chart-grid">

        {/* SEVERITY */}

        <div className="panel analytics-severity-panel">

          <div className="panel-header">

            <div>

              <div className="dashboard-section-kicker">
                RISK CLASSIFICATION
              </div>

              <h2 className="panel-title">
                Severity Distribution
              </h2>

              <div className="panel-subtitle">
                Alerts grouped by severity
              </div>

            </div>

          </div>

          <div className="analytics-pie-layout">

            <div className="analytics-pie">

              {severityTotal > 0 ? (

                <ResponsiveContainer
                  width="100%"
                  height="100%"
                >

                  <PieChart>

                    <Pie
                      data={severityData}
                      dataKey="value"
                      nameKey="name"
                      innerRadius="62%"
                      outerRadius="82%"
                      paddingAngle={3}
                      stroke="none"
                    >

                      {severityData.map(
                        (item) => (
                          <Cell
                            key={item.name}
                            fill={
                              severityColors[
                                item.className
                              ]
                            }
                          />
                        )
                      )}

                    </Pie>

                    <Tooltip
                      content={
                        <AnalyticsTooltip />
                      }
                    />

                  </PieChart>

                </ResponsiveContainer>

              ) : (

                <div className="analytics-pie-empty">
                  No data
                </div>

              )}

              <div className="analytics-pie-center">

                <strong>
                  {formatNumber(
                    severityTotal
                  )}
                </strong>

                <span>
                  alerts
                </span>

              </div>

            </div>

            <div className="analytics-legend">

              {severityData.map(
                (item) => {

                  const percentage =
                    severityTotal > 0
                      ? Math.round(
                          (item.value /
                            severityTotal) *
                            100
                        )
                      : 0;

                  return (

                    <div
                      className="analytics-legend-row"
                      key={item.name}
                    >

                      <div>

                        <span
                          className={`analytics-legend-dot ${item.className}`}
                        />

                        <span>
                          {item.name}
                        </span>

                      </div>

                      <strong>
                        {formatNumber(
                          item.value
                        )}
                      </strong>

                      <small>
                        {percentage}%
                      </small>

                    </div>

                  );
                }
              )}

            </div>

          </div>

        </div>

        {/* PROTOCOL */}

        <div className="panel analytics-protocol-panel">

          <div className="panel-header">

            <div>

              <div className="dashboard-section-kicker">
                NETWORK TELEMETRY
              </div>

              <h2 className="panel-title">
                Protocol Distribution
              </h2>

              <div className="panel-subtitle">
                Network activity by protocol
              </div>

            </div>

          </div>

          <div className="analytics-protocol-chart">

            {protocolData.length > 0 ? (

              <ResponsiveContainer
                width="100%"
                height="100%"
              >

                <BarChart
                  data={protocolData}
                  layout="vertical"
                  margin={{
                    top: 5,
                    right: 20,
                    left: 10,
                    bottom: 5,
                  }}
                >

                  <CartesianGrid
                    stroke="rgba(255,255,255,0.04)"
                    horizontal={false}
                  />

                  <XAxis
                    type="number"
                    allowDecimals={false}
                    axisLine={false}
                    tickLine={false}
                    tick={{
                      fill: "#64748b",
                      fontSize: 9,
                    }}
                  />

                  <YAxis
                    type="category"
                    dataKey="name"
                    axisLine={false}
                    tickLine={false}
                    width={55}
                    tick={{
                      fill: "#94a3b8",
                      fontSize: 9,
                    }}
                  />

                  <Tooltip
                    content={
                      <AnalyticsTooltip />
                    }
                  />

                  <Bar
                    dataKey="value"
                    name="Events"
                    fill="#3b82f6"
                    radius={[
                      0,
                      4,
                      4,
                      0,
                    ]}
                    barSize={16}
                  />

                </BarChart>

              </ResponsiveContainer>

            ) : (

              <div className="analytics-chart-empty">
                <Wifi size={21} />

                <span>
                  No protocol data available
                </span>
              </div>

            )}

          </div>

        </div>

      </section>

      {/* =================================================
          STATUS + TOP SOURCES
          ================================================= */}

      <section className="analytics-bottom-grid">

        {/* ALERT STATUS */}

        <div className="panel analytics-status-panel">

          <div className="panel-header">

            <div>

              <div className="dashboard-section-kicker">
                ALERT MANAGEMENT
              </div>

              <h2 className="panel-title">
                Alert Status
              </h2>

              <div className="panel-subtitle">
                Current lifecycle of security alerts
              </div>

            </div>

          </div>

          <div className="analytics-status-list">

            {statusData.map(
              (item) => {

                const percentage =
                  totalAlerts > 0
                    ? Math.round(
                        (item.value /
                          totalAlerts) *
                          100
                      )
                    : 0;

                return (

                  <div
                    className="analytics-status-item"
                    key={item.name}
                  >

                    <div className="analytics-status-top">

                      <span>
                        {item.name}
                      </span>

                      <strong>
                        {formatNumber(
                          item.value
                        )}
                      </strong>

                    </div>

                    <div className="analytics-status-bar">

                      <span
                        className={
                          item.name
                            .toLowerCase()
                        }
                        style={{
                          width: `${percentage}%`,
                        }}
                      />

                    </div>

                    <small>
                      {percentage}% of all alerts
                    </small>

                  </div>

                );
              }
            )}

          </div>

        </div>

        {/* TOP SOURCES */}

        <div className="panel analytics-ranking-panel">

          <div className="panel-header">

            <div>

              <div className="dashboard-section-kicker">
                THREAT SOURCES
              </div>

              <h2 className="panel-title">
                Top Source IPs
              </h2>

              <div className="panel-subtitle">
                Sources associated with detected alerts
              </div>

            </div>

          </div>

          <div className="analytics-ranking-list">

            {sourceData.length > 0 ? (

              sourceData.map(
                (item, index) => (

                  <div
                    className="analytics-ranking-row"
                    key={`${item.name}-${index}`}
                  >

                    <span className="analytics-rank">
                      {String(
                        index + 1
                      ).padStart(2, "0")}
                    </span>

                    <div className="analytics-ranking-main">

                      <strong>
                        {item.name}
                      </strong>

                      <div className="analytics-ranking-bar">

                        <span
                          style={{
                            width: `${Math.min(
                              100,
                              totalAlerts > 0
                                ? (item.value /
                                    Math.max(
                                      ...sourceData.map(
                                        (source) =>
                                          source.value
                                      )
                                    )) *
                                    100
                                : 0
                            )}%`,
                          }}
                        />

                      </div>

                    </div>

                    <strong className="analytics-ranking-value">
                      {formatNumber(
                        item.value
                      )}
                    </strong>

                  </div>

                )
              )

            ) : (

              <div className="analytics-list-empty">
                No source IP data available.
              </div>

            )}

          </div>

        </div>

      </section>

      {/* =================================================
          DESTINATIONS
          ================================================= */}

      <section className="panel analytics-destinations-panel">

        <div className="panel-header">

          <div>

            <div className="dashboard-section-kicker">
              NETWORK TARGETS
            </div>

            <h2 className="panel-title">
              Top Destination IPs
            </h2>

            <div className="panel-subtitle">
              Destinations associated with detected network
              events
            </div>

          </div>

        </div>

        <div className="analytics-destination-grid">

          {destinationData.length > 0 ? (

            destinationData.map(
              (item, index) => (

                <div
                  className="analytics-destination-card"
                  key={`${item.name}-${index}`}
                >

                  <div className="analytics-destination-index">
                    {String(
                      index + 1
                    ).padStart(2, "0")}
                  </div>

                  <div>

                    <span>
                      DESTINATION
                    </span>

                    <strong>
                      {item.name}
                    </strong>

                  </div>

                  <div className="analytics-destination-count">

                    <strong>
                      {formatNumber(
                        item.value
                      )}
                    </strong>

                    <span>
                      events
                    </span>

                  </div>

                </div>

              )
            )

          ) : (

            <div className="analytics-list-empty">
              No destination IP data available.
            </div>

          )}

        </div>

      </section>

    </div>
  );
}

