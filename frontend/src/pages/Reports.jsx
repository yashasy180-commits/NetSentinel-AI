import { useEffect, useState } from "react";
import {
  FileText,
  FileSpreadsheet,
  Download,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  RefreshCw,
  Filter,
  CalendarDays,
  BarChart3,
} from "lucide-react";

import api from "../services/api";
import { auth } from "../services/auth";

export default function Reports() {
  const [statistics, setStatistics] = useState({
    total: 0,
    open: 0,
    acknowledged: 0,
    resolved: 0,
  });

  const [format, setFormat] = useState("pdf");
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");

  const [loading, setLoading] = useState(false);
  const [statsLoading, setStatsLoading] = useState(true);
  const [message, setMessage] = useState("");

  /* =========================================================
     AUTH HEADER
     ========================================================= */

  const getAuthConfig = () => {
    const token = auth.getToken();

    return {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    };
  };

  /* =========================================================
     LOAD REPORT STATISTICS
     ========================================================= */

  const loadStatistics = async () => {
    try {
      setStatsLoading(true);

      const response = await api.get(
        "/analytics/dashboard",
        getAuthConfig()
      );

      const analytics =
        response.data?.analytics || {};

      const overview =
        analytics.overview || {};

      setStatistics({
        total: Number(
          overview.total_alerts ?? 0
        ),

        open: Number(
          overview.active_alerts ??
            overview.open_alerts ??
            0
        ),

        acknowledged: Number(
          overview.acknowledged_alerts ??
            0
        ),

        resolved: Number(
          overview.resolved_alerts ??
            0
        ),
      });
    } catch (error) {
      console.error(
        "Failed to load report statistics:",
        error
      );

      /* Fallback to alert statistics */
      try {
        const response = await api.get(
          "/alerts/statistics",
          getAuthConfig()
        );

        const data =
          response.data?.statistics ||
          response.data?.data ||
          {};

        setStatistics({
          total: Number(
            data.total ??
              data.total_alerts ??
              0
          ),

          open: Number(
            data.open ??
              data.open_alerts ??
              data.active_alerts ??
              0
          ),

          acknowledged: Number(
            data.acknowledged ??
              data.acknowledged_alerts ??
              0
          ),

          resolved: Number(
            data.resolved ??
              data.resolved_alerts ??
              0
          ),
        });
      } catch (fallbackError) {
        console.error(
          "Statistics fallback failed:",
          fallbackError
        );
      }
    } finally {
      setStatsLoading(false);
    }
  };

  /* =========================================================
     INITIAL LOAD
     ========================================================= */

  useEffect(() => {
    loadStatistics();
  }, []);

  /* =========================================================
     GENERATE REPORT
     ========================================================= */

  const generateReport = async () => {
    try {
      setLoading(true);
      setMessage("");

      const endpoint =
        format === "pdf"
          ? "/reports/pdf"
          : "/reports/csv";

      const params = {};

      if (status) {
        params.status = status;
      }

      if (severity) {
        params.severity = severity;
      }

      const token = auth.getToken();

      if (!token) {
        setMessage(
          "Your session has expired. Please log in again."
        );
        return;
      }

      const response = await api.get(
        endpoint,
        {
          params,

          responseType: "blob",

          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      /*
       * If the backend returns an error while using
       * responseType="blob", Axios gives us a Blob.
       *
       * Check the content type before treating it
       * as a real PDF/CSV file.
       */

      const contentType =
        response.headers["content-type"] || "";

      if (
        contentType.includes("application/json")
      ) {
        const text =
          await response.data.text();

        let errorMessage =
          "Unable to generate the security report.";

        try {
          const errorData =
            JSON.parse(text);

          errorMessage =
            errorData.message ||
            errorMessage;
        } catch {
          // Keep default message.
        }

        throw new Error(errorMessage);
      }

      const blob = new Blob(
        [response.data],
        {
          type:
            format === "pdf"
              ? "application/pdf"
              : "text/csv",
        }
      );

      const url =
        window.URL.createObjectURL(blob);

      const extension =
        format === "pdf"
          ? "pdf"
          : "csv";

      const timestamp =
        new Date()
          .toISOString()
          .replace(/[:.]/g, "-");

      const filename =
        `netsentinel-security-report-${timestamp}.${extension}`;

      const link =
        document.createElement("a");

      link.href = url;
      link.download = filename;

      document.body.appendChild(link);

      link.click();

      link.remove();

      window.URL.revokeObjectURL(url);

      setMessage(
        `${format.toUpperCase()} security report generated successfully.`
      );
    } catch (error) {
      console.error(
        "Report generation failed:",
        error
      );

      setMessage(
        error?.message ||
          "Unable to generate the security report."
      );
    } finally {
      setLoading(false);
    }
  };

  /* =========================================================
     CLEAR FILTERS
     ========================================================= */

  const clearFilters = () => {
    setStatus("");
    setSeverity("");
    setMessage("");
  };

  /* =========================================================
     UI
     ========================================================= */

  return (
    <div className="reports-page">

      {/* HEADER */}
      <div className="reports-header">

        <div>

          <div className="reports-eyebrow">
            <span className="status-dot" />
            SECURITY REPORTING
          </div>

          <h1>
            Security Reports
          </h1>

          <p>
            Generate, filter and export security
            intelligence from the NetSentinel AI
            detection platform.
          </p>

        </div>

        <div className="reports-header-actions">

          <div className="reports-updated">
            <Clock3 size={14} />
            <span>
              Live security data
            </span>
          </div>

          <button
            className="reports-refresh-btn"
            onClick={loadStatistics}
            disabled={statsLoading}
          >
            <RefreshCw
              size={15}
              className={
                statsLoading
                  ? "spin"
                  : ""
              }
            />

            Refresh
          </button>

        </div>

      </div>


      {/* SUMMARY CARDS */}
      <section className="reports-summary-grid">

        {/* TOTAL */}
        <div className="report-stat-card">

          <div className="report-stat-icon blue">
            <ShieldCheck size={19} />
          </div>

          <div>

            <span>
              Total Alerts
            </span>

            <strong>
              {statsLoading
                ? "—"
                : statistics.total}
            </strong>

            <small>
              Recorded security events
            </small>

          </div>

        </div>


        {/* OPEN */}
        <div className="report-stat-card">

          <div className="report-stat-icon red">
            <AlertTriangle size={19} />
          </div>

          <div>

            <span>
              Open Threats
            </span>

            <strong>
              {statsLoading
                ? "—"
                : statistics.open}
            </strong>

            <small>
              Currently unresolved
            </small>

          </div>

        </div>


        {/* ACKNOWLEDGED */}
        <div className="report-stat-card">

          <div className="report-stat-icon amber">
            <Clock3 size={19} />
          </div>

          <div>

            <span>
              Acknowledged
            </span>

            <strong>
              {statsLoading
                ? "—"
                : statistics.acknowledged}
            </strong>

            <small>
              Reviewed by analysts
            </small>

          </div>

        </div>


        {/* RESOLVED */}
        <div className="report-stat-card">

          <div className="report-stat-icon green">
            <CheckCircle2 size={19} />
          </div>

          <div>

            <span>
              Resolved
            </span>

            <strong>
              {statsLoading
                ? "—"
                : statistics.resolved}
            </strong>

            <small>
              Successfully closed
            </small>

          </div>

        </div>

      </section>


      {/* REPORT GENERATOR */}
      <section className="report-generator">

        <div className="section-heading">

          <div className="section-heading-icon">
            <FileText size={18} />
          </div>

          <div>

            <h2>
              Generate Security Report
            </h2>

            <p>
              Export alert intelligence using
              the selected filters.
            </p>

          </div>

        </div>


        <div className="report-generator-body">

          {/* FORMAT */}
          <div className="report-field">

            <label>
              Report Format
            </label>

            <div className="format-selector">

              {/* PDF */}
              <button
                type="button"
                className={`format-option ${
                  format === "pdf"
                    ? "active"
                    : ""
                }`}
                onClick={() =>
                  setFormat("pdf")
                }
              >

                <FileText size={18} />

                <div>

                  <strong>
                    PDF Report
                  </strong>

                  <span>
                    Formatted security document
                  </span>

                </div>

                {format === "pdf" && (
                  <CheckCircle2 size={16} />
                )}

              </button>


              {/* CSV */}
              <button
                type="button"
                className={`format-option ${
                  format === "csv"
                    ? "active"
                    : ""
                }`}
                onClick={() =>
                  setFormat("csv")
                }
              >

                <FileSpreadsheet size={18} />

                <div>

                  <strong>
                    CSV Export
                  </strong>

                  <span>
                    Structured data for analysis
                  </span>

                </div>

                {format === "csv" && (
                  <CheckCircle2 size={16} />
                )}

              </button>

            </div>

          </div>


          {/* FILTERS */}
          <div className="report-filter-row">

            {/* STATUS */}
            <div className="report-field">

              <label>
                <Filter size={13} />
                Alert Status
              </label>

              <select
                value={status}
                onChange={(event) =>
                  setStatus(
                    event.target.value
                  )
                }
              >

                <option value="">
                  All statuses
                </option>

                <option value="OPEN">
                  Open
                </option>

                <option value="ACKNOWLEDGED">
                  Acknowledged
                </option>

                <option value="RESOLVED">
                  Resolved
                </option>

              </select>

            </div>


            {/* SEVERITY */}
            <div className="report-field">

              <label>
                <AlertTriangle size={13} />
                Severity
              </label>

              <select
                value={severity}
                onChange={(event) =>
                  setSeverity(
                    event.target.value
                  )
                }
              >

                <option value="">
                  All severities
                </option>

                <option value="CRITICAL">
                  Critical
                </option>

                <option value="HIGH">
                  High
                </option>

                <option value="MEDIUM">
                  Medium
                </option>

                <option value="LOW">
                  Low
                </option>

              </select>

            </div>


            {/* SCOPE */}
            <div className="report-field">

              <label>
                <CalendarDays size={13} />
                Reporting Scope
              </label>

              <div className="scope-display">
                <span>
                  Available security events
                </span>
              </div>

            </div>

          </div>


          {/* ACTIONS */}
          <div className="report-actions">

            <button
              type="button"
              className="clear-report-btn"
              onClick={clearFilters}
            >
              Clear Filters
            </button>

            <button
              type="button"
              className="generate-report-btn"
              onClick={generateReport}
              disabled={loading}
            >

              {loading ? (
                <>
                  <RefreshCw
                    size={16}
                    className="spin"
                  />

                  Generating...
                </>
              ) : (
                <>
                  <Download size={16} />

                  Generate{" "}
                  {format.toUpperCase()} Report
                </>
              )}

            </button>

          </div>


          {/* MESSAGE */}
          {message && (
            <div
              className={`report-message ${
                message
                  .toLowerCase()
                  .includes("success")
                  ? "success"
                  : "error"
              }`}
            >
              {message}
            </div>
          )}

        </div>

      </section>


      {/* INFORMATION */}
      <section className="report-info-grid">

        <div className="report-info-card">

          <div className="report-info-icon">
            <BarChart3 size={18} />
          </div>

          <div>

            <h3>
              Security Intelligence
            </h3>

            <p>
              Reports are generated from
              security events and alerts
              collected by the NetSentinel AI
              detection pipeline.
            </p>

          </div>

        </div>


        <div className="report-info-card">

          <div className="report-info-icon">
            <ShieldCheck size={18} />
          </div>

          <div>

            <h3>
              Audit-Ready Output
            </h3>

            <p>
              Use PDF reports for documentation
              and CSV exports for investigation,
              analysis or archival.
            </p>

          </div>

        </div>

      </section>

    </div>
  );
}
