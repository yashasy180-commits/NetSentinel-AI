import React, { useState } from "react";
import {
  Settings as SettingsIcon,
  ShieldCheck,
  Activity,
  Database,
  Brain,
  Save,
  RotateCcw,
  Info,
} from "lucide-react";

export default function Settings() {
  const [threshold, setThreshold] = useState(50);
  const [monitoringEnabled, setMonitoringEnabled] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);

    window.setTimeout(() => {
      setSaved(false);
    }, 2500);
  };

  const handleReset = () => {
    setThreshold(50);
    setMonitoringEnabled(true);
    setAutoRefresh(true);
    setSaved(false);
  };

  return (
    <div className="settings-page">
      {/* Header */}
      <div className="settings-header">
        <div>
          <div className="settings-eyebrow">
            <SettingsIcon size={15} />
            SYSTEM CONFIGURATION
          </div>

          <h1>Settings</h1>

          <p>
            Configure detection, monitoring, and platform preferences.
          </p>
        </div>

        <div className="settings-protected">
          <ShieldCheck size={16} />
          Protected configuration
        </div>
      </div>

      {/* Settings Grid */}
      <div className="settings-grid">

        {/* AI Detection */}
        <section className="settings-card">
          <SectionHeader
            icon={<Brain size={19} />}
            title="AI Detection"
            subtitle="Configure the ML threat detection sensitivity."
          />

          <div className="settings-field-block">
            <div className="settings-threshold-header">
              <div>
                <div className="settings-label">
                  Detection Threshold
                </div>

                <div className="settings-hint">
                  Probability required to classify traffic as suspicious.
                </div>
              </div>

              <div className="settings-threshold-value">
                {(threshold / 100).toFixed(2)}
              </div>
            </div>

            <input
              type="range"
              min="10"
              max="90"
              step="5"
              value={threshold}
              onChange={(e) => setThreshold(Number(e.target.value))}
              className="settings-range"
            />

            <div className="settings-range-labels">
              <span>0.10 — More sensitive</span>
              <span>0.90 — More strict</span>
            </div>
          </div>

          <div className="settings-info-box">
            <Info size={17} />

            <div>
              Lower thresholds can produce more detections. Higher thresholds
              require stronger model confidence before generating a threat.
            </div>
          </div>
        </section>

        {/* Network Monitoring */}
        <section className="settings-card">
          <SectionHeader
            icon={<Activity size={19} />}
            title="Network Monitoring"
            subtitle="Control real-time monitoring preferences."
          />

          <SettingToggle
            title="Live Monitoring"
            description="Allow the monitoring engine to process observed network traffic."
            value={monitoringEnabled}
            onChange={setMonitoringEnabled}
          />

          <SettingToggle
            title="Dashboard Auto Refresh"
            description="Keep dashboard statistics updated automatically."
            value={autoRefresh}
            onChange={setAutoRefresh}
          />

          <div className="settings-monitor-state">
            <div className="settings-label">
              Current monitoring mode
            </div>

            <div
              className={`settings-monitor-status ${
                monitoringEnabled ? "enabled" : "disabled"
              }`}
            >
              <span />
              {monitoringEnabled
                ? "Monitoring enabled"
                : "Monitoring disabled"}
            </div>
          </div>
        </section>

        {/* Database */}
        <section className="settings-card">
          <SectionHeader
            icon={<Database size={19} />}
            title="Database"
            subtitle="Current persistence configuration."
          />

          <InfoRow label="Database Engine" value="SQLite" />
          <InfoRow label="Connection" value="Local database" />
          <InfoRow
            label="Migration Ready"
            value="PostgreSQL compatible design"
          />
          <InfoRow
            label="Storage"
            value="NetSentinel database"
          />
        </section>

        {/* Security Platform */}
        <section className="settings-card">
          <SectionHeader
            icon={<ShieldCheck size={19} />}
            title="Security Platform"
            subtitle="Application security configuration."
          />

          <InfoRow label="Authentication" value="JWT" />
          <InfoRow
            label="Authorization"
            value="Role Based Access Control"
          />
          <InfoRow label="Password Security" value="Hashed" />
          <InfoRow label="Audit Logging" value="Enabled" />
        </section>

        {/* ML Model */}
        <section className="settings-card">
          <SectionHeader
            icon={<Brain size={19} />}
            title="ML Model"
            subtitle="Current AI engine information."
          />

          <InfoRow label="Model Type" value="Random Forest" />
          <InfoRow
            label="Purpose"
            value="Network intrusion detection"
          />
          <InfoRow label="Inference" value="Enabled" />
          <InfoRow label="Blocking" value="Disabled by default" />
        </section>

        {/* Configuration Summary */}
        <section className="settings-card">
          <SectionHeader
            icon={<SettingsIcon size={19} />}
            title="Configuration Summary"
            subtitle="Current values used by this page."
          />

          <InfoRow
            label="Detection Threshold"
            value={(threshold / 100).toFixed(2)}
          />

          <InfoRow
            label="Live Monitoring"
            value={monitoringEnabled ? "Enabled" : "Disabled"}
          />

          <InfoRow
            label="Auto Refresh"
            value={autoRefresh ? "Enabled" : "Disabled"}
          />

          <div className="settings-session-note">
            Changes on this page are maintained in the current UI session.
          </div>
        </section>
      </div>

      {/* Actions */}
      <div className="settings-actions">
        <button
          type="button"
          onClick={handleReset}
          className="settings-secondary-button"
        >
          <RotateCcw size={16} />
          Reset
        </button>

        <button
          type="button"
          onClick={handleSave}
          className="settings-primary-button"
        >
          <Save size={16} />
          {saved ? "Saved" : "Save Changes"}
        </button>
      </div>

      {saved && (
        <div className="settings-save-message">
          Settings saved for the current session.
        </div>
      )}
    </div>
  );
}

function SectionHeader({ icon, title, subtitle }) {
  return (
    <div className="settings-section-header">
      <div className="settings-section-title">
        {icon}
        <h2>{title}</h2>
      </div>

      <p>{subtitle}</p>
    </div>
  );
}

function SettingToggle({
  title,
  description,
  value,
  onChange,
}) {
  return (
    <div className="settings-toggle-row">
      <div>
        <div className="settings-label">{title}</div>

        <div className="settings-hint settings-toggle-description">
          {description}
        </div>
      </div>

      <button
        type="button"
        onClick={() => onChange(!value)}
        aria-pressed={value}
        className={`settings-toggle ${
          value ? "active" : "inactive"
        }`}
      >
        <span />
      </button>
    </div>
  );
}

function InfoRow({ label, value }) {
  return (
    <div className="settings-info-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
