import React, { useEffect, useState } from "react";
import {
  User,
  Mail,
  Shield,
  Calendar,
  CheckCircle,
  XCircle,
  Lock,
  Activity,
} from "lucide-react";

import { API_BASE } from "../config";

export default function Profile() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    loadProfile();
  }, []);

  async function loadProfile() {
    try {
      setLoading(true);
      setError("");

      const token =
        localStorage.getItem("access_token") ||
        localStorage.getItem("token") ||
        sessionStorage.getItem("access_token") ||
        sessionStorage.getItem("token");

      if (!token) {
        setError("Authentication session not found.");
        return;
      }

      const response = await fetch(`${API_BASE}/users/me`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data?.message ||
            data?.error ||
            "Unable to load profile."
        );
      }

      const profile =
        data?.user ||
        data?.data ||
        data;

      setUser(profile);
    } catch (err) {
      console.error("Profile loading error:", err);
      setError(
        err.message ||
          "Unable to load profile."
      );
    } finally {
      setLoading(false);
    }
  }

  const displayName =
    user?.username ||
    user?.name ||
    user?.full_name ||
    "User";

  const email =
    user?.email ||
    "Not available";

  const role =
    user?.role ||
    "ANALYST";

  const isActive =
    user?.is_active === undefined
      ? true
      : Boolean(user.is_active);

  const createdAt =
    user?.created_at ||
    user?.createdAt ||
    null;

  function formatDate(value) {
    if (!value) {
      return "Not available";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return value;
    }

    return date.toLocaleDateString(
      "en-IN",
      {
        day: "2-digit",
        month: "short",
        year: "numeric",
      }
    );
  }

  if (loading) {
    return (
      <div className="profile-page">
        <div className="profile-loading">
          <Activity size={22} />
          <span>Loading profile...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="profile-page">
        <div className="profile-error">
          <XCircle size={24} />

          <div>
            <div className="profile-error-title">
              Unable to load profile
            </div>

            <div className="profile-error-text">
              {error}
            </div>

            <button
              type="button"
              onClick={loadProfile}
              className="profile-retry-button"
            >
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="profile-page">

      {/* Header */}
      <div className="profile-header">
        <div>
          <div className="profile-eyebrow">
            ACCOUNT
          </div>

          <h1>Profile</h1>

          <p>
            View your NetSentinel AI account and security information.
          </p>
        </div>

        <div
          className={`profile-status-badge ${
            isActive ? "active" : "inactive"
          }`}
        >
          <span />
          Account {isActive ? "Active" : "Inactive"}
        </div>
      </div>

      {/* Main Profile */}
      <div className="profile-main-card">
        <div className="profile-top">
          <div className="profile-avatar">
            {displayName.charAt(0).toUpperCase()}
          </div>

          <div className="profile-identity">
            <h2>{displayName}</h2>

            <div className="profile-email">
              <Mail size={15} />
              {email}
            </div>

            <div className="profile-role">
              <Shield size={14} />
              {role}
            </div>
          </div>
        </div>
      </div>

      {/* Information Cards */}
      <div className="profile-grid">

        <InfoCard
          icon={<User size={20} />}
          title="Username"
          value={displayName}
        />

        <InfoCard
          icon={<Mail size={20} />}
          title="Email Address"
          value={email}
        />

        <InfoCard
          icon={<Shield size={20} />}
          title="Account Role"
          value={role}
        />

        <InfoCard
          icon={
            isActive ? (
              <CheckCircle size={20} />
            ) : (
              <XCircle size={20} />
            )
          }
          title="Account Status"
          value={
            isActive
              ? "Active"
              : "Inactive"
          }
          valueClass={
            isActive
              ? "success"
              : "danger"
          }
        />

        <InfoCard
          icon={<Calendar size={20} />}
          title="Member Since"
          value={formatDate(createdAt)}
        />

        <InfoCard
          icon={<Lock size={20} />}
          title="Authentication"
          value="JWT Protected"
        />
      </div>

      {/* Security Information */}
      <div className="profile-security-card">
        <div className="profile-security-icon">
          <Shield size={22} />
        </div>

        <div>
          <div className="profile-security-title">
            Account Security
          </div>

          <div className="profile-security-text">
            Your account is protected by JWT-based authentication
            and role-based access control.
          </div>
        </div>
      </div>
    </div>
  );
}

function InfoCard({
  icon,
  title,
  value,
  valueClass = "",
}) {
  return (
    <div className="profile-info-card">
      <div className="profile-info-icon">
        {icon}
      </div>

      <div className="profile-info-content">
        <div className="profile-info-title">
          {title}
        </div>

        <div
          className={`profile-info-value ${valueClass}`}
        >
          {value}
        </div>
      </div>
    </div>
  );
}

