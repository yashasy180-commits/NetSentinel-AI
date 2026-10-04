import React, { useEffect, useMemo, useState } from "react";
import {
  Users as UsersIcon,
  UserPlus,
  ShieldCheck,
  ShieldAlert,
  UserCheck,
  UserX,
  RefreshCw,
  Search,
  MoreVertical,
  ChevronDown,
  Activity,
  Clock3,
  X,
} from "lucide-react";

import { API_BASE_URL } from "../config";

function getToken() {
  return (
    localStorage.getItem("access_token") ||
    sessionStorage.getItem("access_token") ||
    localStorage.getItem("token") ||
    sessionStorage.getItem("token") ||
    ""
  );
}

function getAuthHeaders() {
  const token = getToken();

  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

function formatDate(value) {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function getInitials(name = "") {
  const parts = name.trim().split(/\s+/).filter(Boolean);

  if (!parts.length) return "U";

  if (parts.length === 1) {
    return parts[0].slice(0, 2).toUpperCase();
  }

  return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
}

function normalizeUsers(payload) {
  if (Array.isArray(payload)) return payload;

  if (Array.isArray(payload?.users)) return payload.users;

  if (Array.isArray(payload?.data)) return payload.data;

  return [];
}

export default function Users() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");

  const [openMenu, setOpenMenu] = useState(null);
  const [selectedUser, setSelectedUser] = useState(null);

  const [actionLoading, setActionLoading] = useState(false);
  const [toast, setToast] = useState({
    type: "",
    message: "",
  });

  const showToast = (type, message) => {
    setToast({ type, message });

    window.setTimeout(() => {
      setToast({ type: "", message: "" });
    }, 3500);
  };

  const fetchUsers = async (isRefresh = false) => {
    try {
      if (isRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError("");

      const response = await fetch(`${API_BASE}/api/admin/users`, {
        method: "GET",
        headers: getAuthHeaders(),
      });

      if (!response.ok) {
        const text = await response.text();

        let message = `Unable to load users (${response.status})`;

        try {
          const parsed = JSON.parse(text);
          message = parsed.message || parsed.error || message;
        } catch {
          // Keep default message.
        }

        throw new Error(message);
      }

      const data = await response.json();

      setUsers(normalizeUsers(data));
    } catch (err) {
      console.error("Users fetch error:", err);

      setError(
        err?.message ||
          "Unable to load users. Make sure the backend is running."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const filteredUsers = useMemo(() => {
    const query = search.trim().toLowerCase();

    return users.filter((user) => {
      const username = String(user.username || "").toLowerCase();
      const email = String(user.email || "").toLowerCase();
      const role = String(user.role || "").toUpperCase();

      const matchesSearch =
        !query ||
        username.includes(query) ||
        email.includes(query) ||
        role.toLowerCase().includes(query);

      const matchesRole =
        roleFilter === "ALL" || role === roleFilter;

      const isActive = Boolean(user.is_active);

      const matchesStatus =
        statusFilter === "ALL" ||
        (statusFilter === "ACTIVE" && isActive) ||
        (statusFilter === "INACTIVE" && !isActive);

      return matchesSearch && matchesRole && matchesStatus;
    });
  }, [users, search, roleFilter, statusFilter]);

  const statistics = useMemo(() => {
    const total = users.length;
    const active = users.filter((user) => Boolean(user.is_active)).length;
    const inactive = total - active;
    const admins = users.filter(
      (user) => String(user.role || "").toUpperCase() === "ADMIN"
    ).length;
    const analysts = users.filter(
      (user) => String(user.role || "").toUpperCase() === "ANALYST"
    ).length;

    return {
      total,
      active,
      inactive,
      admins,
      analysts,
    };
  }, [users]);

  const updateUserStatus = async (user) => {
    const nextIsActive = !Boolean(user.is_active);

    try {
      setActionLoading(true);

      const response = await fetch(
        `${API_BASE}/api/admin/users/${user.id}/status`,
        {
          method: "PATCH",
          headers: getAuthHeaders(),
          body: JSON.stringify({
            is_active: nextIsActive,
          }),
        }
      );

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(
          data.message ||
            data.error ||
            `Unable to update user status (${response.status})`
        );
      }

      setUsers((currentUsers) =>
        currentUsers.map((item) =>
          item.id === user.id
            ? {
                ...item,
                ...data,
                is_active: nextIsActive,
              }
            : item
        )
      );

      setOpenMenu(null);

      showToast(
        "success",
        `${user.username || "User"} ${
          nextIsActive ? "activated" : "deactivated"
        } successfully.`
      );
    } catch (err) {
      console.error("Status update error:", err);

      showToast(
        "error",
        err?.message || "Unable to update user status."
      );
    } finally {
      setActionLoading(false);
    }
  };

  const updateUserRole = async (user, newRole) => {
    if (!newRole || newRole === user.role) {
      setOpenMenu(null);
      return;
    }

    try {
      setActionLoading(true);

      const response = await fetch(
        `${API_BASE}/api/admin/users/${user.id}/role`,
        {
          method: "PATCH",
          headers: getAuthHeaders(),
          body: JSON.stringify({
            role: newRole,
          }),
        }
      );

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(
          data.message ||
            data.error ||
            `Unable to update user role (${response.status})`
        );
      }

      setUsers((currentUsers) =>
        currentUsers.map((item) =>
          item.id === user.id
            ? {
                ...item,
                ...data,
                role: newRole,
              }
            : item
        )
      );

      setOpenMenu(null);

      showToast(
        "success",
        `${user.username || "User"} role changed to ${newRole}.`
      );
    } catch (err) {
      console.error("Role update error:", err);

      showToast(
        "error",
        err?.message || "Unable to update user role."
      );
    } finally {
      setActionLoading(false);
    }
  };

  const clearFilters = () => {
    setSearch("");
    setRoleFilter("ALL");
    setStatusFilter("ALL");
  };

  return (
    <div className="users-page">
      <div className="users-page-header">
        <div>
          <div className="users-eyebrow">
            <ShieldCheck size={14} />
            ADMINISTRATION
          </div>

          <h1>User Management</h1>

          <p>
            Manage NetSentinel AI accounts, roles, and access status.
          </p>
        </div>

        <button
          type="button"
          className="users-refresh-button"
          onClick={() => fetchUsers(true)}
          disabled={refreshing}
        >
          <RefreshCw
            size={16}
            className={refreshing ? "users-spin" : ""}
          />
          {refreshing ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      <div className="users-stat-grid">
        <div className="users-stat-card">
          <div className="users-stat-icon blue">
            <UsersIcon size={20} />
          </div>

          <div>
            <span>Total Users</span>
            <strong>{statistics.total}</strong>
          </div>
        </div>

        <div className="users-stat-card">
          <div className="users-stat-icon green">
            <UserCheck size={20} />
          </div>

          <div>
            <span>Active Users</span>
            <strong>{statistics.active}</strong>
          </div>
        </div>

        <div className="users-stat-card">
          <div className="users-stat-icon red">
            <UserX size={20} />
          </div>

          <div>
            <span>Inactive Users</span>
            <strong>{statistics.inactive}</strong>
          </div>
        </div>

        <div className="users-stat-card">
          <div className="users-stat-icon purple">
            <ShieldCheck size={20} />
          </div>

          <div>
            <span>Administrators</span>
            <strong>{statistics.admins}</strong>
          </div>
        </div>
      </div>

      <div className="users-toolbar">
        <div className="users-search">
          <Search size={17} />

          <input
            type="text"
            placeholder="Search username, email or role..."
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />

          {search && (
            <button
              type="button"
              className="users-clear-search"
              onClick={() => setSearch("")}
              aria-label="Clear search"
            >
              <X size={15} />
            </button>
          )}
        </div>

        <div className="users-filter">
          <select
            value={roleFilter}
            onChange={(event) => setRoleFilter(event.target.value)}
          >
            <option value="ALL">All Roles</option>
            <option value="ADMIN">Admin</option>
            <option value="ANALYST">Analyst</option>
          </select>

          <ChevronDown size={15} />
        </div>

        <div className="users-filter">
          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
          >
            <option value="ALL">All Status</option>
            <option value="ACTIVE">Active</option>
            <option value="INACTIVE">Inactive</option>
          </select>

          <ChevronDown size={15} />
        </div>

        {(search || roleFilter !== "ALL" || statusFilter !== "ALL") && (
          <button
            type="button"
            className="users-reset-button"
            onClick={clearFilters}
          >
            Clear filters
          </button>
        )}
      </div>

      {error && (
        <div className="users-error">
          <ShieldAlert size={19} />

          <div>
            <strong>Unable to load users</strong>
            <span>{error}</span>
          </div>

          <button
            type="button"
            onClick={() => fetchUsers()}
          >
            Retry
          </button>
        </div>
      )}

      <div className="users-panel">
        <div className="users-panel-header">
          <div>
            <h2>System Users</h2>
            <p>
              {filteredUsers.length} of {users.length} users displayed
            </p>
          </div>

          <div className="users-security-status">
            <Activity size={15} />
            RBAC Enabled
          </div>
        </div>

        <div className="users-table-wrapper">
          {loading ? (
            <div className="users-loading">
              <RefreshCw size={22} className="users-spin" />
              <span>Loading user accounts...</span>
            </div>
          ) : filteredUsers.length === 0 ? (
            <div className="users-empty">
              <UsersIcon size={34} />
              <strong>No users found</strong>
              <span>
                Try changing your search or filter criteria.
              </span>
            </div>
          ) : (
            <table className="users-table">
              <thead>
                <tr>
                  <th>User</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Security</th>
                  <th aria-label="Actions"></th>
                </tr>
              </thead>

              <tbody>
                {filteredUsers.map((user) => {
                  const isActive = Boolean(user.is_active);
                  const role = String(
                    user.role || "ANALYST"
                  ).toUpperCase();

                  return (
                    <tr key={user.id}>
                      <td>
                        <div className="users-user-cell">
                          <div className="users-avatar">
                            {getInitials(user.username)}
                          </div>

                          <div className="users-user-details">
                            <strong>
                              {user.username || "Unknown User"}
                            </strong>

                            <span>
                              {user.email || "No email available"}
                            </span>
                          </div>
                        </div>
                      </td>

                      <td>
                        <span
                          className={`users-role-badge ${
                            role === "ADMIN"
                              ? "admin"
                              : "analyst"
                          }`}
                        >
                          <ShieldCheck size={13} />
                          {role}
                        </span>
                      </td>

                      <td>
                        <span
                          className={`users-status-badge ${
                            isActive ? "active" : "inactive"
                          }`}
                        >
                          <span className="users-status-dot"></span>
                          {isActive ? "Active" : "Inactive"}
                        </span>
                      </td>

                      <td>
                        <div className="users-created">
                          <Clock3 size={14} />
                          {formatDate(user.created_at)}
                        </div>
                      </td>

                      <td>
                        <span className="users-security-badge">
                          <ShieldCheck size={13} />
                          Protected
                        </span>
                      </td>

                      <td>
                        <div className="users-actions">
                          <button
                            type="button"
                            className="users-action-button"
                            onClick={() =>
                              setOpenMenu(
                                openMenu === user.id
                                  ? null
                                  : user.id
                              )
                            }
                            aria-label={`Actions for ${
                              user.username || "user"
                            }`}
                          >
                            <MoreVertical size={17} />
                          </button>

                          {openMenu === user.id && (
                            <div className="users-action-menu">
                              <button
                                type="button"
                                onClick={() => {
                                  setSelectedUser(user);
                                  setOpenMenu(null);
                                }}
                              >
                                <UsersIcon size={15} />
                                View details
                              </button>

                              <button
                                type="button"
                                disabled={actionLoading}
                                onClick={() =>
                                  updateUserStatus(user)
                                }
                              >
                                {isActive ? (
                                  <>
                                    <UserX size={15} />
                                    Deactivate user
                                  </>
                                ) : (
                                  <>
                                    <UserCheck size={15} />
                                    Activate user
                                  </>
                                )}
                              </button>

                              <div className="users-menu-divider"></div>

                              <div className="users-role-menu-title">
                                Change role
                              </div>

                              <button
                                type="button"
                                disabled={
                                  actionLoading ||
                                  role === "ADMIN"
                                }
                                onClick={() =>
                                  updateUserRole(
                                    user,
                                    "ADMIN"
                                  )
                                }
                              >
                                <ShieldCheck size={15} />
                                Set Admin
                              </button>

                              <button
                                type="button"
                                disabled={
                                  actionLoading ||
                                  role === "ANALYST"
                                }
                                onClick={() =>
                                  updateUserRole(
                                    user,
                                    "ANALYST"
                                  )
                                }
                              >
                                <Activity size={15} />
                                Set Analyst
                              </button>
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {selectedUser && (
        <div
          className="users-modal-overlay"
          onClick={() => setSelectedUser(null)}
        >
          <div
            className="users-modal"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="users-modal-header">
              <div>
                <span className="users-eyebrow">
                  <UserPlus size={14} />
                  ACCOUNT DETAILS
                </span>

                <h2>User Details</h2>
              </div>

              <button
                type="button"
                className="users-modal-close"
                onClick={() => setSelectedUser(null)}
                aria-label="Close"
              >
                <X size={18} />
              </button>
            </div>

            <div className="users-modal-profile">
              <div className="users-modal-avatar">
                {getInitials(selectedUser.username)}
              </div>

              <div>
                <h3>
                  {selectedUser.username || "Unknown User"}
                </h3>

                <p>
                  {selectedUser.email || "No email available"}
                </p>
              </div>
            </div>

            <div className="users-detail-grid">
              <div>
                <span>User ID</span>
                <strong>#{selectedUser.id}</strong>
              </div>

              <div>
                <span>Role</span>
                <strong>
                  {String(
                    selectedUser.role || "ANALYST"
                  ).toUpperCase()}
                </strong>
              </div>

              <div>
                <span>Account Status</span>
                <strong>
                  {selectedUser.is_active
                    ? "Active"
                    : "Inactive"}
                </strong>
              </div>

              <div>
                <span>Created</span>
                <strong>
                  {formatDate(selectedUser.created_at)}
                </strong>
              </div>
            </div>

            <div className="users-modal-footer">
              <button
                type="button"
                onClick={() => setSelectedUser(null)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {toast.message && (
        <div className={`users-toast ${toast.type}`}>
          {toast.type === "success" ? (
            <UserCheck size={17} />
          ) : (
            <ShieldAlert size={17} />
          )}

          <span>{toast.message}</span>
        </div>
      )}

      <style>{`
        .users-page {
          width: 100%;
          max-width: 1500px;
          margin: 0 auto;
          color: var(--text-primary);
        }

        .users-page-header {
          display: flex;
          align-items: flex-end;
          justify-content: space-between;
          gap: 20px;
          margin-bottom: 24px;
        }

        .users-eyebrow {
          display: inline-flex;
          align-items: center;
          gap: 7px;
          margin-bottom: 8px;
          font-size: 11px;
          font-weight: 700;
          letter-spacing: .12em;
          color: var(--accent);
        }

        .users-page-header h1 {
          margin: 0;
          font-size: 28px;
          line-height: 1.15;
          letter-spacing: -.025em;
        }

        .users-page-header p {
          margin: 8px 0 0;
          color: var(--text-secondary);
          font-size: 13px;
        }

        .users-refresh-button {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          min-height: 38px;
          padding: 0 14px;
          border: 1px solid var(--border-strong);
          border-radius: 9px;
          background: var(--bg-panel);
          color: var(--text-primary);
          cursor: pointer;
          font-size: 12px;
          font-weight: 600;
          transition: .2s ease;
        }

        .users-refresh-button:hover {
          border-color: var(--accent);
          color: var(--accent);
        }

        .users-refresh-button:disabled {
          opacity: .6;
          cursor: wait;
        }

        .users-stat-grid {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 14px;
          margin-bottom: 18px;
        }

        .users-stat-card {
          min-height: 92px;
          display: flex;
          align-items: center;
          gap: 14px;
          padding: 18px;
          border: 1px solid var(--border);
          border-radius: 12px;
          background: var(--bg-panel);
          box-shadow: var(--shadow-panel);
        }

        .users-stat-icon {
          width: 42px;
          height: 42px;
          flex: 0 0 42px;
          display: grid;
          place-items: center;
          border-radius: 10px;
        }

        .users-stat-icon.blue {
          color: #3b82f6;
          background: rgba(59, 130, 246, .11);
        }

        .users-stat-icon.green {
          color: #22c55e;
          background: rgba(34, 197, 94, .11);
        }

        .users-stat-icon.red {
          color: #ef4444;
          background: rgba(239, 68, 68, .11);
        }

        .users-stat-icon.purple {
          color: #8b5cf6;
          background: rgba(139, 92, 246, .11);
        }

        .users-stat-card div:last-child {
          min-width: 0;
        }

        .users-stat-card span {
          display: block;
          margin-bottom: 4px;
          color: var(--text-secondary);
          font-size: 11px;
        }

        .users-stat-card strong {
          display: block;
          font-size: 24px;
          line-height: 1;
          color: var(--text-primary);
        }

        .users-toolbar {
          display: flex;
          align-items: center;
          gap: 10px;
          flex-wrap: wrap;
          margin-bottom: 14px;
        }

        .users-search {
          position: relative;
          flex: 1 1 280px;
          min-width: 220px;
          height: 40px;
          display: flex;
          align-items: center;
          gap: 9px;
          padding: 0 12px;
          border: 1px solid var(--border);
          border-radius: 9px;
          background: var(--bg-panel);
          color: var(--text-muted);
        }

        .users-search input {
          width: 100%;
          border: 0;
          outline: 0;
          background: transparent;
          color: var(--text-primary);
          font: inherit;
          font-size: 12px;
        }

        .users-search input::placeholder {
          color: var(--text-muted);
        }

        .users-clear-search {
          display: grid;
          place-items: center;
          border: 0;
          background: transparent;
          color: var(--text-muted);
          cursor: pointer;
        }

        .users-filter {
          position: relative;
          height: 40px;
          min-width: 135px;
          display: flex;
          align-items: center;
          border: 1px solid var(--border);
          border-radius: 9px;
          background: var(--bg-panel);
        }

        .users-filter select {
          appearance: none;
          width: 100%;
          height: 100%;
          padding: 0 34px 0 12px;
          border: 0;
          outline: 0;
          background: transparent;
          color: var(--text-primary);
          cursor: pointer;
          font-size: 12px;
        }

        .users-filter svg {
          position: absolute;
          right: 10px;
          pointer-events: none;
          color: var(--text-muted);
        }

        .users-reset-button {
          height: 40px;
          padding: 0 12px;
          border: 1px solid var(--border);
          border-radius: 9px;
          background: transparent;
          color: var(--text-secondary);
          cursor: pointer;
          font-size: 12px;
        }

        .users-reset-button:hover {
          color: var(--accent);
          border-color: var(--accent);
        }

        .users-error {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-bottom: 14px;
          padding: 13px 15px;
          border: 1px solid rgba(239, 68, 68, .25);
          border-radius: 10px;
          background: rgba(239, 68, 68, .07);
          color: #ef4444;
        }

        .users-error div {
          flex: 1;
          display: flex;
          flex-direction: column;
          gap: 2px;
        }

        .users-error strong {
          font-size: 12px;
        }

        .users-error span {
          color: var(--text-secondary);
          font-size: 11px;
        }

        .users-error button {
          padding: 6px 10px;
          border: 1px solid rgba(239, 68, 68, .3);
          border-radius: 7px;
          background: transparent;
          color: #ef4444;
          cursor: pointer;
          font-size: 11px;
          font-weight: 600;
        }

        .users-panel {
          overflow: visible;
          border: 1px solid var(--border);
          border-radius: 14px;
          background: var(--bg-panel);
          box-shadow: var(--shadow-panel);
        }

        .users-panel-header {
          min-height: 72px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 15px;
          padding: 16px 18px;
          border-bottom: 1px solid var(--border);
        }

        .users-panel-header h2 {
          margin: 0 0 4px;
          font-size: 15px;
        }

        .users-panel-header p {
          margin: 0;
          color: var(--text-muted);
          font-size: 11px;
        }

        .users-security-status {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 6px 9px;
          border: 1px solid rgba(34, 197, 94, .2);
          border-radius: 7px;
          background: rgba(34, 197, 94, .06);
          color: #22c55e;
          font-size: 10px;
          font-weight: 700;
        }

        .users-table-wrapper {
          width: 100%;
          overflow-x: auto;
        }

        .users-table {
          width: 100%;
          min-width: 850px;
          border-collapse: collapse;
        }

        .users-table th {
          padding: 12px 16px;
          border-bottom: 1px solid var(--border);
          color: var(--text-muted);
          text-align: left;
          font-size: 10px;
          font-weight: 700;
          letter-spacing: .07em;
          text-transform: uppercase;
          white-space: nowrap;
        }

        .users-table td {
          position: relative;
          padding: 14px 16px;
          border-bottom: 1px solid var(--border);
          color: var(--text-primary);
          font-size: 12px;
          vertical-align: middle;
        }

        .users-table tbody tr:last-child td {
          border-bottom: 0;
        }

        .users-table tbody tr:hover {
          background: var(--bg-panel-hover);
        }

        .users-user-cell {
          display: flex;
          align-items: center;
          gap: 11px;
          min-width: 210px;
        }

        .users-avatar,
        .users-modal-avatar {
          display: grid;
          place-items: center;
          flex: 0 0 auto;
          border-radius: 10px;
          background: var(--accent-soft);
          color: var(--accent);
          font-weight: 700;
        }

        .users-avatar {
          width: 36px;
          height: 36px;
          font-size: 11px;
        }

        .users-user-details {
          min-width: 0;
          display: flex;
          flex-direction: column;
          gap: 3px;
        }

        .users-user-details strong {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          font-size: 12px;
        }

        .users-user-details span {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          color: var(--text-muted);
          font-size: 10px;
        }

        .users-role-badge,
        .users-status-badge,
        .users-security-badge {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          white-space: nowrap;
          font-size: 10px;
          font-weight: 700;
        }

        .users-role-badge {
          padding: 6px 8px;
          border-radius: 7px;
        }

        .users-role-badge.admin {
          color: #8b5cf6;
          background: rgba(139, 92, 246, .10);
        }

        .users-role-badge.analyst {
          color: var(--accent);
          background: var(--accent-soft);
        }

        .users-status-badge {
          gap: 7px;
        }

        .users-status-badge.active {
          color: #22c55e;
        }

        .users-status-badge.inactive {
          color: #ef4444;
        }

        .users-status-dot {
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background: currentColor;
        }

        .users-created {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          color: var(--text-secondary);
          white-space: nowrap;
          font-size: 10px;
        }

        .users-security-badge {
          color: var(--text-secondary);
        }

        .users-actions {
          position: relative;
          display: flex;
          justify-content: flex-end;
        }

        .users-action-button {
          width: 32px;
          height: 32px;
          display: grid;
          place-items: center;
          border: 1px solid transparent;
          border-radius: 7px;
          background: transparent;
          color: var(--text-muted);
          cursor: pointer;
        }

        .users-action-button:hover {
          border-color: var(--border);
          background: var(--bg-panel-hover);
          color: var(--text-primary);
        }

        .users-action-menu {
          position: absolute;
          z-index: 50;
          top: 36px;
          right: 0;
          width: 190px;
          padding: 5px;
          border: 1px solid var(--border-strong);
          border-radius: 10px;
          background: var(--bg-panel);
          box-shadow: 0 16px 40px rgba(0, 0, 0, .18);
        }

        .users-action-menu button {
          width: 100%;
          display: flex;
          align-items: center;
          gap: 9px;
          padding: 9px 10px;
          border: 0;
          border-radius: 7px;
          background: transparent;
          color: var(--text-secondary);
          cursor: pointer;
          text-align: left;
          font-size: 11px;
        }

        .users-action-menu button:hover {
          background: var(--bg-panel-hover);
          color: var(--text-primary);
        }

        .users-action-menu button:disabled {
          opacity: .45;
          cursor: not-allowed;
        }

        .users-menu-divider {
          height: 1px;
          margin: 4px 0;
          background: var(--border);
        }

        .users-role-menu-title {
          padding: 6px 10px 4px;
          color: var(--text-muted);
          font-size: 9px;
          font-weight: 700;
          letter-spacing: .08em;
          text-transform: uppercase;
        }

        .users-loading,
        .users-empty {
          min-height: 250px;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          gap: 9px;
          color: var(--text-muted);
        }

        .users-loading span,
        .users-empty span {
          font-size: 11px;
        }

        .users-empty strong {
          color: var(--text-primary);
          font-size: 13px;
        }

        .users-spin {
          animation: usersSpin .9s linear infinite;
        }

        @keyframes usersSpin {
          to {
            transform: rotate(360deg);
          }
        }

        .users-modal-overlay {
          position: fixed;
          z-index: 1000;
          inset: 0;
          display: grid;
          place-items: center;
          padding: 20px;
          background: rgba(0, 0, 0, .55);
          backdrop-filter: blur(4px);
        }

        .users-modal {
          width: min(500px, 100%);
          overflow: hidden;
          border: 1px solid var(--border-strong);
          border-radius: 16px;
          background: var(--bg-panel);
          color: var(--text-primary);
          box-shadow: 0 24px 70px rgba(0, 0, 0, .28);
        }

        .users-modal-header {
          display: flex;
          justify-content: space-between;
          gap: 15px;
          padding: 20px;
          border-bottom: 1px solid var(--border);
        }

        .users-modal-header h2 {
          margin: 0;
          font-size: 19px;
        }

        .users-modal-close {
          width: 32px;
          height: 32px;
          display: grid;
          place-items: center;
          border: 1px solid var(--border);
          border-radius: 8px;
          background: transparent;
          color: var(--text-secondary);
          cursor: pointer;
        }

        .users-modal-profile {
          display: flex;
          align-items: center;
          gap: 13px;
          padding: 20px;
        }

        .users-modal-avatar {
          width: 52px;
          height: 52px;
          font-size: 15px;
        }

        .users-modal-profile h3 {
          margin: 0 0 4px;
          font-size: 15px;
        }

        .users-modal-profile p {
          margin: 0;
          color: var(--text-muted);
          font-size: 11px;
        }

        .users-detail-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 10px;
          padding: 0 20px 20px;
        }

        .users-detail-grid > div {
          min-height: 64px;
          padding: 12px;
          border: 1px solid var(--border);
          border-radius: 9px;
          background: var(--bg-panel-hover);
        }

        .users-detail-grid span {
          display: block;
          margin-bottom: 6px;
          color: var(--text-muted);
          font-size: 9px;
          text-transform: uppercase;
          letter-spacing: .07em;
        }

        .users-detail-grid strong {
          display: block;
          color: var(--text-primary);
          font-size: 11px;
          word-break: break-word;
        }

        .users-modal-footer {
          display: flex;
          justify-content: flex-end;
          padding: 14px 20px;
          border-top: 1px solid var(--border);
        }

        .users-modal-footer button {
          min-height: 34px;
          padding: 0 13px;
          border: 1px solid var(--border);
          border-radius: 8px;
          background: var(--bg-panel-hover);
          color: var(--text-primary);
          cursor: pointer;
          font-size: 11px;
          font-weight: 600;
        }

        .users-toast {
          position: fixed;
          z-index: 2000;
          right: 22px;
          bottom: 22px;
          max-width: 380px;
          display: flex;
          align-items: center;
          gap: 9px;
          padding: 12px 14px;
          border: 1px solid var(--border-strong);
          border-radius: 10px;
          background: var(--bg-panel);
          color: var(--text-primary);
          box-shadow: 0 15px 45px rgba(0, 0, 0, .22);
          font-size: 11px;
        }

        .users-toast.success {
          border-color: rgba(34, 197, 94, .28);
        }

        .users-toast.success svg {
          color: #22c55e;
        }

        .users-toast.error {
          border-color: rgba(239, 68, 68, .28);
        }

        .users-toast.error svg {
          color: #ef4444;
        }

        @media (max-width: 1050px) {
          .users-stat-grid {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }
        }

        @media (max-width: 700px) {
          .users-page-header {
            align-items: flex-start;
            flex-direction: column;
          }

          .users-page-header h1 {
            font-size: 23px;
          }

          .users-stat-grid {
            grid-template-columns: 1fr;
          }

          .users-toolbar {
            align-items: stretch;
            flex-direction: column;
          }

          .users-search,
          .users-filter,
          .users-reset-button {
            width: 100%;
          }

          .users-panel-header {
            align-items: flex-start;
            flex-direction: column;
          }

          .users-detail-grid {
            grid-template-columns: 1fr;
          }

          .users-toast {
            right: 12px;
            bottom: 12px;
            left: 12px;
            max-width: none;
          }
        }
      `}</style>
    </div>
  );
}

