import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import {
  Activity,
  ArrowRight,
  Eye,
  EyeOff,
  LockKeyhole,
  ShieldCheck,
  UserRound,
} from "lucide-react";

import { useAuth } from "../context/AuthContext";
import "../styles/login.css";

export default function Login() {
  const { login, isAuthenticated, loading } = useAuth();

  const navigate = useNavigate();
  const location = useLocation();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (isAuthenticated) {
      const destination = location.state?.from?.pathname || "/dashboard";
      navigate(destination, { replace: true });
    }
  }, [isAuthenticated, navigate, location.state]);

  if (loading) {
    return (
      <div className="ns-login-loading">
        <div className="ns-loading-spinner" />
        <span>Initializing secure session...</span>
      </div>
    );
  }

  if (isAuthenticated) {
    return null;
  }

  const handleSubmit = async (event) => {
    event.preventDefault();

    setError("");

    if (!username.trim() || !password) {
      setError("Enter your username and password.");
      return;
    }

    try {
      setSubmitting(true);

      await login(username.trim(), password);
    } catch (err) {
      const message =
        err?.response?.data?.message ||
        err?.response?.data?.error ||
        err?.message ||
        "Authentication failed. Please verify your credentials.";

      setError(message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="ns-login-page">
      <div className="ns-login-grid" />

      <div className="ns-login-shell">
        {/* Brand / security panel */}
        <section className="ns-login-brand">
          <div className="ns-brand-top">
            <div className="ns-brand-mark">
              <ShieldCheck size={24} strokeWidth={2.2} />
            </div>

            <div>
              <div className="ns-brand-name">NetSentinel AI</div>
              <div className="ns-brand-product">
                Network Security Operations
              </div>
            </div>
          </div>

          <div className="ns-brand-content">
            <div className="ns-live-indicator">
              <span />
              Security platform operational
            </div>

            <h1>
              Intelligent network
              <br />
              <span>threat detection.</span>
            </h1>

            <p>
              Monitor network activity, detect suspicious behavior and
              investigate security events from a unified security console.
            </p>
          </div>

          <div className="ns-security-panel">
            <div className="ns-security-icon">
              <Activity size={19} />
            </div>

            <div>
              <strong>AI detection engine</strong>
              <span>
                Real-time traffic analysis and intrusion detection
              </span>
            </div>

            <div className="ns-security-status">ACTIVE</div>
          </div>

          <div className="ns-brand-footer">
            <span>NETSENTINEL AI</span>
            <span>•</span>
            <span>SECURE ACCESS</span>
          </div>
        </section>

        {/* Login panel */}
        <section className="ns-login-card">
          <div className="ns-login-card-header">
            <div className="ns-mobile-brand">
              <div className="ns-brand-mark">
                <ShieldCheck size={21} />
              </div>
              <span>NetSentinel AI</span>
            </div>

            <div className="ns-auth-badge">
              <LockKeyhole size={14} />
              Secure authentication
            </div>

            <h2>Welcome back</h2>

            <p>
              Sign in to access the Security Operations Center.
            </p>
          </div>

          <form className="ns-login-form" onSubmit={handleSubmit}>
            {error && (
              <div className="ns-login-error">
                <div className="ns-error-dot" />
                <span>{error}</span>
              </div>
            )}

            <div className="ns-field">
              <label htmlFor="username">Username</label>

              <div className="ns-input-wrapper">
                <UserRound size={18} />

                <input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  placeholder="Enter your username"
                  autoComplete="username"
                  disabled={submitting}
                />
              </div>
            </div>

            <div className="ns-field">
              <label htmlFor="password">Password</label>

              <div className="ns-input-wrapper">
                <LockKeyhole size={18} />

                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="Enter your password"
                  autoComplete="current-password"
                  disabled={submitting}
                />

                <button
                  type="button"
                  className="ns-password-toggle"
                  onClick={() => setShowPassword((value) => !value)}
                  aria-label={
                    showPassword ? "Hide password" : "Show password"
                  }
                  disabled={submitting}
                >
                  {showPassword ? (
                    <EyeOff size={17} />
                  ) : (
                    <Eye size={17} />
                  )}
                </button>
              </div>
            </div>

            <button
              className="ns-login-submit"
              type="submit"
              disabled={submitting}
            >
              {submitting ? (
                <>
                  <span className="ns-button-spinner" />
                  Authenticating...
                </>
              ) : (
                <>
                  Sign in
                  <ArrowRight size={18} />
                </>
              )}
            </button>
          </form>

          {/* Registration option */}
          <div className="ns-login-register">
            <span>Don't have an account?</span>

            <Link to="/register">
              Create an account
              <ArrowRight size={14} />
            </Link>
          </div>

          <div className="ns-login-security">
            <div className="ns-security-line">
              <ShieldCheck size={16} />
              <span>Protected connection</span>
            </div>

            <p>
              Access is restricted to authorized NetSentinel AI personnel.
            </p>
          </div>

          <div className="ns-login-meta">
            <span>NetSentinel AI</span>
            <span>v1.0</span>
          </div>
        </section>
      </div>
    </div>
  );
}
