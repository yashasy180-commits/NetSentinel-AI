import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  ArrowLeft,
  CheckCircle2,
  Eye,
  EyeOff,
  LockKeyhole,
  Mail,
  ShieldCheck,
  User,
} from "lucide-react";
import api from "../services/api";
import "../styles/register.css";

export default function Register() {
  const navigate = useNavigate();

  const [form, setForm] = useState({
    username: "",
    email: "",
    password: "",
    confirmPassword: "",
  });

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleChange = (event) => {
    const { name, value } = event.target;

    setForm((current) => ({
      ...current,
      [name]: value,
    }));

    if (error) setError("");
  };

  const handleSubmit = async (event) => {
    event.preventDefault();

    setError("");
    setSuccess("");

    const username = form.username.trim();
    const email = form.email.trim();

    if (!username || !email || !form.password || !form.confirmPassword) {
      setError("Please complete all required fields.");
      return;
    }

    if (form.password !== form.confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    if (form.password.length < 8) {
      setError("Password must contain at least 8 characters.");
      return;
    }

    try {
      setLoading(true);

      const response = await api.post("/auth/register", {
        username,
        email,
        password: form.password,
      });

      const data = response.data;

      if (!data.success) {
        throw new Error(data.message || "Registration failed.");
      }

      setSuccess(
        data.message ||
          "Account created successfully. You can now sign in."
      );

      setForm({
        username: "",
        email: "",
        password: "",
        confirmPassword: "",
      });

      setTimeout(() => {
        navigate("/login");
      }, 1400);
    } catch (err) {
      const message =
        err?.response?.data?.message ||
        err?.response?.data?.error ||
        err?.message ||
        "Unable to create account.";

      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="register-page">
      <div className="register-background-grid" />

      <div className="register-shell">
        <section className="register-brand-panel">
          <div className="register-brand">
            <div className="register-logo">
              <ShieldCheck size={25} strokeWidth={2} />
            </div>

            <div>
              <strong>NetSentinel</strong>
              <span>AI SECURITY PLATFORM</span>
            </div>
          </div>

          <div className="register-brand-content">
            <div className="register-eyebrow">
              <span />
              SECURE ACCESS
            </div>

            <h1>
              Create your
              <br />
              <span>security profile.</span>
            </h1>

            <p>
              Join the NetSentinel security console and monitor,
              investigate, and analyze network threats from one
              centralized workspace.
            </p>

            <div className="register-features">
              <div>
                <CheckCircle2 size={17} />
                <span>AI-powered threat detection</span>
              </div>

              <div>
                <CheckCircle2 size={17} />
                <span>Real-time network monitoring</span>
              </div>

              <div>
                <CheckCircle2 size={17} />
                <span>Security analytics and reporting</span>
              </div>
            </div>
          </div>

          <div className="register-brand-footer">
            <span>NETSENTINEL AI</span>
            <span>SECURITY OPERATIONS PLATFORM</span>
          </div>
        </section>

        <section className="register-form-panel">
          <div className="register-form-container">
            <Link to="/login" className="register-back">
              <ArrowLeft size={16} />
              Back to sign in
            </Link>

            <div className="register-heading">
              <div className="register-mobile-logo">
                <ShieldCheck size={22} />
              </div>

              <div className="register-eyebrow">
                <span />
                ACCOUNT REGISTRATION
              </div>

              <h2>Create account</h2>

              <p>
                Set up your analyst profile to access the NetSentinel
                security console.
              </p>
            </div>

            <form onSubmit={handleSubmit} className="register-form">
              <div className="register-field">
                <label htmlFor="username">USERNAME</label>

                <div className="register-input-wrap">
                  <User size={17} />

                  <input
                    id="username"
                    name="username"
                    type="text"
                    placeholder="Enter username"
                    value={form.username}
                    onChange={handleChange}
                    autoComplete="username"
                    disabled={loading}
                  />
                </div>
              </div>

              <div className="register-field">
                <label htmlFor="email">EMAIL ADDRESS</label>

                <div className="register-input-wrap">
                  <Mail size={17} />

                  <input
                    id="email"
                    name="email"
                    type="email"
                    placeholder="you@example.com"
                    value={form.email}
                    onChange={handleChange}
                    autoComplete="email"
                    disabled={loading}
                  />
                </div>
              </div>

              <div className="register-field">
                <label htmlFor="password">PASSWORD</label>

                <div className="register-input-wrap">
                  <LockKeyhole size={17} />

                  <input
                    id="password"
                    name="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="Create a secure password"
                    value={form.password}
                    onChange={handleChange}
                    autoComplete="new-password"
                    disabled={loading}
                  />

                  <button
                    type="button"
                    className="password-toggle"
                    onClick={() => setShowPassword((value) => !value)}
                    aria-label={
                      showPassword
                        ? "Hide password"
                        : "Show password"
                    }
                  >
                    {showPassword ? (
                      <EyeOff size={17} />
                    ) : (
                      <Eye size={17} />
                    )}
                  </button>
                </div>
              </div>

              <div className="register-field">
                <label htmlFor="confirmPassword">
                  CONFIRM PASSWORD
                </label>

                <div className="register-input-wrap">
                  <LockKeyhole size={17} />

                  <input
                    id="confirmPassword"
                    name="confirmPassword"
                    type={showConfirmPassword ? "text" : "password"}
                    placeholder="Confirm your password"
                    value={form.confirmPassword}
                    onChange={handleChange}
                    autoComplete="new-password"
                    disabled={loading}
                  />

                  <button
                    type="button"
                    className="password-toggle"
                    onClick={() =>
                      setShowConfirmPassword((value) => !value)
                    }
                    aria-label={
                      showConfirmPassword
                        ? "Hide password"
                        : "Show password"
                    }
                  >
                    {showConfirmPassword ? (
                      <EyeOff size={17} />
                    ) : (
                      <Eye size={17} />
                    )}
                  </button>
                </div>
              </div>

              <div className="register-role-note">
                <ShieldCheck size={16} />

                <div>
                  <strong>Analyst access</strong>
                  <span>
                    New accounts are created with Analyst privileges.
                  </span>
                </div>
              </div>

              {error && (
                <div className="register-message register-error">
                  <span />
                  {error}
                </div>
              )}

              {success && (
                <div className="register-message register-success">
                  <CheckCircle2 size={16} />
                  {success}
                </div>
              )}

              <button
                type="submit"
                className="register-submit"
                disabled={loading}
              >
                {loading ? (
                  <>
                    <span className="register-spinner" />
                    Creating account...
                  </>
                ) : (
                  <>
                    Create account
                    <ArrowLeft
                      size={17}
                      className="register-arrow"
                    />
                  </>
                )}
              </button>
            </form>

            <div className="register-login-link">
              Already have an account?
              <Link to="/login">Sign in</Link>
            </div>

            <div className="register-security-footer">
              <LockKeyhole size={13} />
              <span>Protected by NetSentinel security controls</span>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
