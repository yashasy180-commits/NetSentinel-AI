import { useState } from "react";
import {
  Bell,
  ChevronDown,
  CircleUserRound,
  LogOut,
  ShieldCheck,
  UserRound,
} from "lucide-react";
import { Link, useNavigate } from "react-router-dom";

import { useAuth } from "../context/AuthContext";
import ThemeToggle from "../context/ThemeToggle";

export default function Navbar() {
  const { user, logout } = useAuth();

  const navigate = useNavigate();

  const [menuOpen, setMenuOpen] = useState(false);
  const [loggingOut, setLoggingOut] = useState(false);

  const handleLogout = async () => {
    if (loggingOut) return;

    try {
      setLoggingOut(true);

      await logout();

      navigate("/login", {
        replace: true,
      });
    } finally {
      setLoggingOut(false);
    }
  };

  const displayName =
    user?.username ||
    user?.name ||
    "Administrator";

  return (
    <header className="top-navbar">
      <div className="navbar-left">
        <div>
          <div className="navbar-title">
            Security Operations Center
          </div>

          <div className="navbar-subtitle">
            Intelligent network security monitoring
          </div>
        </div>
      </div>

      <div className="navbar-right">

        {/* Protected status */}
        <div className="navbar-protected-status">
          <ShieldCheck size={15} />
          Protected
        </div>

        {/* Theme toggle */}
        <ThemeToggle />

        {/* Notifications */}
        <button
          type="button"
          aria-label="Notifications"
          className="navbar-icon-button"
        >
          <Bell size={17} strokeWidth={1.8} />
        </button>

        {/* User menu */}
        <div
          style={{
            position: "relative",
          }}
        >
          <button
            type="button"
            onClick={() => setMenuOpen((value) => !value)}
            aria-expanded={menuOpen}
            className="navbar-user-button"
          >
            <CircleUserRound
              size={20}
              strokeWidth={1.7}
            />

            <span className="navbar-user-name">
              {displayName}
            </span>

            <ChevronDown
              size={14}
              style={{
                transform: menuOpen
                  ? "rotate(180deg)"
                  : "rotate(0deg)",
                transition: "transform 0.2s ease",
              }}
            />
          </button>

          {menuOpen && (
            <div className="navbar-user-menu">

              {/* Profile */}
              <Link
                to="/profile"
                onClick={() => setMenuOpen(false)}
                className="navbar-menu-item"
              >
                <UserRound size={16} />
                Profile
              </Link>

              {/* Logout */}
              <button
                type="button"
                onClick={handleLogout}
                disabled={loggingOut}
                className="navbar-menu-item navbar-logout-item"
              >
                <LogOut size={16} />

                {loggingOut
                  ? "Signing out..."
                  : "Logout"}
              </button>

            </div>
          )}
        </div>

      </div>
    </header>
  );
}
