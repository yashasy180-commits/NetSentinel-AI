import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";

import { useAuth } from "./context/AuthContext";

import Sidebar from "./components/Sidebar";
import Navbar from "./components/Navbar";

import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import NetworkMonitor from "./pages/NetworkMonitor";
import Alerts from "./pages/Alerts";
import Analytics from "./pages/Analytics";
import ThreatDetection from "./pages/ThreatDetection";
import Reports from "./pages/Reports";
import Users from "./pages/Users";
import Settings from "./pages/Settings";
import Profile from "./pages/Profile";


/* =========================================================
   PROTECTED ROUTE
   ========================================================= */

function ProtectedRoute({ children }) {
  const {
    user,
    loading,
  } = useAuth();

  if (loading) {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#080d13",
          color: "#8ea4bd",
          fontFamily: "Arial, sans-serif",
          fontSize: "13px",
        }}
      >
        Loading security console...
      </div>
    );
  }

  if (!user) {
    return (
      <Navigate
        to="/login"
        replace
      />
    );
  }

  return children;
}


/* =========================================================
   APPLICATION LAYOUT
   ========================================================= */

function AppLayout() {
  return (
    <div className="app-shell">

      <Sidebar />

      <div className="app-main">

        <Navbar />

        <main className="page-content">

          <Routes>

            {/* Dashboard */}
            <Route
              path="/dashboard"
              element={<Dashboard />}
            />

            {/* Network Monitoring */}
            <Route
              path="/monitor"
              element={<NetworkMonitor />}
            />

            {/* Threat Detection */}
            <Route
              path="/detection"
              element={<ThreatDetection />}
            />

            {/* Alerts */}
            <Route
              path="/alerts"
              element={<Alerts />}
            />

            {/* Analytics */}
            <Route
              path="/analytics"
              element={<Analytics />}
            />

            {/* Reports */}
            <Route
              path="/reports"
              element={<Reports />}
            />

            {/* Users */}
            <Route
              path="/users"
              element={<Users />}
            />

            {/* Settings */}
            <Route
              path="/settings"
              element={<Settings />}
            />

            {/* Profile */}
            <Route
              path="/profile"
              element={<Profile />}
            />

            {/* Unknown protected route */}
            <Route
              path="*"
              element={
                <Navigate
                  to="/dashboard"
                  replace
                />
              }
            />

          </Routes>

        </main>

      </div>

    </div>
  );
}


/* =========================================================
   MAIN APPLICATION
   ========================================================= */

function App() {
  const {
    user,
    loading,
  } = useAuth();

  if (loading) {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#080d13",
          color: "#8ea4bd",
          fontFamily: "Arial, sans-serif",
          fontSize: "13px",
        }}
      >
        Loading NetSentinel AI...
      </div>
    );
  }

  return (
    <BrowserRouter>

      <Routes>

        {/* =================================================
            LOGIN
            ================================================= */}

        <Route
          path="/login"
          element={
            user ? (
              <Navigate
                to="/dashboard"
                replace
              />
            ) : (
              <Login />
            )
          }
        />

        {/* =================================================
            REGISTER
            ================================================= */}

        <Route
          path="/register"
          element={<Register />}
        />

        {/* =================================================
            PROTECTED APPLICATION
            ================================================= */}

        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <AppLayout />
            </ProtectedRoute>
          }
        />

      </Routes>

    </BrowserRouter>
  );
}


export default App;
