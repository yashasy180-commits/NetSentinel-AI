import { NavLink } from "react-router-dom";
import {
  Activity,
  BarChart3,
  Bell,
  FileText,
  LayoutDashboard,
  Network,
  ScanSearch,
  Settings,
  ShieldCheck,
  Users,
} from "lucide-react";

const primaryNavigation = [
  {
    label: "Overview",
    path: "/dashboard",
    icon: LayoutDashboard,
  },
  {
    label: "Network Monitor",
    path: "/monitor",
    icon: Network,
  },
  {
    label: "Threat Detection",
    path: "/detection",
    icon: ScanSearch,
  },
  {
    label: "Alerts",
    path: "/alerts",
    icon: Bell,
  },
];

const intelligenceNavigation = [
  {
    label: "Analytics",
    path: "/analytics",
    icon: BarChart3,
  },
  {
    label: "Reports",
    path: "/reports",
    icon: FileText,
  },
];

const administrationNavigation = [
  {
    label: "Users",
    path: "/users",
    icon: Users,
  },
  {
    label: "Settings",
    path: "/settings",
    icon: Settings,
  },
];

function NavigationItem({ item }) {
  const Icon = item.icon;

  return (
    <NavLink
      to={item.path}
      className={({ isActive }) =>
        `nav-item ${isActive ? "active" : ""}`
      }
    >
      <Icon size={17} strokeWidth={1.8} />
      <span className="nav-item-label">{item.label}</span>
    </NavLink>
  );
}

function NavigationSection({ title, items }) {
  return (
    <div className="nav-section">
      <div className="nav-section-title">{title}</div>

      {items.map((item) => (
        <NavigationItem key={item.path} item={item} />
      ))}
    </div>
  );
}

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-mark">
          <ShieldCheck size={19} strokeWidth={2} />
        </div>

        <div className="brand-text">
          <span className="brand-name">NetSentinel AI</span>
          <span className="brand-label">Security Operations</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <NavigationSection
          title="Security"
          items={primaryNavigation}
        />

        <NavigationSection
          title="Intelligence"
          items={intelligenceNavigation}
        />

        <NavigationSection
          title="Administration"
          items={administrationNavigation}
        />
      </nav>

      <div className="sidebar-footer">
        <div className="system-status">
          <span className="status-dot" />

          <div className="status-text">
            <span className="status-label">System status</span>
            <span className="status-value">Operational</span>
          </div>

          <Activity
            size={15}
            color="var(--success)"
            style={{ marginLeft: "auto" }}
          />
        </div>
      </div>
    </aside>
  );
}
