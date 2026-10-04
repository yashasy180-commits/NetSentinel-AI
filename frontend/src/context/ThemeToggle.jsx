import { Moon, Sun } from "lucide-react";
import { useTheme } from "../context/ThemeContext";

export default function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();

  const isDark = theme === "dark";

  return (
    <button
      type="button"
      className="theme-toggle"
      onClick={toggleTheme}
      aria-label={
        isDark
          ? "Switch to light mode"
          : "Switch to dark mode"
      }
      title={
        isDark
          ? "Switch to light mode"
          : "Switch to dark mode"
      }
    >
      <span className="theme-toggle-icon">
        {isDark ? (
          <Sun size={16} strokeWidth={1.8} />
        ) : (
          <Moon size={16} strokeWidth={1.8} />
        )}
      </span>

      <span className="theme-toggle-label">
        {isDark ? "Light" : "Dark"}
      </span>
    </button>
  );
}
