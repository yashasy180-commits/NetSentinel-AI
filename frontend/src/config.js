export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";

export const API_BASE = `${API_BASE_URL}/api`;

export const SOCKET_URL =
  import.meta.env.VITE_SOCKET_URL || API_BASE_URL;
