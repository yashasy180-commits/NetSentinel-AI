import api from "./api";

const TOKEN_KEY = "access_token";
const REFRESH_TOKEN_KEY = "refresh_token";

export const auth = {
  async login(username, password) {
    const response = await api.post("/auth/login", {
      identifier: username,
      password,
    });

    const data = response.data;

    if (!data.success) {
      throw new Error(data.message || "Login failed");
    }

    localStorage.setItem(TOKEN_KEY, data.access_token);

    if (data.refresh_token) {
      localStorage.setItem(REFRESH_TOKEN_KEY, data.refresh_token);
    }

    return data;
  },

  async logout() {
    const token = localStorage.getItem(TOKEN_KEY);

    try {
      if (token) {
        await api.post(
          "/auth/logout",
          {},
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );
      }
    } catch (error) {
      // Even if the token has expired or the server rejects it,
      // the local session must still be cleared.
      console.warn("Server logout could not be completed.");
    } finally {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(REFRESH_TOKEN_KEY);
    }
  },

  getToken() {
    return localStorage.getItem(TOKEN_KEY);
  },

  getRefreshToken() {
    return localStorage.getItem(REFRESH_TOKEN_KEY);
  },

  isAuthenticated() {
    return Boolean(localStorage.getItem(TOKEN_KEY));
  },
};
