import { create } from "zustand";

interface User {
  id: string;
  email: string;
  name: string;
  role: string;
}

interface SecurityState {
  user: User | null;
  token: string | null;
  apiBaseUrl: string;
  setAuth: (user: User, token: string) => void;
  logout: () => void;
  setApiBaseUrl: (url: string) => void;
}

// Load initial values from localStorage if present
const storedUser = localStorage.getItem("cdn_user");
const storedToken = localStorage.getItem("cdn_token");
const storedApiUrl = localStorage.getItem("cdn_api_url") || "http://127.0.0.1:8000";

export const useSecurityStore = create<SecurityState>((set) => ({
  user: storedUser ? JSON.parse(storedUser) : null,
  token: storedToken || null,
  apiBaseUrl: storedApiUrl,
  setAuth: (user, token) => {
    localStorage.setItem("cdn_user", JSON.stringify(user));
    localStorage.setItem("cdn_token", token);
    set({ user, token });
  },
  logout: () => {
    localStorage.removeItem("cdn_user");
    localStorage.removeItem("cdn_token");
    set({ user: null, token: null });
  },
  setApiBaseUrl: (url) => {
    localStorage.setItem("cdn_api_url", url);
    set({ apiBaseUrl: url });
  },
}));
