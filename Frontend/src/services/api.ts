import axios from "axios";
import { useSecurityStore } from "../store/useSecurityStore";

export const getApiClient = () => {
  const { apiBaseUrl, token, logout } = useSecurityStore.getState();
  
  const client = axios.create({
    baseURL: apiBaseUrl,
    headers: {
      "Content-Type": "application/json",
    },
  });

  // Inject token
  if (token) {
    client.defaults.headers.common["Authorization"] = `Bearer ${token}`;
  }

  // Response interceptor to handle authentication errors
  client.interceptors.response.use(
    (response) => response,
    (error) => {
      if (error.response && error.response.status === 401) {
        logout(); // force logout on 401 Unauthorized
      }
      return Promise.reject(error);
    }
  );

  return client;
};
