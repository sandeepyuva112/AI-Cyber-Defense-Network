import React, { useState, useEffect } from "react";
import { Settings as SettingsIcon, CheckCircle2, AlertTriangle, ShieldCheck, Database, Server } from "lucide-react";
import { useSecurityStore } from "../store/useSecurityStore";
import { getApiClient } from "../services/api";

export default function Settings() {
  const { apiBaseUrl, setApiBaseUrl } = useSecurityStore();
  const [urlInput, setUrlInput] = useState(apiBaseUrl);
  const [health, setHealth] = useState<any | null>(null);
  const [loadingHealth, setLoadingHealth] = useState(true);
  const [errorHealth, setErrorHealth] = useState<string | null>(null);
  const [apiKey, setApiKey] = useState("");
  const [savingKey, setSavingKey] = useState(false);

  const checkSystemHealth = async () => {
    setLoadingHealth(true);
    setErrorHealth(null);
    try {
      const client = getApiClient();
      const res = await client.get("/api/v1/health-checks");
      setHealth(res.data);
    } catch (err: any) {
      setErrorHealth("Failed to communicate with API server.");
      setHealth(null);
    } finally {
      setLoadingHealth(false);
    }
  };

  useEffect(() => {
    checkSystemHealth();
  }, [apiBaseUrl]);

  const handleSaveUrl = (e: React.FormEvent) => {
    e.preventDefault();
    setApiBaseUrl(urlInput);
    alert("API server URL updated!");
  };

  const handleSaveKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!apiKey.trim()) return;
    setSavingKey(true);
    try {
      const client = getApiClient();
      await client.post("/api/v1/settings/api-keys", {
        openai_api_key: apiKey
      });
      alert("API keys updated successfully!");
      setApiKey("");
      checkSystemHealth();
    } catch (err: any) {
      alert(err.response?.data?.detail || "Failed to update API keys.");
    } finally {
      setSavingKey(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <SettingsIcon className="text-cyberPrimary" /> SYSTEM SETTINGS & TELEMETRY
        </h1>
        <p className="text-sm text-gray-400">Configure connection paths, OpenAI API keys, and check engine health</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Connection Settings */}
        <div className="glass-panel p-5 rounded-lg space-y-4">
          <h2 className="text-sm font-semibold tracking-wider text-white uppercase flex items-center gap-2">
            <Server size={16} className="text-cyberPrimary" /> API Server Connection
          </h2>

          <form onSubmit={handleSaveUrl} className="space-y-3">
            <div>
              <label className="block text-xs font-semibold text-gray-400 uppercase mb-1">Backend Server Base URL</label>
              <input 
                type="text" 
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                className="w-full bg-gray-900 border border-gray-800 rounded p-2 text-sm text-white focus:outline-none focus:border-cyberPrimary"
                placeholder="http://127.0.0.1:8000"
              />
            </div>
            <button 
              type="submit"
              className="px-4 py-2 bg-cyberPrimary text-black font-semibold rounded hover:bg-cyberPrimary/80 transition text-xs shadow-glow"
            >
              Update API Server URL
            </button>
          </form>

          {/* API Key Configuration */}
          <div className="pt-6 border-t border-gray-800 space-y-3">
            <h3 className="text-sm font-semibold text-white uppercase flex items-center gap-2">
              <ShieldCheck size={16} className="text-cyberPurple" /> API Key Integration
            </h3>
            <form onSubmit={handleSaveKey} className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-gray-400 uppercase mb-1">OpenAI API Access Key</label>
                <input 
                  type="password" 
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-800 rounded p-2 text-sm text-white focus:outline-none focus:border-cyberPurple"
                  placeholder="sk-proj-........................"
                />
              </div>
              <button 
                type="submit"
                disabled={savingKey}
                className="px-4 py-2 bg-cyberPurple text-white font-semibold rounded hover:bg-cyberPurple/80 transition text-xs shadow-purpleGlow"
              >
                {savingKey ? "Updating keys..." : "Save API Credentials"}
              </button>
            </form>
          </div>
        </div>

        {/* Engine Diagnostics */}
        <div className="glass-panel p-5 rounded-lg space-y-4">
          <div className="flex justify-between items-center">
            <h2 className="text-sm font-semibold tracking-wider text-white uppercase flex items-center gap-2">
              <Database size={16} className="text-cyberWarning" /> Engine Health Diagnostics
            </h2>
            <button 
              onClick={checkSystemHealth}
              className="text-xs text-cyberPrimary hover:underline"
            >
              Refresh Diagnostics
            </button>
          </div>

          {loadingHealth ? (
            <div className="py-6 text-sm text-gray-500">Checking network health...</div>
          ) : errorHealth ? (
            <div className="p-3 bg-cyberDanger/10 border border-cyberDanger/20 text-cyberDanger text-xs rounded flex items-center gap-2">
              <AlertTriangle size={16} /> {errorHealth}
            </div>
          ) : health ? (
            <div className="space-y-3 text-sm">
              <div className="flex justify-between items-center py-2 border-b border-gray-900">
                <span className="text-gray-400">Database Configured</span>
                <span className={`font-bold flex items-center gap-1 ${health.database_configured ? "text-cyberSuccess" : "text-cyberDanger"}`}>
                  {health.database_configured ? (
                    <>
                      <CheckCircle2 size={14} /> Yes
                    </>
                  ) : (
                    <>
                      <AlertTriangle size={14} /> No
                    </>
                  )}
                </span>
              </div>

              <div className="flex justify-between items-center py-2 border-b border-gray-900">
                <span className="text-gray-400">AI Engine Services</span>
                <span className={`font-bold flex items-center gap-1 ${health.openai_configured ? "text-cyberSuccess" : "text-cyberWarning"}`}>
                  {health.openai_configured ? (
                    <>
                      <CheckCircle2 size={14} /> OpenAI Configured
                    </>
                  ) : (
                    <>
                      <AlertTriangle size={14} /> Local Rules Fallback
                    </>
                  )}
                </span>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
