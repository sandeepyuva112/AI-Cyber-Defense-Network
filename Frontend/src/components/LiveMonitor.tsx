import React, { useState, useEffect } from "react";
import { Activity, Shield, Search, RefreshCw, Terminal } from "lucide-react";
import { getApiClient } from "../services/api";

export default function LiveMonitor() {
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchEvents = async () => {
    try {
      const client = getApiClient();
      const res = await client.get("/api/v1/logs/events/all?limit=100");
      setEvents(res.data);
    } catch (err) {
      console.error("Error fetching live monitor events:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, []);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      fetchEvents();
    }, 4000);
    return () => clearInterval(interval);
  }, [autoRefresh]);

  const filteredEvents = events.filter((ev) => {
    const s = search.toLowerCase();
    return (
      (ev.ip && ev.ip.toLowerCase().includes(s)) ||
      (ev.username && ev.username.toLowerCase().includes(s)) ||
      (ev.process && ev.process.toLowerCase().includes(s)) ||
      (ev.message && ev.message.toLowerCase().includes(s)) ||
      (ev.event_type && ev.event_type.toLowerCase().includes(s))
    );
  });

  const getSeverityBadge = (sev: string | null) => {
    const s = (sev || "low").toLowerCase();
    if (s === "critical" || s === "high" || s === "error") {
      return "bg-cyberDanger/10 border-cyberDanger/30 text-cyberDanger shadow-redGlow";
    }
    if (s === "medium" || s === "warning") {
      return "bg-cyberWarning/10 border-cyberWarning/30 text-cyberWarning";
    }
    return "bg-cyberSuccess/10 border-cyberSuccess/30 text-cyberSuccess";
  };

  return (
    <div className="space-y-6 scanline-effect min-h-[85vh]">
      {/* Title */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Activity className="text-cyberPrimary animate-pulse" /> LIVE STREAM MONITOR
          </h1>
          <p className="text-sm text-gray-400">Rolling telemetry feeds of parsed security event logs</p>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs font-semibold text-gray-400 uppercase cursor-pointer">
            <input 
              type="checkbox" 
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="rounded bg-gray-900 border-gray-800 text-cyberPrimary focus:ring-cyberPrimary focus:ring-offset-gray-950" 
            />
            Auto Poll (4s)
          </label>
          <button 
            onClick={fetchEvents}
            className="p-2 bg-gray-900 border border-gray-800 rounded text-gray-400 hover:text-white transition"
          >
            <RefreshCw size={16} />
          </button>
        </div>
      </div>

      {/* Filter and Stats */}
      <div className="flex flex-col md:flex-row gap-4 justify-between items-center bg-gray-900/30 p-4 border border-gray-800/60 rounded-lg">
        {/* Search */}
        <div className="relative w-full md:w-96">
          <Search className="absolute left-3 top-2.5 text-gray-500" size={16} />
          <input 
            type="text" 
            placeholder="Search events by IP, User, Process, or Message..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-gray-950 border border-gray-800 rounded text-sm text-white focus:outline-none focus:border-cyberPrimary"
          />
        </div>
        {/* Stats */}
        <div className="text-xs text-gray-400 font-semibold uppercase tracking-wider flex gap-4">
          <div>Parsed Events: <span className="text-white">{events.length}</span></div>
          <div>Filtered View: <span className="text-cyberPrimary">{filteredEvents.length}</span></div>
        </div>
      </div>

      {/* Terminal Display */}
      <div className="glass-panel rounded-lg overflow-hidden border border-gray-800 flex flex-col h-[60vh] shadow-glow">
        <div className="bg-gray-950/80 px-4 py-2 border-b border-gray-800 flex items-center gap-2">
          <Terminal size={14} className="text-cyberPrimary" />
          <span className="text-xs font-bold text-gray-400 uppercase tracking-widest">security_console_feed.log</span>
        </div>
        
        <div className="flex-1 overflow-y-auto p-4 font-mono text-xs space-y-2.5 bg-black/40">
          {loading ? (
            <div className="text-center py-12 text-gray-500">Connecting to telemetry stream...</div>
          ) : filteredEvents.length > 0 ? (
            filteredEvents.map((ev) => (
              <div key={ev.id} className="flex flex-col md:flex-row md:items-center gap-2 md:gap-4 p-2 bg-gray-950/40 rounded border border-gray-900/60 hover:border-gray-800 transition">
                {/* Timestamp */}
                <span className="text-gray-500 shrink-0">
                  [{ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : "00:00:00"}]
                </span>

                {/* Severity */}
                <span className={`px-2 py-0.5 border rounded text-[10px] uppercase font-bold shrink-0 ${getSeverityBadge(ev.severity)}`}>
                  {ev.severity || "low"}
                </span>

                {/* Event Type */}
                <span className="text-cyberPurple font-semibold shrink-0">
                  {ev.event_type}
                </span>

                {/* Host/IP */}
                <span className="text-cyberPrimary font-semibold shrink-0">
                  {ev.ip || ev.source || "local"}
                </span>

                {/* Payload Message */}
                <span className="text-gray-300 break-all flex-1">
                  {ev.message}
                </span>

                {/* Threat Score */}
                {ev.threat_score !== null && (
                  <span className="text-right font-semibold text-cyberDanger shrink-0">
                    TS: {ev.threat_score}
                  </span>
                )}
              </div>
            ))
          ) : (
            <div className="text-center py-12 text-gray-500">No events matched query or stream is empty.</div>
          )}
        </div>
      </div>
    </div>
  );
}
