import React, { useState, useEffect } from "react";
import { AlertTriangle, ShieldCheck, Search, Filter, Eye } from "lucide-react";
import { getApiClient } from "../services/api";

export default function Alerts() {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [filterSeverity, setFilterSeverity] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [selectedAlert, setSelectedAlert] = useState<any | null>(null);
  const [updatingStatus, setUpdatingStatus] = useState(false);

  const fetchAlerts = async () => {
    try {
      const client = getApiClient();
      // Fetch all alerts
      const res = await client.get("/api/v1/alerts?limit=100");
      setAlerts(res.data.items);
    } catch (err) {
      console.error("Error loading alerts:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  const handleStatusUpdate = async (alertId: number, newStatus: string) => {
    setUpdatingStatus(true);
    try {
      const client = getApiClient();
      const res = await client.post(`/api/v1/alerts/${alertId}/status`, { status: newStatus });
      // Update local state
      setAlerts((prev: any[]) => prev.map(a => a.alert_id === alertId ? { ...a, status: newStatus } : a));
      if (selectedAlert && selectedAlert.alert_id === alertId) {
        setSelectedAlert((prev: any) => ({ ...prev, status: newStatus }));
      }
    } catch (err: any) {
      alert(err.response?.data?.detail || "Failed to update alert status.");
    } finally {
      setUpdatingStatus(false);
    }
  };

  const getSeverityBg = (level: string) => {
    const l = level.toLowerCase();
    if (l === "critical" || l === "high") return "bg-cyberDanger/10 border-cyberDanger/20 text-cyberDanger";
    if (l === "medium") return "bg-cyberWarning/10 border-cyberWarning/20 text-cyberWarning";
    return "bg-cyberSuccess/10 border-cyberSuccess/20 text-cyberSuccess";
  };

  const getStatusColor = (status: string) => {
    const s = (status || "open").toLowerCase();
    if (s === "closed" || s === "resolved") return "text-cyberSuccess";
    if (s === "investigating") return "text-cyberWarning";
    return "text-cyberDanger animate-pulse";
  };

  const filteredAlerts = alerts.filter((a) => {
    const matchSearch = a.threat_category?.toLowerCase().includes(search.toLowerCase()) || false;
    const matchSeverity = filterSeverity === "all" || a.severity_level?.toLowerCase() === filterSeverity.toLowerCase();
    const matchStatus = filterStatus === "all" || a.status?.toLowerCase() === filterStatus.toLowerCase();
    return matchSearch && matchSeverity && matchStatus;
  });

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <AlertTriangle className="text-cyberWarning animate-pulse" /> ALERTS MANAGEMENT CONSOLE
        </h1>
        <p className="text-sm text-gray-400">Triage, investigate, and transition lifecycle status of security alerts</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left List Pane */}
        <div className="lg:col-span-2 space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap gap-3 bg-gray-900/30 p-4 border border-gray-800/60 rounded-lg">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-2.5 text-gray-500" size={16} />
              <input 
                type="text" 
                placeholder="Search alerts by threat category..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-9 pr-4 py-2 bg-gray-950 border border-gray-800 rounded text-sm text-white focus:outline-none focus:border-cyberPrimary"
              />
            </div>
            
            <select 
              value={filterSeverity} 
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="bg-gray-950 border border-gray-800 rounded text-sm text-white p-2 focus:outline-none focus:border-cyberPrimary"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <select 
              value={filterStatus} 
              onChange={(e) => setFilterStatus(e.target.value)}
              className="bg-gray-950 border border-gray-800 rounded text-sm text-white p-2 focus:outline-none focus:border-cyberPrimary"
            >
              <option value="all">All Statuses</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
              <option value="closed">Closed</option>
            </select>
          </div>

          {/* List */}
          <div className="glass-panel p-5 rounded-lg">
            <h2 className="text-sm font-semibold tracking-wider text-gray-300 uppercase mb-4">Active Alerts ({filteredAlerts.length})</h2>

            {loading ? (
              <div className="py-12 text-center text-gray-500">Retrieving alert list...</div>
            ) : filteredAlerts.length > 0 ? (
              <div className="space-y-3">
                {filteredAlerts.map((a) => (
                  <div 
                    key={a.alert_id} 
                    onClick={() => setSelectedAlert(a)}
                    className={`p-3 bg-gray-950/50 border rounded-lg flex justify-between items-center cursor-pointer hover:border-cyberPrimary/30 transition ${
                      selectedAlert?.alert_id === a.alert_id ? "border-cyberPrimary/60 bg-cyberPrimary/5" : "border-gray-800"
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <span className={`px-2 py-0.5 border text-[10px] font-bold uppercase rounded ${getSeverityBg(a.severity_level)}`}>
                        {a.severity_level}
                      </span>
                      <div>
                        <h4 className="text-sm font-bold text-white capitalize">{a.threat_category?.replace("_", " ") || "Security Alert"}</h4>
                        <span className="text-[10px] text-gray-500 font-mono">Confidence: {(a.confidence_value * 100).toFixed(0)}%</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <span className={`text-xs font-bold uppercase ${getStatusColor(a.status)}`}>
                        {a.status || "Open"}
                      </span>
                      <button className="p-1.5 bg-gray-900 border border-gray-800 rounded text-gray-400 hover:text-white transition">
                        <Eye size={12} />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-12 text-center text-gray-500">No alerts found matching filter settings.</div>
            )}
          </div>
        </div>

        {/* Right Details Triage Pane */}
        <div className="lg:col-span-1">
          {selectedAlert ? (
            <div className="glass-panel p-5 rounded-lg space-y-4">
              <h2 className="text-sm font-semibold tracking-wider text-white uppercase border-b border-gray-800 pb-2">Triage Alert ID: {selectedAlert.alert_id}</h2>
              
              <div className="space-y-3 text-sm">
                <div>
                  <span className="text-gray-400 text-xs block">Category</span>
                  <span className="text-white font-medium capitalize">{selectedAlert.threat_category?.replace("_", " ")}</span>
                </div>
                <div>
                  <span className="text-gray-400 text-xs block">Confidence Score</span>
                  <span className="text-white font-medium">{(selectedAlert.confidence_value * 100).toFixed(0)}%</span>
                </div>
                <div>
                  <span className="text-gray-400 text-xs block">Severity Level</span>
                  <span className="text-white font-medium capitalize">{selectedAlert.severity_level}</span>
                </div>
                <div>
                  <span className="text-gray-400 text-xs block">Current Status</span>
                  <span className={`font-bold uppercase ${getStatusColor(selectedAlert.status)}`}>
                    {selectedAlert.status || "Open"}
                  </span>
                </div>
              </div>

              {/* Status Update Actions */}
              <div className="pt-4 border-t border-gray-800 space-y-3">
                <span className="block text-xs font-semibold text-gray-400 uppercase">Change Lifecycle Status</span>
                
                <div className="grid grid-cols-2 gap-2">
                  <button 
                    disabled={updatingStatus || selectedAlert.status === "Investigating"}
                    onClick={() => handleStatusUpdate(selectedAlert.alert_id, "Investigating")}
                    className="py-1.5 bg-cyberWarning/10 border border-cyberWarning/30 text-cyberWarning rounded text-xs font-bold hover:bg-cyberWarning/20 disabled:opacity-50 transition"
                  >
                    Investigate
                  </button>
                  <button 
                    disabled={updatingStatus || selectedAlert.status === "Resolved"}
                    onClick={() => handleStatusUpdate(selectedAlert.alert_id, "Resolved")}
                    className="py-1.5 bg-cyberSuccess/10 border border-cyberSuccess/30 text-cyberSuccess rounded text-xs font-bold hover:bg-cyberSuccess/20 disabled:opacity-50 transition"
                  >
                    Resolve
                  </button>
                  <button 
                    disabled={updatingStatus || selectedAlert.status === "Closed"}
                    onClick={() => handleStatusUpdate(selectedAlert.alert_id, "Closed")}
                    className="py-1.5 bg-gray-900 border border-gray-800 text-gray-400 rounded text-xs font-bold hover:bg-gray-800 disabled:opacity-50 transition col-span-2"
                  >
                    Close Case
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="glass-panel p-5 rounded-lg flex items-center justify-center py-12 text-sm text-gray-500 text-center">
              Select an alert from the console list to start incident triage and transition its status.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
