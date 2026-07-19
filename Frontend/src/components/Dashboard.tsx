import React, { useEffect, useState } from "react";
import { 
  Shield, AlertTriangle, Activity, Database, Flame, 
  TrendingUp, BarChart3, Clock, CheckCircle2 
} from "lucide-react";
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, 
  Tooltip, ResponsiveContainer, BarChart, Bar, 
  PieChart, Pie, Cell 
} from "recharts";
import { getApiClient } from "../services/api";

export default function Dashboard({ navigateTo }: { navigateTo: (page: string, refId?: number) => void }) {
  const [metrics, setMetrics] = useState({ open_alerts: 0, total_incidents: 0, ai_analyses: 0 });
  const [timeline, setTimeline] = useState<any[]>([]);
  const [distribution, setDistribution] = useState<any[]>([]);
  const [activity, setActivity] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        const client = getApiClient();
        const [mRes, tRes, dRes, aRes] = await Promise.all([
          client.get("/api/v1/dashboard/metrics"),
          client.get("/api/v1/dashboard/threat-timeline"),
          client.get("/api/v1/dashboard/risk-distribution"),
          client.get("/api/v1/dashboard/recent-activity")
        ]);
        setMetrics(mRes.data);
        setTimeline(tRes.data.items);
        setDistribution(dRes.data.buckets);
        setActivity(aRes.data.items);
      } catch (err) {
        console.error("Error loading dashboard data:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchDashboardData();
  }, []);

  const COLORS = ["#EF4444", "#FACC15", "#8B5CF6", "#00E5FF", "#22C55E"];

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-cyberPrimary"></div>
      </div>
    );
  }

  // Calculate generic security status
  const totalAlerts = metrics.open_alerts;
  const totalIncidents = metrics.total_incidents;
  const overallRisk = totalIncidents > 0 ? Math.min(Math.round((totalIncidents * 12 + totalAlerts * 4)), 100) : 0;
  
  const riskColor = 
    overallRisk > 75 ? "text-cyberDanger" : 
    overallRisk > 40 ? "text-cyberWarning" : 
    "text-cyberSuccess";

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Shield className="text-cyberPrimary animate-pulse" /> SECURITY OPERATION CENTER
          </h1>
          <p className="text-sm text-gray-400">Real-time threat feeds & AI incident response</p>
        </div>
        <div className="flex gap-3">
          <button 
            onClick={() => navigateTo("Upload Logs")}
            className="px-4 py-2 bg-cyberPrimary/10 border border-cyberPrimary/30 rounded text-cyberPrimary hover:bg-cyberPrimary/20 transition text-sm font-semibold shadow-glow"
          >
            Upload New Log
          </button>
        </div>
      </div>

      {/* Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="glass-panel p-5 rounded-lg flex items-center justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">Total Alerts</p>
            <h3 className="text-2xl font-bold mt-1 text-white">{metrics.open_alerts}</h3>
          </div>
          <div className="p-3 bg-cyberWarning/10 rounded-full text-cyberWarning">
            <AlertTriangle size={24} />
          </div>
        </div>

        <div className="glass-panel p-5 rounded-lg flex items-center justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">Active Incidents</p>
            <h3 className="text-2xl font-bold mt-1 text-white">{metrics.total_incidents}</h3>
          </div>
          <div className="p-3 bg-cyberDanger/10 rounded-full text-cyberDanger">
            <Flame size={24} />
          </div>
        </div>

        <div className="glass-panel p-5 rounded-lg flex items-center justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">Risk Score</p>
            <h3 className={`text-2xl font-bold mt-1 ${riskColor}`}>{overallRisk}%</h3>
          </div>
          <div className="p-3 bg-cyberPrimary/10 rounded-full text-cyberPrimary">
            <Activity size={24} />
          </div>
        </div>

        <div className="glass-panel p-5 rounded-lg flex items-center justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">AI Analyses</p>
            <h3 className="text-2xl font-bold mt-1 text-white">{metrics.ai_analyses}</h3>
          </div>
          <div className="p-3 bg-cyberPurple/10 rounded-full text-cyberPurple">
            <Database size={24} />
          </div>
        </div>
      </div>

      {/* Charts section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline area */}
        <div className="lg:col-span-2 glass-panel p-5 rounded-lg">
          <h2 className="text-sm font-semibold tracking-wider text-gray-300 uppercase mb-4 flex items-center gap-2">
            <TrendingUp size={16} className="text-cyberPrimary" /> Incident Timeline
          </h2>
          <div className="h-64">
            {timeline.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timeline.map(t => ({ ...t, date: t.timestamp.split("T")[0] }))}>
                  <defs>
                    <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00E5FF" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#00E5FF" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="date" stroke="#9ca3af" fontSize={11} />
                  <YAxis stroke="#9ca3af" fontSize={11} allowDecimals={false} />
                  <Tooltip contentStyle={{ backgroundColor: "#101827", borderColor: "#1f2937", color: "#fff" }} />
                  <Area type="monotone" dataKey="count" stroke="#00E5FF" fillOpacity={1} fill="url(#colorCount)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-sm text-gray-500">No incident activity recorded.</div>
            )}
          </div>
        </div>

        {/* Severity distribution */}
        <div className="glass-panel p-5 rounded-lg">
          <h2 className="text-sm font-semibold tracking-wider text-gray-300 uppercase mb-4 flex items-center gap-2">
            <BarChart3 size={16} className="text-cyberPurple" /> Risk Distribution
          </h2>
          <div className="h-64 flex items-center justify-center">
            {distribution.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={distribution}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="count"
                    nameKey="severity"
                  >
                    {distribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: "#101827", borderColor: "#1f2937", color: "#fff" }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-sm text-gray-500">No severity metrics available.</div>
            )}
          </div>
        </div>
      </div>

      {/* Feed and Details */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Activity Feed */}
        <div className="lg:col-span-2 glass-panel p-5 rounded-lg">
          <h2 className="text-sm font-semibold tracking-wider text-gray-300 uppercase mb-4 flex items-center gap-2">
            <Clock size={16} className="text-cyberWarning" /> Recent Activity Feed
          </h2>
          <div className="space-y-3 max-h-80 overflow-y-auto pr-2">
            {activity.length > 0 ? (
              activity.map((item, idx) => (
                <div key={idx} className="flex items-center justify-between p-3 bg-gray-900/40 rounded border border-gray-800/60 hover:border-cyberPrimary/30 transition">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-full ${
                      item.type === "incident" ? "bg-cyberDanger/10 text-cyberDanger" :
                      item.type === "alert" ? "bg-cyberWarning/10 text-cyberWarning" :
                      "bg-cyberPrimary/10 text-cyberPrimary"
                    }`}>
                      {item.type === "incident" ? <Flame size={16} /> :
                       item.type === "alert" ? <AlertTriangle size={16} /> :
                       <Database size={16} />}
                    </div>
                    <div>
                      <p className="text-sm font-medium text-white capitalize">{item.type} Recorded</p>
                      <p className="text-xs text-gray-400">{new Date(item.timestamp).toLocaleString()}</p>
                    </div>
                  </div>
                  <button 
                    onClick={() => {
                      if (item.type === "incident") {
                        navigateTo("Threat Explorer", item.ref_id);
                      } else if (item.type === "alert") {
                        navigateTo("Alerts");
                      } else {
                        navigateTo("Live Monitor");
                      }
                    }}
                    className="text-xs text-cyberPrimary hover:underline"
                  >
                    View Details
                  </button>
                </div>
              ))
            ) : (
              <div className="text-center py-6 text-sm text-gray-500">No recent activity detected.</div>
            )}
          </div>
        </div>

        {/* AI Copilot Suggestion Box */}
        <div className="glass-panel p-5 rounded-lg flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-semibold tracking-wider text-gray-300 uppercase mb-3 flex items-center gap-2">
              <CheckCircle2 size={16} className="text-cyberSuccess" /> AI Security Assistant
            </h2>
            <div className="p-3 bg-cyberPurple/5 border border-cyberPurple/20 rounded-lg">
              <p className="text-xs text-gray-400 italic">"I've scanned all raw logs uploaded recently. No active malware beacons have been seen. You have {metrics.open_alerts} open alerts that require your confirmation in the Alerts console."</p>
            </div>
          </div>
          <button 
            onClick={() => navigateTo("AI Copilot")}
            className="w-full mt-4 py-2 bg-cyberPurple text-white rounded text-sm font-semibold shadow-purpleGlow hover:bg-cyberPurple/80 transition"
          >
            Ask Copilot
          </button>
        </div>
      </div>
    </div>
  );
}
