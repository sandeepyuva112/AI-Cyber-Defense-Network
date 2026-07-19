import React, { useState, useEffect } from "react";
import { 
  ShieldAlert, ShieldX, Eye, ArrowLeft, Cpu, 
  Tag, AlertTriangle, Play, FileText, CheckCircle2 
} from "lucide-react";
import { getApiClient } from "../services/api";

export default function ThreatExplorer({ initialRefId }: { initialRefId?: number }) {
  const [threats, setThreats] = useState<any[]>([]);
  const [selectedThreatId, setSelectedThreatId] = useState<number | null>(initialRefId || null);
  const [threatDetails, setThreatDetails] = useState<any | null>(null);
  const [mitreList, setMitreList] = useState<any[]>([]);
  const [iocList, setIocList] = useState<any[]>([]);
  const [aiAnalysis, setAiAnalysis] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchThreats = async () => {
    try {
      const client = getApiClient();
      const res = await client.get("/api/v1/threats?limit=50");
      setThreats(res.data);
    } catch (err) {
      console.error("Error loading threats:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
  }, []);

  const loadThreatDetails = async (id: number) => {
    setLoading(true);
    try {
      const client = getApiClient();
      const [tRes, mRes, iRes] = await Promise.all([
        client.get(`/api/v1/threats/${id}`),
        client.get(`/api/v1/threats/${id}/mitre`),
        client.get(`/api/v1/threats/${id}/iocs`),
      ]);
      setThreatDetails(tRes.data);
      setMitreList(mRes.data);
      setIocList(iRes.data);

      // Check if there is an AI Analysis for this threat
      if (tRes.data.incident_id) {
        const histRes = await client.get(`/api/v1/ai/history?limit=1`);
        if (histRes.data.length > 0) {
          const detailRes = await client.get(`/api/v1/ai/explanations/${histRes.data[0].analysis_id}`);
          setAiAnalysis(detailRes.data);
        }
      }
    } catch (err) {
      console.error("Error loading threat details:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedThreatId) {
      loadThreatDetails(selectedThreatId);
    } else {
      setThreatDetails(null);
      setMitreList([]);
      setIocList([]);
      setAiAnalysis(null);
    }
  }, [selectedThreatId]);

  const getSeverityColor = (level: string | null) => {
    const l = (level || "low").toLowerCase();
    if (l === "critical" || l === "high" || l === "danger") return "text-cyberDanger";
    if (l === "medium" || l === "warning") return "text-cyberWarning";
    return "text-cyberSuccess";
  };

  const getSeverityBg = (level: string | null) => {
    const l = (level || "low").toLowerCase();
    if (l === "critical" || l === "high" || l === "danger") return "bg-cyberDanger/10 border-cyberDanger/20";
    if (l === "medium" || l === "warning") return "bg-cyberWarning/10 border-cyberWarning/20";
    return "bg-cyberSuccess/10 border-cyberSuccess/20";
  };

  if (selectedThreatId && threatDetails) {
    return (
      <div className="space-y-6">
        {/* Back Button and Title */}
        <div className="flex items-center gap-4">
          <button 
            onClick={() => setSelectedThreatId(null)}
            className="p-2 bg-gray-900 border border-gray-800 rounded text-gray-400 hover:text-white transition"
          >
            <ArrowLeft size={16} />
          </button>
          <div>
            <h1 className="text-xl font-bold text-white uppercase flex items-center gap-2">
              <ShieldAlert className={getSeverityColor(threatDetails.severity_level)} /> Threat Details: ID {threatDetails.threat_id}
            </h1>
            <p className="text-xs text-gray-400">Incident and forensic trace details</p>
          </div>
        </div>

        {/* Master Details Block */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column: Metadata */}
          <div className="lg:col-span-1 space-y-6">
            <div className="glass-panel p-5 rounded-lg space-y-4">
              <h3 className="text-sm font-semibold text-white border-b border-gray-800 pb-2 uppercase">Core Classification</h3>
              
              <div className="space-y-3 text-sm">
                <div>
                  <span className="text-gray-400 text-xs block">Category</span>
                  <span className="text-white font-medium capitalize">{threatDetails.threat_category.replace("_", " ")}</span>
                </div>
                <div>
                  <span className="text-gray-400 text-xs block">Severity</span>
                  <span className={`px-2.5 py-0.5 border rounded-full text-xs font-bold inline-block mt-1 ${getSeverityBg(threatDetails.severity_level)} ${getSeverityColor(threatDetails.severity_level)}`}>
                    {threatDetails.severity_level || "Low"}
                  </span>
                </div>
                <div>
                  <span className="text-gray-400 text-xs block">Confidence Score</span>
                  <span className="text-white font-medium">{(threatDetails.confidence_value * 100).toFixed(0)}%</span>
                </div>
                <div>
                  <span className="text-gray-400 text-xs block">Detection Time</span>
                  <span className="text-white font-medium">{new Date(threatDetails.created_at).toLocaleString()}</span>
                </div>
              </div>
            </div>

            {/* IOC List */}
            <div className="glass-panel p-5 rounded-lg">
              <h3 className="text-sm font-semibold text-white border-b border-gray-800 pb-2 uppercase mb-3">IOCs Extracted</h3>
              <div className="space-y-2">
                {iocList.length > 0 ? (
                  iocList.map((ioc, idx) => (
                    <div key={idx} className="p-2.5 bg-gray-950/80 border border-gray-900 rounded font-mono text-xs text-cyberPrimary break-all">
                      <div className="text-[10px] text-gray-500 uppercase font-bold">{ioc.ioc_type}</div>
                      {ioc.ioc_value}
                    </div>
                  ))
                ) : (
                  <div className="text-xs text-gray-500">No indicators extracted for this threat context.</div>
                )}
              </div>
            </div>
          </div>

          {/* Right Column: AI Analysis & MITRE Mapping */}
          <div className="lg:col-span-2 space-y-6">
            {/* AI Explanation */}
            {aiAnalysis ? (
              <div className="glass-panel p-5 rounded-lg space-y-4 border-l-2 border-l-cyberPurple">
                <h3 className="text-sm font-semibold text-cyberPurple uppercase flex items-center gap-2">
                  <Cpu size={16} /> AI Explanation & Recommendations
                </h3>
                <div className="space-y-4">
                  <div>
                    <h4 className="text-xs font-bold text-gray-400 uppercase">Incident Summary</h4>
                    <p className="text-sm text-gray-200 mt-1">{aiAnalysis.executive_summary}</p>
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-gray-400 uppercase">Response/Mitigation Plan</h4>
                    <p className="text-sm text-gray-300 mt-1 whitespace-pre-line">{aiAnalysis.reasoning_explanation}</p>
                  </div>
                </div>
              </div>
            ) : (
              <div className="glass-panel p-5 rounded-lg flex items-center justify-center py-12 text-sm text-gray-500">
                AI analysis has not been compiled for this incident yet. Click "Analyze" in the Log Upload history.
              </div>
            )}

            {/* MITRE Mapping */}
            <div className="glass-panel p-5 rounded-lg">
              <h3 className="text-sm font-semibold text-white border-b border-gray-800 pb-2 uppercase mb-4 flex items-center gap-2">
                <Tag size={16} className="text-cyberPrimary" /> MITRE ATT&CK Matrix Alignment
              </h3>
              
              <div className="overflow-x-auto">
                {mitreList.length > 0 ? (
                  <table className="w-full text-left text-xs text-gray-400">
                    <thead className="text-[10px] uppercase bg-gray-950/60 text-gray-500 border-b border-gray-900">
                      <tr>
                        <th className="py-2.5 px-3">Technique ID</th>
                        <th className="py-2.5 px-3">Technique Name</th>
                        <th className="py-2.5 px-3">Tactic Categories</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-900/60">
                      {mitreList.map((m, idx) => (
                        <tr key={idx} className="hover:bg-gray-900/20">
                          <td className="py-2.5 px-3 text-cyberPrimary font-mono font-semibold">{m.technique_id}</td>
                          <td className="py-2.5 px-3 text-white font-medium">{m.technique_name}</td>
                          <td className="py-2.5 px-3 font-semibold">{m.tactics.join(", ")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="text-xs text-gray-500">No MITRE tactics mapped for this threat.</div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <ShieldX className="text-cyberDanger" /> THREAT INTELLIGENCE EXPLORER
        </h1>
        <p className="text-sm text-gray-400">Investigate, classify, and correlate threat telemetry parsed across defense layers</p>
      </div>

      {/* Threats Grid */}
      <div className="glass-panel p-5 rounded-lg">
        <h2 className="text-sm font-semibold tracking-wider text-gray-300 uppercase mb-4">Correlated Threat List</h2>

        {loading ? (
          <div className="py-12 text-center text-gray-500">Retrieving threat feeds...</div>
        ) : threats.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {threats.map((t) => (
              <div 
                key={t.threat_id} 
                className="p-4 bg-gray-900/40 border border-gray-800 rounded-lg flex justify-between items-start hover:border-cyberPrimary/30 transition cursor-pointer"
                onClick={() => setSelectedThreatId(t.threat_id)}
              >
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 border rounded text-[10px] uppercase font-bold ${getSeverityBg(t.severity_level)} ${getSeverityColor(t.severity_level)}`}>
                      {t.severity_level || "low"}
                    </span>
                    <span className="text-xs text-gray-400 font-mono">ID {t.threat_id}</span>
                  </div>
                  <h3 className="text-sm font-bold text-white capitalize">{t.threat_category.replace("_", " ")}</h3>
                  <p className="text-xs text-gray-500">{new Date(t.created_at).toLocaleString()}</p>
                </div>
                <button className="p-2 bg-gray-950 border border-gray-800 rounded text-cyberPrimary hover:bg-cyberPrimary/10 transition">
                  <Eye size={14} />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-12 text-center text-gray-500">No active threats registered in the SOC database.</div>
        )}
      </div>
    </div>
  );
}
