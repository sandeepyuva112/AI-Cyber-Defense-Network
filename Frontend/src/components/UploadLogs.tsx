import React, { useState, useEffect } from "react";
import { Upload, Database, FileText, CheckCircle2, ShieldAlert, Cpu } from "lucide-react";
import { getApiClient } from "../services/api";

export default function UploadLogs({ navigateTo }: { navigateTo: (page: string, refId?: number) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [logType, setLogType] = useState<string>("unknown");
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [logsList, setLogsList] = useState<any[]>([]);
  const [loadingList, setLoadingList] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchLogs = async () => {
    try {
      const client = getApiClient();
      const res = await client.get("/api/v1/logs");
      setLogsList(res.data);
    } catch (err) {
      console.error("Error loading logs history:", err);
    } finally {
      setLoadingList(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;

    setUploading(true);
    setProgress(10);
    setError(null);

    const formData = new FormData();
    formData.append("file", file);
    
    // Pass log_type if selected
    let url = "/api/v1/logs/upload";
    if (logType !== "unknown") {
      url += `?log_type=${logType}`;
    }

    try {
      const client = getApiClient();
      
      setProgress(40);
      const res = await client.post(url, formData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });

      setProgress(100);
      setFile(null);
      fetchLogs();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Upload failed. Check file size/format.");
    } finally {
      setTimeout(() => {
        setUploading(false);
        setProgress(0);
      }, 1000);
    }
  };

  const triggerAnalyze = async (logId: number) => {
    try {
      const client = getApiClient();
      await client.post(`/api/v1/logs/${logId}/analyze`);
      fetchLogs(); // refresh list to show updated status
      alert("AI analysis task dispatched in the background!");
    } catch (err: any) {
      alert(err.response?.data?.detail || "Failed to trigger analysis.");
    }
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <Upload className="text-cyberPrimary" /> LOG UPLOAD PORTAL
        </h1>
        <p className="text-sm text-gray-400">Ingest raw cybersecurity event logs for forensic analysis & threat correlation</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Upload Form */}
        <div className="lg:col-span-1 glass-panel p-5 rounded-lg h-fit space-y-4">
          <h2 className="text-sm font-semibold tracking-wider text-gray-300 uppercase flex items-center gap-2">
            File Ingestion Options
          </h2>

          <form onSubmit={handleUpload} className="space-y-4">
            {/* File Drag and Drop */}
            <div className="border border-dashed border-gray-700 hover:border-cyberPrimary/50 rounded-lg p-6 text-center cursor-pointer transition relative bg-gray-900/20">
              <input 
                type="file" 
                onChange={handleFileChange} 
                className="absolute inset-0 opacity-0 cursor-pointer" 
              />
              <Upload className="mx-auto text-gray-500 mb-2" size={32} />
              {file ? (
                <div className="text-sm text-cyberPrimary font-semibold truncate">{file.name}</div>
              ) : (
                <div className="text-xs text-gray-400">Drag & Drop or click to browse files</div>
              )}
            </div>

            {/* Parser selection */}
            <div>
              <label className="block text-xs font-semibold text-gray-400 uppercase mb-1">Select Parser Pipeline</label>
              <select 
                value={logType} 
                onChange={(e) => setLogType(e.target.value)}
                className="w-full bg-gray-900 border border-gray-800 rounded p-2 text-sm text-white focus:outline-none focus:border-cyberPrimary"
              >
                <option value="unknown">Auto-Select Pipeline</option>
                <option value="windows_event_logs">Windows Event Logs (JSON/EVTX)</option>
                <option value="syslog">Linux Syslog (Syslog format)</option>
                <option value="csv_logs">CSV Spreadsheet Logs</option>
                <option value="json_logs">JSON Structured Logs</option>
                <option value="apache_logs">Apache Web Logs</option>
                <option value="nginx_logs">Nginx Web Logs</option>
                <option value="firewall_logs">Firewall Conn Deny Logs</option>
              </select>
            </div>

            {error && (
              <div className="p-3 bg-cyberDanger/10 border border-cyberDanger/20 text-cyberDanger text-xs rounded">
                {error}
              </div>
            )}

            {uploading && (
              <div className="space-y-1">
                <div className="flex justify-between text-xs text-gray-400">
                  <span>Uploading & Parsing...</span>
                  <span>{progress}%</span>
                </div>
                <div className="w-full bg-gray-900 rounded-full h-1.5 overflow-hidden">
                  <div className="bg-cyberPrimary h-full transition-all duration-300" style={{ width: `${progress}%` }}></div>
                </div>
              </div>
            )}

            <button 
              type="submit" 
              disabled={!file || uploading}
              className="w-full py-2 bg-cyberPrimary text-black font-semibold rounded hover:bg-cyberPrimary/80 transition text-sm disabled:opacity-50 shadow-glow"
            >
              Start Upload Pipeline
            </button>
          </form>
        </div>

        {/* History / Uploaded list */}
        <div className="lg:col-span-2 glass-panel p-5 rounded-lg">
          <h2 className="text-sm font-semibold tracking-wider text-gray-300 uppercase mb-4 flex items-center gap-2">
            <Database size={16} className="text-cyberPurple" /> Log Upload History
          </h2>

          <div className="overflow-x-auto">
            {loadingList ? (
              <div className="py-12 text-center text-gray-500">Loading history...</div>
            ) : logsList.length > 0 ? (
              <table className="w-full text-left text-sm text-gray-400">
                <thead className="text-xs uppercase bg-gray-900/60 text-gray-400 border-b border-gray-800">
                  <tr>
                    <th className="py-3 px-4">Filename</th>
                    <th className="py-3 px-4">Parser</th>
                    <th className="py-3 px-4">Size (Bytes)</th>
                    <th className="py-3 px-4">Alerts</th>
                    <th className="py-3 px-4">Ingestion Date</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/40">
                  {logsList.map((log) => (
                    <tr key={log.log_id} className="hover:bg-gray-900/20">
                      <td className="py-3 px-4 text-white font-medium flex items-center gap-2">
                        <FileText size={16} className="text-cyberPrimary" /> {log.source_filename}
                      </td>
                      <td className="py-3 px-4 capitalize">{log.log_type.replace("_", " ")}</td>
                      <td className="py-3 px-4">{log.size || "Unknown"}</td>
                      <td className="py-3 px-4">
                        {log.total_alerts > 0 ? (
                          <span className="px-2 py-0.5 bg-cyberDanger/10 border border-cyberDanger/20 text-cyberDanger text-xs rounded-full font-semibold">
                            {log.total_alerts} Alerts
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 bg-cyberSuccess/10 border border-cyberSuccess/20 text-cyberSuccess text-xs rounded-full font-semibold">
                            Clean
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4">{new Date(log.created_at).toLocaleDateString()}</td>
                      <td className="py-3 px-4 text-right flex justify-end gap-2">
                        <button 
                          onClick={() => triggerAnalyze(log.log_id)}
                          className="px-3 py-1 bg-cyberPurple/10 border border-cyberPurple/30 text-cyberPurple text-xs rounded hover:bg-cyberPurple/20 transition flex items-center gap-1 font-semibold"
                        >
                          <Cpu size={12} /> Analyze
                        </button>
                        <button 
                          onClick={() => navigateTo("Threat Explorer", log.log_id)}
                          className="px-3 py-1 bg-cyberPrimary/10 border border-cyberPrimary/30 text-cyberPrimary text-xs rounded hover:bg-cyberPrimary/20 transition font-semibold"
                        >
                          View
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="py-12 text-center text-gray-500">No logs have been uploaded yet.</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
