import React, { useState, useEffect } from "react";
import { FileText, Download, Eye, ArrowLeft, RefreshCw, CheckCircle2 } from "lucide-react";
import { getApiClient } from "../services/api";

export default function Reports() {
  const [reports, setReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedReportId, setSelectedReportId] = useState<number | null>(null);
  const [reportDetails, setReportDetails] = useState<any | null>(null);

  const fetchReports = async () => {
    try {
      const client = getApiClient();
      const res = await client.get("/api/v1/reports?limit=50");
      setReports(res.data);
    } catch (err) {
      console.error("Error loading reports:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const loadReportDetails = async (id: number) => {
    setLoading(true);
    try {
      const client = getApiClient();
      const res = await client.get(`/api/v1/reports/${id}`);
      setReportDetails(res.data);
    } catch (err) {
      console.error("Error loading report details:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedReportId) {
      loadReportDetails(selectedReportId);
    } else {
      setReportDetails(null);
    }
  }, [selectedReportId]);

  const handleExport = (report: any, format: string) => {
    // Parse findings
    let content = "";
    try {
      content = JSON.stringify(JSON.parse(report.content_json), null, 2);
    } catch (e) {
      content = report.content_json;
    }

    if (format === "json") {
      const blob = new Blob([content], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `incident_report_ID_${report.report_id}.json`;
      a.click();
    } else {
      // Export as HTML
      const htmlContent = `
        <html>
          <head>
            <title>Incident Report ID ${report.report_id}</title>
            <style>
              body { font-family: sans-serif; padding: 40px; background: #070B14; color: #e5e7eb; }
              h1 { color: #00E5FF; }
              pre { background: #101827; padding: 20px; border: 1px solid #1f2937; color: #fff; }
            </style>
          </head>
          <body>
            <h1>Incident Forensic Report</h1>
            <p>Generated: ${new Date(report.created_at).toLocaleString()}</p>
            <p>Type: ${report.report_type}</p>
            <h2>Structured AI Findings</h2>
            <pre>${content}</pre>
          </body>
        </html>
      `;
      const blob = new Blob([htmlContent], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `incident_report_ID_${report.report_id}.html`;
      a.click();
    }
  };

  if (selectedReportId && reportDetails) {
    // Parse json
    let findings: any = {};
    try {
      findings = JSON.parse(reportDetails.content_json);
    } catch (e) {
      findings = {};
    }

    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <button 
            onClick={() => setSelectedReportId(null)}
            className="p-2 bg-gray-900 border border-gray-800 rounded text-gray-400 hover:text-white transition"
          >
            <ArrowLeft size={16} />
          </button>
          <div>
            <h1 className="text-xl font-bold text-white uppercase flex items-center gap-2">
              <FileText className="text-cyberPrimary" /> Report ID: {reportDetails.report_id}
            </h1>
            <p className="text-xs text-gray-400">Forensic incident report summary</p>
          </div>
        </div>

        <div className="glass-panel p-5 rounded-lg space-y-4">
          <div className="flex justify-between items-center border-b border-gray-800 pb-3">
            <h3 className="text-sm font-semibold text-white uppercase">Forensic Summary Data</h3>
            <div className="flex gap-2">
              <button 
                onClick={() => handleExport(reportDetails, "json")}
                className="px-3 py-1 bg-cyberPrimary/10 border border-cyberPrimary/30 text-cyberPrimary text-xs rounded hover:bg-cyberPrimary/20 transition flex items-center gap-1 font-semibold"
              >
                <Download size={12} /> Export JSON
              </button>
              <button 
                onClick={() => handleExport(reportDetails, "html")}
                className="px-3 py-1 bg-cyberPurple/10 border border-cyberPurple/30 text-cyberPurple text-xs rounded hover:bg-cyberPurple/20 transition flex items-center gap-1 font-semibold"
              >
                <Download size={12} /> Export HTML
              </button>
            </div>
          </div>

          <div className="space-y-4 text-sm text-gray-300">
            <div>
              <span className="text-gray-500 font-semibold uppercase text-xs">Overview</span>
              <p className="text-white font-medium mt-1">
                {findings.executive_summary?.overview || "No overview available."}
              </p>
            </div>
            
            {findings.classification && (
              <div>
                <span className="text-gray-500 font-semibold uppercase text-xs">Classification</span>
                <p className="text-white font-medium mt-1">
                  Incident Type: {findings.classification.incident_type} (Confidence: {findings.classification.confidence_percentage}%)
                </p>
              </div>
            )}

            {findings.remediation && (
              <div className="p-4 bg-cyberPurple/5 border border-cyberPurple/20 rounded-lg space-y-2">
                <span className="text-cyberPurple font-semibold uppercase text-xs block">AI Mitigation Directives</span>
                <div className="text-gray-300 whitespace-pre-line text-xs leading-relaxed">
                  {findings.remediation.containment_steps?.join("\n")}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <FileText className="text-cyberPrimary" /> INCIDENT FORENSIC REPORTS
          </h1>
          <p className="text-sm text-gray-400">Exportable executive and forensic incident reports generated by security pipelines</p>
        </div>
        <button 
          onClick={fetchReports}
          className="p-2 bg-gray-900 border border-gray-800 rounded text-gray-400 hover:text-white transition"
        >
          <RefreshCw size={16} />
        </button>
      </div>

      {/* Reports Grid */}
      <div className="glass-panel p-5 rounded-lg">
        <h2 className="text-sm font-semibold tracking-wider text-gray-300 uppercase mb-4">Saved Incident Reports ({reports.length})</h2>

        {loading ? (
          <div className="py-12 text-center text-gray-500">Loading reports...</div>
        ) : reports.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {reports.map((rep) => (
              <div 
                key={rep.report_id} 
                className="p-4 bg-gray-900/40 border border-gray-800 rounded-lg flex justify-between items-center hover:border-cyberPrimary/30 transition"
              >
                <div className="space-y-1">
                  <h4 className="text-sm font-bold text-white">Forensic Report ID {rep.report_id}</h4>
                  <p className="text-xs text-gray-400">{new Date(rep.created_at).toLocaleString()}</p>
                </div>
                <div className="flex gap-2">
                  <button 
                    onClick={() => setSelectedReportId(rep.report_id)}
                    className="p-2 bg-cyberPrimary/10 border border-cyberPrimary/30 text-cyberPrimary rounded hover:bg-cyberPrimary/20 transition"
                  >
                    <Eye size={14} />
                  </button>
                  <button 
                    onClick={() => handleExport(rep, "json")}
                    className="p-2 bg-gray-950 border border-gray-850 text-gray-400 rounded hover:text-white transition"
                  >
                    <Download size={14} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-12 text-center text-gray-500">No incident reports compiled. Generate reports by clicking "Analyze" on log uploads.</div>
        )}
      </div>
    </div>
  );
}
