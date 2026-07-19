import React, { useState, useEffect } from "react";
import { Database, Search, ShieldAlert, Cpu } from "lucide-react";
import { getApiClient } from "../services/api";

export default function IOCExplorer() {
  const [iocs, setIocs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [filterType, setFilterType] = useState("all");

  useEffect(() => {
    const fetchIOCs = async () => {
      try {
        const client = getApiClient();
        const res = await client.get("/api/v1/threats/iocs/all?limit=100");
        setIocs(res.data);
      } catch (err) {
        console.error("Error loading IOCs:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchIOCs();
  }, []);

  const filteredIOCs = iocs.filter((ioc) => {
    const matchSearch = ioc.ioc_value.toLowerCase().includes(search.toLowerCase());
    const matchType = filterType === "all" || ioc.ioc_type?.toLowerCase() === filterType.toLowerCase();
    return matchSearch && matchType;
  });

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <Database className="text-cyberPrimary" /> IOC ARCHIVE & CORRELATION
        </h1>
        <p className="text-sm text-gray-400">Indicators of compromise extracted during raw log execution</p>
      </div>

      {/* Filters */}
      <div className="flex flex-col md:flex-row gap-4 justify-between bg-gray-900/30 p-4 border border-gray-800/60 rounded-lg">
        {/* Search */}
        <div className="relative w-full md:w-96">
          <Search className="absolute left-3 top-2.5 text-gray-500" size={16} />
          <input 
            type="text" 
            placeholder="Search IOC values (IPs, file hashes, domains)..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-gray-950 border border-gray-800 rounded text-sm text-white focus:outline-none focus:border-cyberPrimary"
          />
        </div>
        {/* Filter */}
        <select 
          value={filterType} 
          onChange={(e) => setFilterType(e.target.value)}
          className="bg-gray-950 border border-gray-800 rounded text-sm text-white p-2 focus:outline-none focus:border-cyberPrimary"
        >
          <option value="all">All IOC Types</option>
          <option value="ip">IP Addresses</option>
          <option value="domain">Domain Names</option>
          <option value="url">URLs</option>
          <option value="sha256">SHA256 Hashes</option>
        </select>
      </div>

      {/* Grid of IOC cards */}
      <div className="glass-panel p-5 rounded-lg">
        <h2 className="text-sm font-semibold tracking-wider text-gray-300 uppercase mb-4">Extracted Indicators ({filteredIOCs.length})</h2>

        {loading ? (
          <div className="py-12 text-center text-gray-500">Loading indicators...</div>
        ) : filteredIOCs.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {filteredIOCs.map((ioc) => (
              <div 
                key={ioc.ioc_id} 
                className="p-3 bg-gray-950/60 border border-gray-850 rounded hover:border-cyberPrimary/30 transition flex flex-col justify-between"
              >
                <div>
                  <span className={`px-2 py-0.5 text-[9px] font-bold rounded uppercase tracking-wider ${
                    ioc.ioc_type === "ip" ? "bg-cyberPrimary/10 border border-cyberPrimary/20 text-cyberPrimary" :
                    ioc.ioc_type === "domain" ? "bg-cyberPurple/10 border border-cyberPurple/20 text-cyberPurple" :
                    "bg-cyberWarning/10 border border-cyberWarning/20 text-cyberWarning"
                  }`}>
                    {ioc.ioc_type || "indicator"}
                  </span>
                  <div className="mt-2 font-mono text-xs text-white break-all">{ioc.ioc_value}</div>
                </div>
                <div className="mt-3 flex justify-between items-center text-[10px] text-gray-500 border-t border-gray-900 pt-2">
                  <span>Target: Incident Context</span>
                  <span className="text-cyberPrimary uppercase font-bold flex items-center gap-0.5">
                    <ShieldAlert size={10} /> Active
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-12 text-center text-gray-500">No indicators match current filter settings.</div>
        )}
      </div>
    </div>
  );
}
