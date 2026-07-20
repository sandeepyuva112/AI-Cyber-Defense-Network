import React, { useState, useEffect } from "react";
import { Grid, ShieldCheck, Tag } from "lucide-react";
import { getApiClient } from "../services/api";

export default function MITREExplorer() {
  const [mappings, setMappings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchMITRE = async () => {
      try {
        const client = getApiClient();
        const res = await client.get("/api/v1/threats/mitre/all?limit=100");
        setMappings(res.data);
      } catch (err) {
        console.error("Error loading MITRE mappings:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchMITRE();
  }, []);

  // Standard MITRE ATT&CK Tactics
  const tacticsList = [
    { name: "Initial Access", key: "initial_access" },
    { name: "Execution", key: "execution" },
    { name: "Persistence", key: "persistence" },
    { name: "Privilege Escalation", key: "privilege_escalation" },
    { name: "Defense Evasion", key: "defense_evasion" },
    { name: "Credential Access", key: "credential_access" },
    { name: "Discovery", key: "discovery" },
    { name: "Command and Control", key: "command_and_control" },
    { name: "Exfiltration", key: "exfiltration" }
  ];

  // Helper to check if mapping aligns with tactic name (case-insensitive fuzzy match)
  // Helper to check if mapping aligns with tactic name (case-insensitive fuzzy match)
  const getTechniquesForTactic = (tacticKey: string) => {
    const tName = tacticKey.replace(/_/g, " ").replace(/-/g, " ").toLowerCase();
    
    // Extract matching techniques
    const matching: any[] = [];
    mappings.forEach(m => {
      const match = m.tactics.some((t: string) => {
        const normalizedT = t.replace(/_/g, " ").replace(/-/g, " ").toLowerCase();
        return normalizedT.includes(tName) || tName.includes(normalizedT);
      });
      if (match) {
        // avoid duplicate technique additions
        if (!matching.some(x => x.technique_id === m.technique_id)) {
          matching.push(m);
        }
      }
    });

    return matching;
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <Grid className="text-cyberPrimary" /> MITRE ATT&CK® MATRIX
        </h1>
        <p className="text-sm text-gray-400">Tactical alignment of detected threat vectors with the global security framework</p>
      </div>

      {loading ? (
        <div className="py-12 text-center text-gray-500">Compiling matrix alignment...</div>
      ) : (
        <div className="glass-panel p-5 rounded-lg overflow-x-auto">
          <div className="flex gap-4 min-w-[1200px] pb-4">
            {tacticsList.map(tactic => {
              const techniques = getTechniquesForTactic(tactic.key);
              const isActive = techniques.length > 0;

              return (
                <div 
                  key={tactic.key} 
                  className={`flex-1 min-w-[150px] p-3 rounded-lg border flex flex-col justify-start h-[50vh] ${
                    isActive 
                      ? "bg-cyberPrimary/5 border-cyberPrimary/20" 
                      : "bg-gray-900/10 border-gray-900/60"
                  }`}
                >
                  <div className="pb-2 border-b border-gray-800/80 mb-3">
                    <h3 className={`text-xs font-extrabold uppercase tracking-widest ${
                      isActive ? "text-cyberPrimary text-glow" : "text-gray-500"
                    }`}>
                      {tactic.name}
                    </h3>
                    <span className="text-[10px] text-gray-400 font-bold">{techniques.length} Active</span>
                  </div>

                  <div className="flex-1 overflow-y-auto space-y-2.5">
                    {isActive ? (
                      techniques.map((tech, idx) => (
                        <div 
                          key={idx} 
                          className="p-2 bg-gray-950 border border-cyberPrimary/30 rounded text-[11px] text-white hover:border-cyberPrimary transition cursor-default shadow-glow"
                        >
                          <div className="font-mono text-cyberPrimary font-bold text-[9px] mb-0.5">{tech.technique_id}</div>
                          <div className="font-semibold leading-tight">{tech.technique_name}</div>
                        </div>
                      ))
                    ) : (
                      <div className="h-full flex items-center justify-center text-[10px] text-gray-600 italic">No techniques active</div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
