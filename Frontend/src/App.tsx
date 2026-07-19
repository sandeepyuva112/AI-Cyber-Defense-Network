import React, { useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useSecurityStore } from "./store/useSecurityStore";
import Login from "./components/Login";
import Dashboard from "./components/Dashboard";
import UploadLogs from "./components/UploadLogs";
import LiveMonitor from "./components/LiveMonitor";
import ThreatExplorer from "./components/ThreatExplorer";
import IOCExplorer from "./components/IOCExplorer";
import MITREExplorer from "./components/MITREExplorer";
import AICopilot from "./components/AICopilot";
import Alerts from "./components/Alerts";
import Reports from "./components/Reports";
import Settings from "./components/Settings";
import { 
  Shield, ShieldAlert, Activity, Upload, Database, 
  Grid, Cpu, AlertTriangle, FileText, Settings as SettingsIcon, LogOut 
} from "lucide-react";

const queryClient = new QueryClient();

export default function App() {
  const { token, user, logout } = useSecurityStore();
  const [activePage, setActivePage] = useState<string>("Dashboard");
  const [pageRefId, setPageRefId] = useState<number | undefined>(undefined);

  const navigateTo = (page: string, refId?: number) => {
    setPageRefId(refId);
    setActivePage(page);
  };

  // Login Bypass / Gate
  if (!token) {
    return <Login />;
  }

  const navItems = [
    { name: "Dashboard", icon: Shield },
    { name: "Live Monitor", icon: Activity },
    { name: "Upload Logs", icon: Upload },
    { name: "Threat Explorer", icon: ShieldAlert },
    { name: "IOC Registry", icon: Database },
    { name: "MITRE Matrix", icon: Grid },
    { name: "AI Copilot", icon: Cpu },
    { name: "Alerts Center", icon: AlertTriangle },
    { name: "Reports", icon: FileText },
    { name: "Settings", icon: SettingsIcon },
  ];

  return (
    <QueryClientProvider client={queryClient}>
      <div className="flex h-screen bg-cyberBg text-gray-200 overflow-hidden font-cyber">
        {/* Cyberpunk Grid Grid Background */}
        <div className="absolute inset-0 cyber-grid opacity-30 pointer-events-none z-0"></div>

        {/* Sidebar */}
        <aside className="w-64 bg-gray-950/80 border-r border-gray-800/80 flex flex-col z-10 glass-panel">
          {/* Logo Brand */}
          <div className="h-16 flex items-center gap-3 px-5 border-b border-gray-800/80 shrink-0">
            <Shield className="text-cyberPrimary animate-pulse" size={24} />
            <div>
              <span className="text-sm font-extrabold text-white tracking-widest block leading-tight">CYBER DEFENSE</span>
              <span className="text-[10px] text-gray-500 font-bold uppercase tracking-wider block">Network SOC</span>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1 scrollbar-none">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isSelected = activePage === item.name || 
                                 (item.name === "Threat Explorer" && activePage === "Threat Explorer") ||
                                 (item.name === "Alerts Center" && activePage === "Alerts") ||
                                 (item.name === "IOC Registry" && activePage === "IOC Explorer") ||
                                 (item.name === "MITRE Matrix" && activePage === "MITRE Explorer");
              
              let targetPageName = item.name;
              if (item.name === "Alerts Center") targetPageName = "Alerts";
              if (item.name === "IOC Registry") targetPageName = "IOC Explorer";
              if (item.name === "MITRE Matrix") targetPageName = "MITRE Explorer";

              return (
                <button
                  key={item.name}
                  onClick={() => navigateTo(targetPageName)}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded text-sm font-semibold transition-all ${
                    isSelected
                      ? "bg-cyberPrimary/10 border border-cyberPrimary/30 text-cyberPrimary text-glow"
                      : "text-gray-400 hover:text-white hover:bg-gray-900/30 border border-transparent"
                  }`}
                >
                  <Icon size={16} />
                  <span>{item.name}</span>
                </button>
              );
            })}
          </nav>

          {/* Profile User Badge & Logout */}
          <div className="p-4 border-t border-gray-800/80 shrink-0 bg-gray-950/45 space-y-3">
            <div className="flex items-center gap-3">
              <div className="h-9 w-9 bg-cyberPurple/10 border border-cyberPurple/30 text-cyberPurple rounded-full flex items-center justify-center font-bold text-sm uppercase shadow-purpleGlow">
                {user?.name ? user.name[0] : "A"}
              </div>
              <div className="min-w-0 flex-1">
                <span className="text-xs font-bold text-white block truncate leading-tight">{user?.name || "Agent analyst"}</span>
                <span className="text-[9px] bg-cyberPrimary/15 border border-cyberPrimary/20 text-cyberPrimary px-1.5 py-0.5 rounded-full inline-block font-extrabold uppercase mt-1">
                  {user?.role || "analyst"}
                </span>
              </div>
            </div>
            
            <button
              onClick={logout}
              className="w-full flex items-center justify-center gap-2 py-1.5 bg-gray-900/60 hover:bg-cyberDanger/10 border border-gray-800 hover:border-cyberDanger/30 rounded text-xs font-bold text-gray-400 hover:text-cyberDanger transition"
            >
              <LogOut size={12} /> Log Out System
            </button>
          </div>
        </aside>

        {/* Content Pane */}
        <main className="flex-1 overflow-y-auto z-10 relative p-6">
          {activePage === "Dashboard" && <Dashboard navigateTo={navigateTo} />}
          {activePage === "Live Monitor" && <LiveMonitor />}
          {activePage === "Upload Logs" && <UploadLogs navigateTo={navigateTo} />}
          {activePage === "Threat Explorer" && <ThreatExplorer initialRefId={pageRefId} />}
          {activePage === "IOC Explorer" && <IOCExplorer />}
          {activePage === "MITRE Explorer" && <MITREExplorer />}
          {activePage === "AI Copilot" && <AICopilot />}
          {activePage === "Alerts" && <Alerts />}
          {activePage === "Reports" && <Reports />}
          {activePage === "Settings" && <Settings />}
        </main>
      </div>
    </QueryClientProvider>
  );
}
