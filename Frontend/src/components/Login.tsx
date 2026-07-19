import React, { useState } from "react";
import { Shield, Lock, Mail, UserPlus, LogIn, Key } from "lucide-react";
import { useSecurityStore } from "../store/useSecurityStore";
import { getApiClient } from "../services/api";

export default function Login() {
  const { setAuth, apiBaseUrl } = useSecurityStore();
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const client = getApiClient();
      
      if (isRegister) {
        // Register action
        await client.post("/api/v1/auth/register", {
          email,
          password,
          name,
          role: "analyst"
        });
        setIsRegister(false);
        setError("Account registered successfully! You can now log in.");
      } else {
        // Login action (sends JSON body)
        const res = await client.post("/api/v1/auth/login", {
          email,
          password
        });

        const token = res.data.access_token;
        
        // Fetch current user details
        const meClient = getApiClient();
        meClient.defaults.headers.common["Authorization"] = `Bearer ${token}`;
        const meRes = await meClient.get("/api/v1/auth/me");

        setAuth(meRes.data, token);
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || "Authentication request failed. Check server.");
    } finally {
      setLoading(false);
    }
  };

  const handleAdminBypass = () => {
    setEmail("admin@cyberdefense.local");
    setPassword("admin");
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-cyberBg text-gray-200 relative overflow-hidden font-cyber cyber-grid scanline-effect">
      {/* Glow balls */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyberPrimary/10 rounded-full blur-3xl animate-pulse"></div>
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-cyberPurple/10 rounded-full blur-3xl animate-pulse"></div>

      {/* Main card */}
      <div className="w-full max-w-md p-8 glass-panel rounded-xl shadow-glow relative z-10 space-y-6">
        {/* Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex p-3 bg-cyberPrimary/10 border border-cyberPrimary/30 rounded-full text-cyberPrimary shadow-glow mb-2 animate-bounce">
            <Shield size={36} />
          </div>
          <h2 className="text-2xl font-extrabold text-white tracking-widest uppercase">CYBER DEFENSE NETWORK</h2>
          <p className="text-xs text-gray-400">AUTHENTICATION SECURE GATEWAY</p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          {isRegister && (
            <div className="space-y-1">
              <label className="block text-[10px] font-bold text-gray-400 uppercase">Full Name</label>
              <input 
                type="text" 
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full bg-gray-900/60 border border-gray-800 focus:border-cyberPrimary rounded p-2 text-sm text-white focus:outline-none"
                placeholder="Agent Name"
              />
            </div>
          )}

          <div className="space-y-1">
            <label className="block text-[10px] font-bold text-gray-400 uppercase">Secure Email</label>
            <div className="relative">
              <Mail className="absolute left-3 top-2.5 text-gray-500" size={16} />
              <input 
                type="email" 
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full pl-9 bg-gray-900/60 border border-gray-800 focus:border-cyberPrimary rounded p-2 text-sm text-white focus:outline-none"
                placeholder="agent@defense.local"
              />
            </div>
          </div>

          <div className="space-y-1">
            <label className="block text-[10px] font-bold text-gray-400 uppercase">Cryptographic Password</label>
            <div className="relative">
              <Lock className="absolute left-3 top-2.5 text-gray-500" size={16} />
              <input 
                type="password" 
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full pl-9 bg-gray-900/60 border border-gray-800 focus:border-cyberPrimary rounded p-2 text-sm text-white focus:outline-none"
                placeholder="••••••••••••"
              />
            </div>
          </div>

          {error && (
            <div className="p-3 bg-cyberDanger/10 border border-cyberDanger/20 text-cyberDanger text-xs rounded text-center">
              {error}
            </div>
          )}

          <button 
            type="submit"
            disabled={loading}
            className="w-full py-2.5 bg-cyberPrimary text-black font-extrabold rounded hover:bg-cyberPrimary/80 transition text-sm flex items-center justify-center gap-2 shadow-glow uppercase"
          >
            {loading ? (
              <span className="animate-spin rounded-full h-4 w-4 border-t-2 border-b-2 border-black"></span>
            ) : isRegister ? (
              <>
                <UserPlus size={16} /> Create SOC Account
              </>
            ) : (
              <>
                <LogIn size={16} /> Secure Access
              </>
            )}
          </button>
        </form>

        {/* Toggle Mode & Auto login */}
        <div className="flex flex-col gap-3 text-center border-t border-gray-850 pt-4">
          <button 
            onClick={() => {
              setIsRegister(!isRegister);
              setError(null);
            }}
            className="text-xs text-cyberPrimary hover:underline"
          >
            {isRegister ? "Already have account? Sign In" : "Need credentials? Sign Up"}
          </button>

          {!isRegister && (
            <button 
              onClick={handleAdminBypass}
              className="text-[10px] bg-cyberPurple/10 border border-cyberPurple/30 text-cyberPurple hover:bg-cyberPurple/20 transition rounded py-1 px-3 flex items-center justify-center gap-1 mx-auto font-semibold uppercase tracking-wider shadow-purpleGlow"
            >
              <Key size={10} /> Autofill Default Admin Credentials
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
