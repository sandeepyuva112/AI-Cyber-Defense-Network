import React, { useState, useEffect, useRef } from "react";
import { Cpu, Send, Sparkles, User, RefreshCw, AlertCircle } from "lucide-react";
import { getApiClient } from "../services/api";

interface ChatMessage {
  sender: "user" | "copilot";
  text: string;
  timestamp: Date;
}

export default function AICopilot() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);

  // Suggested Prompts
  const suggestions = [
    "Summarize active threat vectors on my network.",
    "Explain how the MITRE execution phase is triggered in event logs.",
    "Provide a containment playbook for ransomware beacons.",
    "What are some common indicators of privilege escalation?"
  ];

  useEffect(() => {
    // Start with a warm greeting from the Copilot
    setMessages([
      {
        sender: "copilot",
        text: "System status: ONLINE. I am your AI Cyber Defense Copilot. I can analyze raw telemetry logs, describe correlated MITRE mappings, explain malware behavior, and provide containment advice. How can I assist your operations today?",
        timestamp: new Date()
      }
    ]);
  }, []);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSend = async (textToSend: string) => {
    if (!textToSend.trim() || sending) return;

    // Add user message
    const userMsg: ChatMessage = { sender: "user", text: textToSend, timestamp: new Date() };
    setMessages(prev => [...prev, userMsg]);
    setInput("");
    setSending(true);

    try {
      const client = getApiClient();
      const payload: any = { prompt: textToSend };
      if (conversationId) {
        payload.conversation_id = conversationId;
      }

      const res = await client.post("/api/v1/ai/copilot", payload);
      
      if (res.data.conversation_id) {
        setConversationId(res.data.conversation_id);
      }

      const copilotMsg: ChatMessage = {
        sender: "copilot",
        text: res.data.response,
        timestamp: new Date()
      };
      setMessages(prev => [...prev, copilotMsg]);
    } catch (err: any) {
      const errorMsg: ChatMessage = {
        sender: "copilot",
        text: `Error contacting Security Copilot backend: ${err.message}. Make sure your OpenAI API key or local model is configured.`,
        timestamp: new Date()
      };
      setMessages(prev => [...prev, errorMsg]);
    } finally {
      setSending(false);
    }
  };

  const handleClear = () => {
    setConversationId(null);
    setMessages([
      {
        sender: "copilot",
        text: "Conversation context cleared. Starting a new session. How can I help you analyze your log telemetry?",
        timestamp: new Date()
      }
    ]);
  };

  return (
    <div className="flex flex-col h-[85vh] space-y-4">
      {/* Title */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Cpu className="text-cyberPurple animate-pulse" /> SECURITY COPILOT
          </h1>
          <p className="text-sm text-gray-400">Conversational security intelligence and mitigation playbook generator</p>
        </div>
        <button 
          onClick={handleClear}
          className="px-3 py-1 bg-gray-900 border border-gray-800 text-gray-400 hover:text-white rounded text-xs font-semibold flex items-center gap-1 transition"
        >
          <RefreshCw size={12} /> Clear Context
        </button>
      </div>

      {/* Main chat window */}
      <div className="flex-1 glass-panel rounded-lg flex flex-col overflow-hidden border border-gray-800 shadow-purpleGlow">
        {/* Messages Stream */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-black/20">
          {messages.map((msg, idx) => (
            <div 
              key={idx} 
              className={`flex items-start gap-3 max-w-[85%] ${
                msg.sender === "user" ? "ml-auto flex-row-reverse" : ""
              }`}
            >
              {/* Icon */}
              <div className={`p-2 rounded-full shrink-0 ${
                msg.sender === "user" ? "bg-cyberPrimary/10 text-cyberPrimary" : "bg-cyberPurple/10 text-cyberPurple"
              }`}>
                {msg.sender === "user" ? <User size={16} /> : <Sparkles size={16} />}
              </div>

              {/* Bubble */}
              <div className={`p-3.5 rounded-lg border text-sm leading-relaxed ${
                msg.sender === "user" 
                  ? "bg-cyberPrimary/5 border-cyberPrimary/20 text-white" 
                  : "bg-cyberPurple/5 border-cyberPurple/20 text-gray-200"
              }`}>
                {msg.text}
                <span className="block text-[9px] text-gray-500 mt-1 text-right">
                  {msg.timestamp.toLocaleTimeString()}
                </span>
              </div>
            </div>
          ))}
          {sending && (
            <div className="flex items-start gap-3">
              <div className="p-2 bg-cyberPurple/10 text-cyberPurple rounded-full animate-bounce">
                <Sparkles size={16} />
              </div>
              <div className="p-3 bg-cyberPurple/5 border border-cyberPurple/20 rounded-lg text-xs text-gray-400">
                Security Copilot is researching playbook...
              </div>
            </div>
          )}
          <div ref={chatEndRef} />
        </div>

        {/* Suggested Actions (only shown if messages are minimal) */}
        {messages.length <= 1 && (
          <div className="px-4 py-3 bg-gray-900/40 border-t border-gray-800 flex flex-wrap gap-2">
            {suggestions.map((s, idx) => (
              <button 
                key={idx}
                onClick={() => handleSend(s)}
                className="px-3 py-1.5 bg-gray-950 border border-gray-800 hover:border-cyberPurple/50 rounded text-xs text-gray-300 hover:text-white transition"
              >
                {s}
              </button>
            ))}
          </div>
        )}

        {/* Input box */}
        <div className="p-4 bg-gray-950/80 border-t border-gray-800 flex gap-2">
          <input 
            type="text" 
            placeholder="Type your security prompt or playbook query..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSend(input)}
            className="flex-1 bg-gray-900 border border-gray-800 rounded px-4 py-2.5 text-sm text-white focus:outline-none focus:border-cyberPurple"
          />
          <button 
            onClick={() => handleSend(input)}
            disabled={!input.trim() || sending}
            className="px-4 py-2 bg-cyberPurple text-white rounded hover:bg-cyberPurple/80 transition flex items-center justify-center disabled:opacity-50 shadow-purpleGlow"
          >
            <Send size={16} />
          </button>
        </div>
      </div>
    </div>
  );
}
