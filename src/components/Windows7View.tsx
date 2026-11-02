"use client";

import React, { useState, useEffect, useRef } from "react";
import { analyzeUrl } from "@/services/analyzer";
import { AnalysisResult } from "@/types";

interface Windows7ViewProps {
  onSwitchToModern?: () => void;
}

export function Windows7View({ onSwitchToModern }: Windows7ViewProps) {
  const [activeTab, setActiveTab] = useState<"dashboard" | "terminal">("dashboard");
  const [inputUrl, setInputUrl] = useState("http://192.0.2.10/login");
  const [result, setResult] = useState<AnalysisResult>(() => analyzeUrl("http://192.0.2.10/login"));

  // Terminal state
  const [termHistory, setTermHistory] = useState<Array<{ type: "cmd" | "out" | "err" | "info"; text: string }>>([
    { type: "info", text: "Microsoft Windows [Version 6.1.7601] (Windows 7 Ultimate SP1)" },
    { type: "info", text: "(c) 2009 Microsoft Corporation. All rights reserved." },
    { type: "info", text: "" },
    { type: "cmd", text: "python phishing_checker.py" },
    { type: "out", text: "================================" },
    { type: "out", text: "PHISHING URL AWARENESS CHECKER" },
    { type: "out", text: "================================" },
    { type: "out", text: "" },
    { type: "out", text: "Warnings Found:" },
    { type: "err", text: "[1] HTTP detected (Weight: 15)" },
    { type: "err", text: "[2] IP address host detected (Weight: 35)" },
    { type: "err", text: "[3] Suspicious keyword detected: 'login' (Weight: 25)" },
    { type: "out", text: "" },
    { type: "err", text: "Risk Score: 75/100" },
    { type: "err", text: "Classification: HIGH RISK" },
    { type: "out", text: "Recommendation: Review carefully before interacting. High probability of deceptive credential harvesting." },
    { type: "out", text: "================================" },
  ]);
  const [termInput, setTermInput] = useState("");
  const termEndRef = useRef<HTMLDivElement>(null);
  const termInputRef = useRef<HTMLInputElement>(null);

  // Auto-scroll terminal
  useEffect(() => {
    if (activeTab === "terminal") {
      termEndRef.current?.scrollIntoView({ behavior: "smooth" });
      termInputRef.current?.focus();
    }
  }, [termHistory, activeTab]);

  const runAnalysis = (url: string) => {
    const res = analyzeUrl(url);
    setResult(res);

    // Also append to terminal log
    setTermHistory((prev) => {
      const logs: Array<{ type: "cmd" | "out" | "err" | "info"; text: string }> = [
        ...prev,
        { type: "cmd", text: `python phishing_checker.py --url "${url}"` },
        { type: "out", text: "================================" },
        { type: "out", text: "PHISHING URL AWARENESS CHECKER" },
        { type: "out", text: "================================" },
      ];

      if (!res.isValid) {
        logs.push({ type: "err", text: `[!] Input Error: ${res.errorMessage}` });
        logs.push({ type: "out", text: `Recommendation: ${res.recommendation}` });
      } else {
        if (res.findings.length === 0) {
          logs.push({ type: "info", text: "Warnings Found: None (0 warnings detected)" });
        } else {
          logs.push({ type: "out", text: `Warnings Found (${res.findings.length}):` });
          res.findings.forEach((f, idx) => {
            logs.push({ type: "err", text: `[${idx + 1}] ${f.title} (${f.code})` });
          });
        }
        logs.push({ type: "out", text: "" });
        logs.push({
          type: res.riskScore >= 70 ? "err" : res.riskScore >= 40 ? "err" : "info",
          text: `Risk Score: ${res.riskScore}/100`,
        });
        logs.push({
          type: res.riskScore >= 70 ? "err" : res.riskScore >= 40 ? "err" : "info",
          text: `Classification: ${res.classification}`,
        });
        logs.push({ type: "out", text: `Recommendation: ${res.recommendation}` });
      }
      logs.push({ type: "out", text: "================================" });
      logs.push({ type: "out", text: "" });
      return logs;
    });
  };

  const handleInspectSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputUrl.trim()) return;
    runAnalysis(inputUrl);
  };

  const handleTerminalCommand = (e: React.FormEvent) => {
    e.preventDefault();
    const cmd = termInput.trim();
    if (!cmd) return;

    setTermInput("");
    const lower = cmd.toLowerCase();

    if (lower === "cls" || lower === "clear") {
      setTermHistory([
        { type: "info", text: "Microsoft Windows [Version 6.1.7601] (Windows 7 Ultimate SP1)" },
        { type: "info", text: "(c) 2009 Microsoft Corporation. All rights reserved." },
        { type: "info", text: "" },
      ]);
      return;
    }

    if (lower === "help") {
      setTermHistory((prev) => [
        ...prev,
        { type: "cmd", text: cmd },
        { type: "info", text: "Supported Commands:" },
        { type: "out", text: "  scan <url>          Inspect any URL for phishing indicators" },
        { type: "out", text: "  <url>               Direct URL input (automatically scanned)" },
        { type: "out", text: "  samples             List benchmark test URLs" },
        { type: "out", text: "  cls | clear         Clear screen" },
        { type: "out", text: "  help                Display this manual" },
        { type: "out", text: "" },
      ]);
      return;
    }

    if (lower === "samples") {
      setTermHistory((prev) => [
        ...prev,
        { type: "cmd", text: cmd },
        { type: "info", text: "Available Test Samples:" },
        { type: "out", text: "  1. https://www.google.com/  (Clean HTTPS Benchmark)" },
        { type: "out", text: "  2. http://192.0.2.10/login  (IP + HTTP + Login Lure)" },
        { type: "out", text: "  3. http://google.com@attacker.invalid/login  (Userinfo @)" },
        { type: "out", text: "  4. https://xn--example.invalid/  (Punycode IDN)" },
        { type: "out", text: "  5. https://a.b.c.d.e.target.invalid/  (Deep Subdomains)" },
        { type: "out", text: "  6. https://claude.ai/chat/c6bfaa97-602e-4ba5-9087-69c654157747  (Claude Chat)" },
        { type: "out", text: "" },
        { type: "info", text: "Type any sample above to scan instantly." },
      ]);
      return;
    }

    let targetUrl = cmd;
    if (cmd.startsWith("scan ")) {
      targetUrl = cmd.replace(/^scan\s+/, "").trim();
    } else if (cmd.startsWith("python phishing_checker.py ")) {
      targetUrl = cmd.replace(/^python\s+phishing_checker\.py\s+/, "").trim();
    }

    setInputUrl(targetUrl);
    runAnalysis(targetUrl);
  };

  const sampleButtons = [
    { label: "Clean HTTPS", url: "https://www.google.com/" },
    { label: "IP + HTTP + Login", url: "http://192.0.2.10/login" },
    { label: "@ Disguise", url: "http://example.com@sample.invalid/login" },
    { label: "Punycode (xn--)", url: "https://xn--example.invalid/" },
    { label: "5 Subdomains", url: "https://a.b.c.d.e.example.invalid/path" },
    { label: "Claude Chat (Safe)", url: "https://claude.ai/chat/c6bfaa97-602e-4ba5-9087-69c654157747" },
  ];

  // Helper colors
  const getBadgeStyle = () => {
    switch (result.classification) {
      case "HIGH RISK":
        return "bg-red-600 text-white border-red-700";
      case "MEDIUM RISK":
        return "bg-amber-500 text-slate-900 border-amber-600 font-bold";
      case "LOW RISK":
        return "bg-yellow-400 text-slate-900 border-yellow-500";
      default:
        return "bg-emerald-600 text-white border-emerald-700";
    }
  };

  const getScoreColor = () => {
    if (result.riskScore >= 70) return "#dc2626";
    if (result.riskScore >= 40) return "#d97706";
    if (result.riskScore >= 20) return "#ca8a04";
    return "#16a34a";
  };

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_50%_30%,#1e5799_0%,#133966_50%,#0a1b33_100%)] font-sans p-3 sm:p-6 flex flex-col justify-between select-none text-slate-800">
      
      {/* Top Bar Switcher to Modern SOC */}
      <div className="max-w-4xl w-full mx-auto mb-3 flex items-center justify-between text-xs text-white/90">
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-cyan-300 animate-pulse" />
          <span className="font-semibold drop-shadow-sm">Windows 7 Aero Glass Security Shell (v6.1.7601)</span>
        </div>
        {onSwitchToModern && (
          <button
            onClick={onSwitchToModern}
            className="px-3 py-1 rounded bg-white/20 hover:bg-white/30 backdrop-blur-md border border-white/40 text-white text-xs font-semibold shadow transition-all cursor-pointer"
          >
            Switch to Modern SOC Dark UI &rarr;
          </button>
        )}
      </div>

      {/* Main Aero Glass Window */}
      <div className="max-w-4xl w-full mx-auto rounded-lg overflow-hidden border border-white/60 bg-white/85 backdrop-blur-2xl shadow-[0_20px_60px_rgba(0,0,0,0.65),0_0_20px_rgba(255,255,255,0.4)_inset]">
        
        {/* Title Bar (Authentic Aero Gloss) */}
        <div className="bg-gradient-to-b from-white/70 via-white/30 to-blue-300/40 border-b border-white/50 px-4 py-2 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <span className="text-lg drop-shadow">🛡️</span>
            <span className="text-sm font-semibold text-slate-900 tracking-wide drop-shadow-[0_1px_1px_rgba(255,255,255,0.8)]">
              Phishing URL Awareness Checker - [Version 6.1.7601]
            </span>
          </div>
          {/* Win7 Window Controls */}
          <div className="flex items-center gap-1.5">
            <button className="w-6 h-5 rounded flex items-center justify-center bg-gradient-to-b from-slate-100 to-slate-300 hover:from-white hover:to-slate-200 border border-slate-400 text-[11px] text-slate-700 shadow-sm cursor-pointer">
              _
            </button>
            <button className="w-6 h-5 rounded flex items-center justify-center bg-gradient-to-b from-slate-100 to-slate-300 hover:from-white hover:to-slate-200 border border-slate-400 text-[11px] text-slate-700 shadow-sm cursor-pointer">
              □
            </button>
            <button
              onClick={onSwitchToModern}
              className="w-7 h-5 rounded flex items-center justify-center bg-gradient-to-b from-red-400 to-red-600 hover:from-red-300 hover:to-red-500 border border-red-700 text-[11px] font-bold text-white shadow-sm cursor-pointer"
              title="Close and return to Modern SOC"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="bg-slate-200/90 border-b border-slate-300 px-4 pt-2 flex items-center gap-2">
          <button
            onClick={() => setActiveTab("dashboard")}
            className={`px-4 py-2 rounded-t-md text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer ${
              activeTab === "dashboard"
                ? "bg-white text-blue-900 border-t-2 border-t-blue-500 border-x border-slate-300 shadow-sm"
                : "text-slate-600 hover:text-slate-900 hover:bg-slate-100/60"
            }`}
          >
            <span>🛡️</span> Security Dashboard
          </button>
          <button
            onClick={() => setActiveTab("terminal")}
            className={`px-4 py-2 rounded-t-md text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer ${
              activeTab === "terminal"
                ? "bg-white text-blue-900 border-t-2 border-t-blue-500 border-x border-slate-300 shadow-sm"
                : "text-slate-600 hover:text-slate-900 hover:bg-slate-100/60"
            }`}
          >
            <span>💻</span> Windows Command Prompt (cmd.exe)
          </button>
        </div>

        {/* Content Area */}
        <div className="p-4 sm:p-6 bg-gradient-to-b from-slate-50 to-slate-100 min-h-[460px]">
          
          {activeTab === "dashboard" ? (
            <div className="space-y-5">
              
              {/* Banner */}
              <div className="flex items-center gap-3.5 p-3.5 rounded-lg bg-gradient-to-r from-blue-600 via-blue-700 to-indigo-800 text-white shadow-md">
                <div className="w-10 h-10 rounded-lg bg-white/20 border border-white/30 flex items-center justify-center text-xl shrink-0">
                  🛡️
                </div>
                <div>
                  <h2 className="text-sm sm:text-base font-bold">
                    Zero-Network Static Heuristic Inspection Engine
                  </h2>
                  <p className="text-xs text-blue-100">
                    RFC 3986 syntactic analysis with zero outbound sockets. Safe to evaluate live phishing targets offline.
                  </p>
                </div>
              </div>

              {/* Form Input */}
              <form onSubmit={handleInspectSubmit} className="space-y-3">
                <div className="flex flex-col sm:flex-row gap-2">
                  <input
                    type="text"
                    value={inputUrl}
                    onChange={(e) => setInputUrl(e.target.value)}
                    placeholder="Enter URL to inspect (e.g. http://192.0.2.10/login)..."
                    className="flex-1 px-3.5 py-2.5 rounded border border-slate-300 bg-white text-slate-800 font-mono text-xs sm:text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 shadow-inner"
                  />
                  <button
                    type="submit"
                    className="px-6 py-2.5 rounded bg-gradient-to-b from-blue-500 to-blue-700 hover:from-blue-400 hover:to-blue-600 text-white text-xs sm:text-sm font-bold border border-blue-800 shadow-[0_2px_4px_rgba(0,0,0,0.2)] cursor-pointer shrink-0"
                  >
                    Inspect Link
                  </button>
                </div>

                {/* Sample Pills */}
                <div className="flex items-center flex-wrap gap-1.5 pt-1">
                  <span className="text-[11px] font-semibold text-slate-500 mr-1">Test Samples:</span>
                  {sampleButtons.map((btn, i) => (
                    <button
                      key={i}
                      type="button"
                      onClick={() => {
                        setInputUrl(btn.url);
                        runAnalysis(btn.url);
                      }}
                      className="px-2.5 py-1 rounded-full bg-white hover:bg-slate-200 border border-slate-300 text-slate-700 text-[11px] font-medium shadow-xs transition-colors cursor-pointer"
                    >
                      {btn.label}
                    </button>
                  ))}
                </div>
              </form>

              {/* Inspection Results Box */}
              <div className="p-4 rounded-lg bg-white border border-slate-200 shadow-sm space-y-4">
                
                {/* Score & Classification Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-200">
                  <div>
                    <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                      Composite Risk Assessment
                    </span>
                    <div className="flex items-baseline gap-2 mt-0.5">
                      <span className="text-3xl font-extrabold" style={{ color: getScoreColor() }}>
                        {result.riskScore}
                      </span>
                      <span className="text-slate-400 text-sm font-bold">/ 100</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-500 font-medium">Classification:</span>
                    <span className={`px-3 py-1 rounded text-xs font-extrabold uppercase border shadow-xs ${getBadgeStyle()}`}>
                      {result.classification}
                    </span>
                  </div>
                </div>

                {/* Warnings List */}
                <div>
                  <h4 className="text-xs font-bold text-slate-700 mb-2 flex items-center justify-between">
                    <span>Active Warnings Detected</span>
                    <span className="text-[11px] font-normal text-slate-500">
                      {result.findings.length} findings
                    </span>
                  </h4>

                  {result.findings.length === 0 ? (
                    <div className="p-3 rounded bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs font-semibold flex items-center gap-2">
                      <span>✓</span> No malicious heuristics triggered. Clean structure based on RFC 3986 lexical evaluation.
                    </div>
                  ) : (
                    <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                      {result.findings.map((finding, idx) => (
                        <div
                          key={idx}
                          className="p-2.5 rounded bg-slate-50 border border-slate-200 flex items-start justify-between gap-2 text-xs"
                        >
                          <div className="flex items-start gap-2">
                            <span className="font-bold text-amber-600">[{idx + 1}]</span>
                            <div>
                              <span className="font-bold text-slate-800">{finding.title}</span>
                              <p className="text-[11px] text-slate-600 mt-0.5">{finding.description}</p>
                            </div>
                          </div>
                          <span className="px-2 py-0.5 rounded bg-slate-200 text-slate-700 font-mono text-[10px] font-bold shrink-0">
                            +{finding.points} pts
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Recommendation Box */}
                <div className="p-3 rounded bg-blue-50 border border-blue-200 text-xs text-blue-900">
                  <span className="font-bold">Official Recommendation: </span>
                  <span>{result.recommendation}</span>
                </div>

              </div>

            </div>
          ) : (
            /* TERMINAL VIEW (Windows 7 cmd.exe look) */
            <div className="rounded border border-slate-700 bg-[#0c0c0c] text-[#cccccc] font-mono text-xs sm:text-sm p-4 min-h-[440px] max-h-[500px] flex flex-col justify-between shadow-2xl">
              <div className="overflow-y-auto space-y-1 pr-1 flex-1 max-h-[400px]">
                {termHistory.map((line, i) => (
                  <div key={i} className="leading-relaxed">
                    {line.type === "cmd" && (
                      <div>
                        <span className="text-cyan-400">C:\Users\ManishPatil&gt; </span>
                        <span className="text-white font-bold">{line.text}</span>
                      </div>
                    )}
                    {line.type === "info" && <div className="text-slate-400">{line.text}</div>}
                    {line.type === "out" && <div className="text-slate-200">{line.text}</div>}
                    {line.type === "err" && <div className="text-amber-400 font-semibold">{line.text}</div>}
                  </div>
                ))}
                <div ref={termEndRef} />
              </div>

              {/* Command Input Prompt */}
              <form onSubmit={handleTerminalCommand} className="flex items-center gap-2 pt-3 border-t border-slate-800 mt-2">
                <span className="text-cyan-400 shrink-0">C:\Users\ManishPatil&gt;</span>
                <input
                  ref={termInputRef}
                  type="text"
                  value={termInput}
                  onChange={(e) => setTermInput(e.target.value)}
                  placeholder="type url, 'samples', 'cls', or 'help'..."
                  className="flex-1 bg-transparent text-white font-mono text-xs sm:text-sm outline-none border-none focus:ring-0 p-0"
                />
              </form>
            </div>
          )}

        </div>

        {/* Status Bar */}
        <div className="bg-gradient-to-b from-slate-200 to-slate-300 border-t border-slate-300 px-4 py-1.5 flex items-center justify-between text-[11px] text-slate-600">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block" />
            <span>Local Protection: Active (Zero Network Transmission)</span>
          </div>
          <div className="hidden sm:flex items-center gap-4">
            <span>Heuristic Engine: RFC 3986 Standard</span>
            <span className="font-semibold text-slate-800">Manish Pundlik Patil (EWB-OL-2026-CYB-0195)</span>
          </div>
        </div>

      </div>

      {/* Windows 7 Desktop Taskbar */}
      <div className="max-w-4xl w-full mx-auto mt-4 rounded-lg bg-gradient-to-b from-slate-900/90 via-slate-950/95 to-black/95 border border-white/20 backdrop-blur-md px-3 py-1.5 flex items-center justify-between text-xs text-slate-200 shadow-xl">
        <div className="flex items-center gap-2">
          {/* Start Orb */}
          <div className="w-7 h-7 rounded-full bg-gradient-to-tr from-blue-700 via-blue-500 to-cyan-300 border-2 border-white/80 flex items-center justify-center text-xs font-bold text-white shadow-[0_0_10px_rgba(59,130,246,0.8)] cursor-pointer">
            ❖
          </div>
          <div className="px-3 py-1 rounded bg-white/15 border border-white/20 text-xs font-medium flex items-center gap-2">
            <span>🛡️</span>
            <span>Phishing URL Checker</span>
          </div>
        </div>

        <div className="flex items-center gap-3 text-[11px] text-slate-300 font-mono">
          <span>⚡ Local Zero-Socket</span>
          <span className="hidden sm:inline">|</span>
          <span className="hidden sm:inline">100% Safe Offline</span>
        </div>
      </div>

    </div>
  );
}
