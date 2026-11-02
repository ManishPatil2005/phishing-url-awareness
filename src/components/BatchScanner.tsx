"use client";

import React, { useState } from "react";
import { analyzeThreatV2 } from "@/services/scorerV2";
import { defangUrl } from "@/utils/defang";
import { EngineV2Result } from "@/services/scorerV2";
import {
  FileText,
  Download,
  Upload,
  AlertTriangle,
  ShieldCheck,
  CheckCircle2,
  Trash2,
  Filter,
} from "lucide-react";

export function BatchScanner() {
  const [inputText, setInputText] = useState("");
  const [results, setResults] = useState<EngineV2Result[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [filterTier, setFilterTier] = useState<string>("ALL");

  const handleRunBatch = () => {
    const lines = inputText
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith("#"));

    if (lines.length === 0) return;

    setIsProcessing(true);
    // Limit to 500 lines for local performance safety
    const batch = lines.slice(0, 500);

    const analyzed = batch.map((url) => analyzeThreatV2(url));
    setResults(analyzed);
    setIsProcessing(false);
  };

  const handleLoadSampleBatch = () => {
    const samples = [
      "https://www.google.com/",
      "http://192.0.2.10/login",
      "https://github.com/ManishPatil2005",
      "http://paypal.com@verify-account.invalid/signin",
      "https://g00gle.com/secure-login",
      "https://claude.ai/chat/c6bfaa97-602e-4ba5-9087-69c654157747",
      "https://onlinesbi-portal-kyc-update.com/login",
      "https://secure-invoice-download.zip/",
      "https://apple.com/iphone",
      "http://secure-online-banking-portal.update.com/otp",
    ];
    setInputText(samples.join("\n"));
  };

  const exportCsv = () => {
    if (results.length === 0) return;
    const headers = ["Defanged URL", "Risk Score", "Classification", "Finding Count", "Recommendation"];
    const rows = results.map((r) => [
      `"${defangUrl(r.rawUrl)}"`,
      r.riskScore,
      `"${r.classification}"`,
      r.findings.length,
      `"${r.recommendation.replace(/"/g, '""')}"`,
    ]);
    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map((e) => e.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `phishintel_batch_report_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const exportJson = () => {
    if (results.length === 0) return;
    const cleanJson = results.map((r) => ({
      rawUrl: r.rawUrl,
      defangedUrl: defangUrl(r.rawUrl),
      riskScore: r.riskScore,
      classification: r.classification,
      findingsCount: r.findings.length,
      findings: r.findings.map((f) => ({ code: f.ruleCode, name: f.name, severity: f.severity })),
      categoryScores: r.categoryScores,
      combinationBonuses: r.combinationBonuses,
      recommendation: r.recommendation,
    }));
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(cleanJson, null, 2));
    const link = document.createElement("a");
    link.setAttribute("href", dataStr);
    link.setAttribute("download", `phishintel_batch_report_${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const filteredResults = results.filter((r) => {
    if (filterTier === "ALL") return true;
    return r.classification === filterTier;
  });

  const highRiskCount = results.filter((r) => r.classification === "HIGH RISK").length;
  const medRiskCount = results.filter((r) => r.classification === "MEDIUM RISK").length;
  const safeCount = results.filter((r) => r.classification === "SAFE-LOOKING").length;

  return (
    <div className="rounded-2xl border border-border bg-card p-5 sm:p-6 shadow-sm space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-base sm:text-lg font-bold text-slate-100 flex items-center gap-2">
            <span>⚡ High-Throughput Batch Scanner</span>
            <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/20">
              Up to 500 URLs
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Instantaneous, zero-network parallel inspection. All analysis executes locally in-memory.
          </p>
        </div>

        <button
          onClick={handleLoadSampleBatch}
          className="text-xs text-primary hover:underline font-semibold cursor-pointer text-left sm:text-right"
        >
          Load 10 Benchmark Samples &rarr;
        </button>
      </div>

      {/* Input Textarea */}
      <div className="space-y-2">
        <textarea
          rows={5}
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          placeholder="Paste up to 500 candidate URLs (one per line)...&#10;https://www.example.com/&#10;http://192.0.2.10/login&#10;https://g00gle.com/secure-login"
          className="w-full rounded-xl border border-border bg-slate-950 p-3.5 font-mono text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-primary/40 resize-y"
        />

        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="text-[11px] text-slate-400">
            {inputText.split("\n").filter((l) => l.trim().length > 0).length} target lines ready
          </div>

          <div className="flex items-center gap-2">
            {results.length > 0 && (
              <button
                onClick={() => {
                  setResults([]);
                  setInputText("");
                }}
                className="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear</span>
              </button>
            )}

            <button
              onClick={handleRunBatch}
              disabled={isProcessing || !inputText.trim()}
              className="px-5 py-2 rounded-xl bg-primary hover:bg-blue-600 disabled:opacity-50 text-white font-bold text-xs shadow-md transition-all cursor-pointer flex items-center gap-2"
            >
              <span>{isProcessing ? "Analyzing..." : "Analyze Batch (0ms Sockets)"}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Results Section */}
      {results.length > 0 && (
        <div className="space-y-4 pt-3 border-t border-border">
          
          {/* Summary Pills & Export Controls */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2 flex-wrap text-xs">
              <span className="font-semibold text-slate-300">Summary:</span>
              <span className="px-2.5 py-1 rounded-md bg-red-500/10 border border-red-500/30 text-red-400 font-bold">
                {highRiskCount} High Risk
              </span>
              <span className="px-2.5 py-1 rounded-md bg-amber-500/10 border border-amber-500/30 text-amber-400 font-bold">
                {medRiskCount} Medium
              </span>
              <span className="px-2.5 py-1 rounded-md bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-bold">
                {safeCount} Safe-looking
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={exportCsv}
                className="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5 text-primary" />
                <span>Export CSV</span>
              </button>
              <button
                onClick={exportJson}
                className="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
              >
                <FileText className="w-3.5 h-3.5 text-cyan-400" />
                <span>Export JSON</span>
              </button>
            </div>
          </div>

          {/* Filter Bar */}
          <div className="flex items-center gap-2 text-xs">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-400">Filter View:</span>
            {["ALL", "HIGH RISK", "MEDIUM RISK", "SAFE-LOOKING"].map((tier) => (
              <button
                key={tier}
                onClick={() => setFilterTier(tier)}
                className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-all cursor-pointer ${
                  filterTier === tier
                    ? "bg-primary text-white"
                    : "bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800"
                }`}
              >
                {tier}
              </button>
            ))}
          </div>

          {/* Results Table */}
          <div className="overflow-x-auto rounded-xl border border-border bg-slate-950">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-border bg-slate-900/60 text-slate-400 font-mono text-[11px]">
                <tr>
                  <th className="py-2.5 px-3">#</th>
                  <th className="py-2.5 px-3">Defanged URL</th>
                  <th className="py-2.5 px-3">Score</th>
                  <th className="py-2.5 px-3">Classification</th>
                  <th className="py-2.5 px-3">Findings</th>
                  <th className="py-2.5 px-3">Top Rule</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60 font-mono">
                {filteredResults.map((r, i) => (
                  <tr key={i} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-2.5 px-3 text-slate-500">{i + 1}</td>
                    <td className="py-2.5 px-3 text-slate-200 max-w-xs truncate font-medium" title={r.rawUrl}>
                      {defangUrl(r.rawUrl)}
                    </td>
                    <td className="py-2.5 px-3 font-bold">
                      <span
                        className={
                          r.riskScore >= 70
                            ? "text-red-400"
                            : r.riskScore >= 40
                            ? "text-amber-400"
                            : "text-emerald-400"
                        }
                      >
                        {r.riskScore}/100
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase ${
                          r.classification === "HIGH RISK"
                            ? "bg-red-500/10 text-red-400 border border-red-500/30"
                            : r.classification === "MEDIUM RISK"
                            ? "bg-amber-500/10 text-amber-400 border border-amber-500/30"
                            : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                        }`}
                      >
                        {r.classification}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-400">{r.findings.length} findings</td>
                    <td className="py-2.5 px-3 text-slate-300 max-w-[180px] truncate">
                      {r.findings[0]?.name || "None (RFC 3986 Clean)"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
