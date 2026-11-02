"use client";

import React, { useState } from "react";
import { AnalysisResult } from "@/types";
import { FileText, Download, Copy, Check, ShieldCheck, X } from "lucide-react";

interface Props {
  result: AnalysisResult;
  onClose: () => void;
}

export function SecurityReportModal({ result, onClose }: Props) {
  const [copied, setCopied] = useState(false);

  const generatePlainTextReport = (): string => {
    return [
      "==================================================================",
      "PHISHING URL INTELLIGENCE PLATFORM — EXECUTIVE SECURITY ASSESSMENT",
      "==================================================================",
      `Date & Time        : ${result.timestamp}`,
      `Target URL         : ${result.rawUrl}`,
      `Normalized URL     : ${result.normalizedUrl}`,
      `Risk Score         : ${result.riskScore}/100`,
      `Classification     : ${result.classification}`,
      "------------------------------------------------------------------",
      "EXECUTIVE SUMMARY:",
      result.executiveSummary,
      "------------------------------------------------------------------",
      `OBSERVED THREAT INDICATORS (${result.findings.length}):`,
      ...result.findings.map(
        (f, i) =>
          `[${i + 1}] ${f.title} (+${f.points} pts)\n    Details: ${f.description}\n    Action : ${f.recommendedAction}`
      ),
      "------------------------------------------------------------------",
      "TRIAGE RECOMMENDATION:",
      result.recommendation,
      "------------------------------------------------------------------",
      "DEFENSIVE ARCHITECTURE NOTES:",
      ...result.securityNotes.map((n) => `- ${n}`),
      "==================================================================",
      "Candidate Name: Manish Pundlik Patil (Intern ID: EWB-OL-2026-CYB-0195)",
      "EWB Edutech Private Limited | Defensive Security Research",
      "==================================================================",
    ].join("\n");
  };

  const handleCopyClipboard = async () => {
    const text = generatePlainTextReport();
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadTxt = () => {
    const text = generatePlainTextReport();
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `Security_Report_${Date.now()}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadJson = () => {
    const jsonStr = JSON.stringify(result, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `Security_Report_${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-4">
      <div className="bg-card border border-border w-full max-w-3xl rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh] animate-fade-in">
        
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-border flex items-center justify-between bg-slate-900/80">
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-primary" />
            <h3 className="text-base font-bold text-slate-100">
              Executive Security Assessment Report
            </h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-100 p-1.5 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Report Content Body */}
        <div className="p-5 sm:p-6 overflow-y-auto space-y-4 font-sans text-sm text-slate-300">
          
          {/* Metadata Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3.5 rounded-xl bg-slate-950 border border-border/80">
            <div>
              <span className="text-[10px] uppercase font-bold text-slate-400 block">Risk Score</span>
              <span className="text-lg font-mono font-bold text-slate-100">{result.riskScore}/100</span>
            </div>
            <div>
              <span className="text-[10px] uppercase font-bold text-slate-400 block">Threat Tier</span>
              <span className="text-xs font-bold text-primary block mt-1">{result.classification}</span>
            </div>
            <div>
              <span className="text-[10px] uppercase font-bold text-slate-400 block">Indicators</span>
              <span className="text-sm font-mono font-bold text-slate-200">{result.findings.length} Flags</span>
            </div>
            <div>
              <span className="text-[10px] uppercase font-bold text-slate-400 block">Timestamp</span>
              <span className="text-[11px] font-mono text-slate-400">{result.timestamp.slice(0, 10)}</span>
            </div>
          </div>

          {/* Executive Summary */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5">Executive Summary</h4>
            <p className="p-3.5 rounded-xl bg-slate-950/80 border border-border/70 text-xs sm:text-sm text-slate-200 leading-relaxed">
              {result.executiveSummary}
            </p>
          </div>

          {/* Triage Recommendation */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5">Actionable Triage Recommendation</h4>
            <div className="p-3.5 rounded-xl bg-primary/10 border border-primary/30 text-xs sm:text-sm text-slate-200 leading-relaxed">
              {result.recommendation}
            </div>
          </div>

          {/* Findings List */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5">Observed Threat Indicators</h4>
            {result.findings.length === 0 ? (
              <p className="text-xs text-success">Zero syntactic warning flags identified.</p>
            ) : (
              <div className="space-y-2">
                {result.findings.map((f, i) => (
                  <div key={i} className="p-2.5 rounded-lg bg-slate-950 border border-border/70 text-xs">
                    <div className="font-semibold text-slate-100 flex items-center justify-between">
                      <span>[{i + 1}] {f.title}</span>
                      <span className="text-danger font-mono font-bold">+{f.points} pts</span>
                    </div>
                    <p className="text-slate-400 mt-0.5 text-[11px]">{f.description}</p>
                  </div>
                ))}
              </div>
            )}
          </div>

        </div>

        {/* Actions Footer */}
        <div className="p-4 border-t border-border bg-slate-900/80 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleCopyClipboard}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-all cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-success" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? "Copied to Clipboard!" : "Copy Report"}</span>
            </button>

            <button
              type="button"
              onClick={handleDownloadTxt}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-all cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-primary" />
              <span>Export .TXT</span>
            </button>

            <button
              type="button"
              onClick={handleDownloadJson}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-all cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-primary" />
              <span>Export .JSON</span>
            </button>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-primary hover:bg-primary-hover text-white text-xs font-semibold transition-all cursor-pointer"
          >
            Done
          </button>
        </div>

      </div>
    </div>
  );
}
