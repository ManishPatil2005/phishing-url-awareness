"use client";

import React, { useState, useEffect } from "react";
import { Navbar } from "@/components/Navbar";
import { DashboardMetrics } from "@/components/DashboardMetrics";
import { UrlInputForm } from "@/components/UrlInputForm";
import { VisualScoreMeter } from "@/components/VisualScoreMeter";
import { UrlBreakdownViewer } from "@/components/UrlBreakdownViewer";
import { ThreatCards } from "@/components/ThreatCards";
import { SecurityReportModal } from "@/components/SecurityReportModal";
import { AnalysisHistory } from "@/components/AnalysisHistory";
import { analyzeUrl } from "@/services/analyzer";
import {
  calculateMetrics,
  clearScanHistory,
  deleteScanItem,
  getScanHistory,
  saveScanResult,
} from "@/services/history";
import { AnalysisResult, ScanHistoryItem } from "@/types";
import { FileText, ShieldAlert, Sparkles, Terminal, Info, AlertOctagon } from "lucide-react";

export default function Home() {
  const [currentResult, setCurrentResult] = useState<AnalysisResult | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [showReportModal, setShowReportModal] = useState(false);
  const [isClient, setIsClient] = useState(false);

  // Initial load
  useEffect(() => {
    setIsClient(true);
    const stored = getScanHistory();
    setHistory(stored);

    // Run initial benchmark scan on load
    const initial = analyzeUrl("http://192.0.2.10/login");
    setCurrentResult(initial);
    const updated = saveScanResult(initial);
    setHistory(updated);
  }, []);

  const handleScan = (url: string) => {
    const result = analyzeUrl(url);
    setCurrentResult(result);
    if (result.isValid) {
      const updated = saveScanResult(result);
      setHistory(updated);
    }
  };

  const handleDeleteHistory = (id: string) => {
    const updated = deleteScanItem(id);
    setHistory(updated);
  };

  const handleClearAllHistory = () => {
    clearScanHistory();
    setHistory([]);
  };

  const metrics = calculateMetrics(history);

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      {/* Top Navbar */}
      <Navbar />

      {/* Main SOC Dashboard Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        
        {/* Hero Alert & Zero-Network Guarantee */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-2xl bg-gradient-to-r from-blue-950/40 via-card to-slate-900/60 border border-border">
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary shrink-0">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-base sm:text-lg font-bold text-slate-100">
                Threat Surface Analysis Engine
              </h1>
              <p className="text-xs text-slate-400">
                100% offline text-only inspection pursuant to RFC 3986. Zero HTTP sockets. No external telemetry.
              </p>
            </div>
          </div>

          {currentResult && currentResult.isValid && (
            <button
              type="button"
              onClick={() => setShowReportModal(true)}
              className="flex items-center justify-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold transition-all shadow-sm cursor-pointer shrink-0"
            >
              <FileText className="w-4 h-4 text-primary" />
              <span>Generate Executive Report</span>
            </button>
          )}
        </div>

        {/* Dashboard Metrics Cards */}
        {isClient && <DashboardMetrics metrics={metrics} />}

        {/* Search Input Command Center */}
        <UrlInputForm onScan={handleScan} />

        {/* Results Workspace Grid */}
        {currentResult && (
          <div className="space-y-6 animate-fade-in">
            
            {/* Input Error State */}
            {!currentResult.isValid ? (
              <div className="p-5 rounded-2xl bg-danger/10 border border-danger/30 text-danger flex items-center gap-3">
                <AlertOctagon className="w-6 h-6 shrink-0" />
                <div>
                  <h3 className="text-sm font-bold">Input Error: {currentResult.errorMessage}</h3>
                  <p className="text-xs text-slate-300 mt-0.5">{currentResult.recommendation}</p>
                </div>
              </div>
            ) : (
              <>
                {/* Score Meter & Threat Cards Row */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  {/* Left Column: Visual Risk Gauge */}
                  <div className="lg:col-span-1">
                    <VisualScoreMeter
                      score={currentResult.riskScore}
                      classification={currentResult.classification}
                      findingCount={currentResult.findings.length}
                      recommendation={currentResult.recommendation}
                    />
                  </div>

                  {/* Right Column: Threat Findings */}
                  <div className="lg:col-span-2">
                    <ThreatCards findings={currentResult.findings} />
                  </div>
                </div>

                {/* Full Width: RFC 3986 Structural Decomposition */}
                <UrlBreakdownViewer breakdown={currentResult.breakdown} />
              </>
            )}

          </div>
        )}

        {/* History Audit Drawer */}
        {isClient && (
          <AnalysisHistory
            history={history}
            onSelectUrl={handleScan}
            onDeleteItem={handleDeleteHistory}
            onClearHistory={handleClearAllHistory}
          />
        )}

        {/* Educational Awareness Disclaimer */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-border/80 text-xs text-slate-400 flex items-start gap-3">
          <Info className="w-4 h-4 text-primary shrink-0 mt-0.5" />
          <p className="leading-relaxed">
            <strong className="text-slate-300">Defensive Learning Notice:</strong> This platform is designed for educational threat awareness and triage. It conducts lexical text analysis only and does not query live DNS, reputation databases, or scan page content. An assessment of <strong>Safe-Looking (0/100)</strong> indicates the absence of common syntax red flags, but does not certify that a target web resource is benign. Always verify domain authenticity independently before supplying credentials.
          </p>
        </div>

      </main>

      {/* Footer */}
      <footer className="border-t border-border bg-card/40 py-6 text-center text-xs text-slate-500">
        <p>
          Engineered by <strong className="text-slate-300">Manish Pundlik Patil</strong> &bull; Candidate ID: <code className="text-primary font-mono">EWB-OL-2026-CYB-0195</code>
        </p>
        <p className="mt-1">
          EWB Edutech Private Limited &bull; <a href="https://github.com/ManishPatil2005/phishing-url-awareness" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">GitHub Repository</a> &bull; MIT License
        </p>
      </footer>

      {/* Security Report Modal */}
      {showReportModal && currentResult && (
        <SecurityReportModal
          result={currentResult}
          onClose={() => setShowReportModal(false)}
        />
      )}
    </div>
  );
}
