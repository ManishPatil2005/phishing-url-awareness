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
import { BatchScanner } from "@/components/BatchScanner";
import { EmailHeaderAnalyzer } from "@/components/EmailHeaderAnalyzer";
import { RuleCatalogBrowser } from "@/components/RuleCatalogBrowser";
import { EducationalQuizModal } from "@/components/EducationalQuizModal";
import { Windows7View } from "@/components/Windows7View";
import { analyzeUrl } from "@/services/analyzer";
import {
  calculateMetrics,
  clearScanHistory,
  deleteScanItem,
  getScanHistory,
  saveScanResult,
} from "@/services/history";
import { AnalysisResult, ScanHistoryItem } from "@/types";
import {
  FileText,
  Sparkles,
  AlertOctagon,
  Search,
  Layers,
  Mail,
  BookOpen,
  GraduationCap,
} from "lucide-react";

export default function Home() {
  const [viewMode, setViewMode] = useState<"modern" | "win7">("modern");
  const [activeTab, setActiveTab] = useState<"inspector" | "batch" | "email" | "catalog">("inspector");
  const [currentResult, setCurrentResult] = useState<AnalysisResult | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [showReportModal, setShowReportModal] = useState(false);
  const [showQuizModal, setShowQuizModal] = useState(false);
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

  if (viewMode === "win7") {
    return (
      <div className="min-h-screen flex flex-col bg-slate-950">
        <Navbar
          viewMode={viewMode}
          onToggleView={() => setViewMode("modern")}
          onOpenQuiz={() => setShowQuizModal(true)}
        />
        <Windows7View onSwitchToModern={() => setViewMode("modern")} />
        <EducationalQuizModal isOpen={showQuizModal} onClose={() => setShowQuizModal(false)} />
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      {/* Top Navbar */}
      <Navbar
        viewMode={viewMode}
        onToggleView={() => setViewMode("win7")}
        onOpenQuiz={() => setShowQuizModal(true)}
      />

      {/* Main SOC Dashboard Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        
        {/* Hero Alert & Zero-Network Guarantee */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-2xl bg-gradient-to-r from-blue-950/40 via-card to-slate-900/60 border border-border">
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary shrink-0">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-base sm:text-lg font-bold text-slate-100 flex items-center gap-2">
                <span>Threat Surface Analysis Engine v2.0</span>
                <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  100% Calibrated
                </span>
              </h1>
              <p className="text-xs text-slate-400">
                100% offline text-only inspection pursuant to RFC 3986. 114 modular heuristics. Zero HTTP sockets. No external telemetry.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setShowQuizModal(true)}
              className="flex items-center justify-center gap-2 px-3.5 py-2 rounded-xl bg-indigo-600/20 hover:bg-indigo-600/30 border border-indigo-500/40 text-indigo-300 text-xs font-semibold transition-all shadow-sm cursor-pointer shrink-0"
            >
              <GraduationCap className="w-4 h-4 text-indigo-400" />
              <span>Awareness Quiz</span>
            </button>

            {currentResult && currentResult.isValid && activeTab === "inspector" && (
              <button
                type="button"
                onClick={() => setShowReportModal(true)}
                className="flex items-center justify-center gap-2 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold transition-all shadow-sm cursor-pointer shrink-0"
              >
                <FileText className="w-4 h-4 text-primary" />
                <span>Executive Report</span>
              </button>
            )}
          </div>
        </div>

        {/* Primary Workspace Navigation Tabs */}
        <div className="flex items-center gap-2 p-1.5 rounded-2xl bg-slate-900/80 border border-border overflow-x-auto">
          <button
            onClick={() => setActiveTab("inspector")}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer whitespace-nowrap ${
              activeTab === "inspector"
                ? "bg-primary text-white shadow-md"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <Search className="w-4 h-4" />
            <span>URL Inspector</span>
          </button>

          <button
            onClick={() => setActiveTab("batch")}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer whitespace-nowrap ${
              activeTab === "batch"
                ? "bg-primary text-white shadow-md"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>Batch Scanner (500 URLs)</span>
          </button>

          <button
            onClick={() => setActiveTab("email")}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer whitespace-nowrap ${
              activeTab === "email"
                ? "bg-primary text-white shadow-md"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <Mail className="w-4 h-4" />
            <span>Email Header Analyzer</span>
          </button>

          <button
            onClick={() => setActiveTab("catalog")}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer whitespace-nowrap ${
              activeTab === "catalog"
                ? "bg-primary text-white shadow-md"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <BookOpen className="w-4 h-4" />
            <span>Rule Catalog (114)</span>
          </button>
        </div>

        {/* Tab 1: Single URL Inspector Workspace */}
        {activeTab === "inspector" && (
          <div className="space-y-6">
            {/* Dashboard Metrics Cards */}
            {isClient && <DashboardMetrics metrics={metrics} />}

            {/* Search Input Command Center */}
            <UrlInputForm onScan={handleScan} />

            {/* Results Workspace Grid */}
            {currentResult && (
              <div className="space-y-6 animate-fade-in">
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
                      <div className="lg:col-span-1">
                        <VisualScoreMeter
                          score={currentResult.riskScore}
                          classification={currentResult.classification}
                          findingCount={currentResult.findings.length}
                          recommendation={currentResult.recommendation}
                        />
                      </div>
                      <div className="lg:col-span-2">
                        <ThreatCards
                          findings={currentResult.findings}
                        />
                      </div>
                    </div>

                    {/* URL Decomposition Breakdown Viewer */}
                    <UrlBreakdownViewer breakdown={currentResult.breakdown} />
                  </>
                )}
              </div>
            )}

            {/* Persistent Scan History Component */}
            {isClient && (
              <AnalysisHistory
                history={history}
                onSelectUrl={(url) => handleScan(url)}
                onDeleteItem={handleDeleteHistory}
                onClearHistory={handleClearAllHistory}
              />
            )}
          </div>
        )}

        {/* Tab 2: High-Throughput Batch Scanner */}
        {activeTab === "batch" && <BatchScanner />}

        {/* Tab 3: Raw Email Header Analyzer */}
        {activeTab === "email" && <EmailHeaderAnalyzer />}

        {/* Tab 4: Interactive Rule Catalog Browser */}
        {activeTab === "catalog" && <RuleCatalogBrowser />}

      </main>

      {/* Footer */}
      <footer className="border-t border-border bg-card/40 py-6 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-400">
          <p>
            Developed by <strong className="text-slate-200">Manish Pundlik Patil</strong> (Intern ID:{" "}
            <span className="font-mono text-primary font-semibold">EWB-OL-2026-CYB-0195</span>)
          </p>
          <div className="flex items-center gap-4 text-[11px]">
            <span>Deterministic RFC 3986 Lexical Engine</span>
            <span>•</span>
            <span className="text-emerald-400 font-semibold">Zero Sockets Transmitted</span>
            <span>•</span>
            <span>EWB Edutech Certified</span>
          </div>
        </div>
      </footer>

      {/* Security Report Export Modal */}
      {showReportModal && currentResult && (
        <SecurityReportModal
          result={currentResult}
          onClose={() => setShowReportModal(false)}
        />
      )}

      {/* Educational Phishing Quiz Modal */}
      <EducationalQuizModal
        isOpen={showQuizModal}
        onClose={() => setShowQuizModal(false)}
      />
    </div>
  );
}
