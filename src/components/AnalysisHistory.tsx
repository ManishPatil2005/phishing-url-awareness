"use client";

import React from "react";
import { ScanHistoryItem } from "@/types";
import { History, Trash2, Download, ExternalLink, ShieldAlert, ShieldCheck } from "lucide-react";
import { exportHistoryAsJson } from "@/services/history";

interface Props {
  history: ScanHistoryItem[];
  onSelectUrl: (url: string) => void;
  onDeleteItem: (id: string) => void;
  onClearHistory: () => void;
}

export function AnalysisHistory({
  history,
  onSelectUrl,
  onDeleteItem,
  onClearHistory,
}: Props) {
  if (history.length === 0) {
    return (
      <div className="bg-card border border-border rounded-2xl p-6 shadow-xl text-center">
        <History className="w-8 h-8 text-slate-500 mx-auto mb-2 opacity-50" />
        <h4 className="text-sm font-semibold text-slate-300">No Scan History Yet</h4>
        <p className="text-xs text-slate-500 mt-1">
          Evaluated URLs are persisted locally in your browser session.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-card border border-border rounded-2xl p-5 sm:p-6 shadow-xl space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border/60 pb-3">
        <div>
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <History className="w-4 h-4 text-primary" />
            Session Analysis History ({history.length})
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Client-side local audit log (Stored in localStorage only — zero database dependency).
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => exportHistoryAsJson(history)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs border border-slate-700 transition-colors cursor-pointer"
            title="Export History JSON"
          >
            <Download className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Export</span>
          </button>

          <button
            type="button"
            onClick={onClearHistory}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-danger/10 hover:bg-danger/20 text-danger text-xs border border-danger/30 transition-colors cursor-pointer"
            title="Clear all history"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Clear All</span>
          </button>
        </div>
      </div>

      {/* History List Table / Cards */}
      <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
        {history.map((item) => {
          const badgeColor =
            item.classification === "HIGH RISK"
              ? "text-danger bg-danger/10 border-danger/30"
              : item.classification === "MEDIUM RISK"
              ? "text-warning bg-warning/10 border-warning/30"
              : item.classification === "LOW RISK"
              ? "text-primary bg-primary/10 border-primary/30"
              : "text-success bg-success/10 border-success/30";

          return (
            <div
              key={item.id}
              className="p-3 rounded-xl bg-slate-950/70 border border-border/70 flex items-center justify-between gap-3 hover:border-slate-700 transition-colors"
            >
              <div className="flex items-center gap-3 min-w-0">
                <span className="font-mono text-xs font-bold text-slate-100 shrink-0 w-12 text-right">
                  {item.riskScore}/100
                </span>
                
                <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border shrink-0 ${badgeColor}`}>
                  {item.classification}
                </span>

                <div className="min-w-0">
                  <div className="text-xs font-mono text-slate-300 truncate max-w-xs sm:max-w-md md:max-w-lg">
                    {item.url}
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                    {new Date(item.timestamp).toLocaleTimeString()} &bull; {item.findingCount} indicators
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-1 shrink-0">
                <button
                  type="button"
                  onClick={() => onSelectUrl(item.url)}
                  className="p-1.5 text-slate-400 hover:text-primary transition-colors cursor-pointer"
                  title="Re-analyze this URL"
                >
                  <ExternalLink className="w-4 h-4" />
                </button>
                <button
                  type="button"
                  onClick={() => onDeleteItem(item.id)}
                  className="p-1.5 text-slate-500 hover:text-danger transition-colors cursor-pointer"
                  title="Delete from history"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
