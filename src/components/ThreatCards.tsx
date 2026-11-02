"use client";

import React, { useState } from "react";
import { HeuristicFinding } from "@/types";
import { ShieldAlert, AlertTriangle, Info, ChevronDown, ChevronUp, CheckCircle } from "lucide-react";

interface Props {
  findings: HeuristicFinding[];
}

export function ThreatCards({ findings }: Props) {
  const [expandedId, setExpandedId] = useState<string | null>(findings[0]?.id || null);

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  if (findings.length === 0) {
    return (
      <div className="bg-card border border-border rounded-2xl p-6 shadow-xl flex items-center gap-4">
        <div className="w-12 h-12 rounded-xl bg-success/10 border border-success/30 flex items-center justify-center text-success shrink-0">
          <CheckCircle className="w-6 h-6" />
        </div>
        <div>
          <h4 className="text-sm font-bold text-slate-100">Zero Structural Threat Indicators Detected</h4>
          <p className="text-xs text-slate-400 mt-1 leading-relaxed">
            This URL does not exhibit any of the standard heuristic red flags (no bare IP, no @ disguise, normal length, no punycode, no high-risk keywords). Remember: this does <strong>not</strong> prove absolute safety; spear-phishing may utilize clean domains.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-card border border-border rounded-2xl p-5 sm:p-6 shadow-xl space-y-4">
      <div className="flex items-center justify-between border-b border-border/60 pb-3">
        <div>
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-danger" />
            Threat Intelligence Findings ({findings.length})
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Detailed breakdown of observed heuristic vectors, attacker mechanics, and mitigations.
          </p>
        </div>
      </div>

      <div className="space-y-3">
        {findings.map((f, idx) => {
          const isExpanded = expandedId === f.id;
          const severityColors =
            f.severity === "critical"
              ? "border-danger/40 bg-danger/5 text-danger"
              : f.severity === "high"
              ? "border-danger/30 bg-danger/5 text-danger"
              : f.severity === "medium"
              ? "border-warning/30 bg-warning/5 text-warning"
              : "border-primary/30 bg-primary/5 text-primary";

          return (
            <div
              key={f.id}
              className="rounded-xl border border-border bg-slate-950/70 overflow-hidden transition-all duration-200"
            >
              {/* Card Header (Clickable) */}
              <button
                type="button"
                onClick={() => toggleExpand(f.id)}
                className="w-full text-left p-4 flex items-center justify-between hover:bg-slate-900/60 transition-colors cursor-pointer"
              >
                <div className="flex items-center gap-3">
                  <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-slate-900 border border-border text-slate-300">
                    #{idx + 1}
                  </span>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-slate-100">{f.title}</span>
                      <span className={`text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded border ${severityColors}`}>
                        +{f.points} pts
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5">{f.description}</p>
                  </div>
                </div>

                <div className="text-slate-400 pl-2">
                  {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </div>
              </button>

              {/* Expandable Intelligence Section */}
              {isExpanded && (
                <div className="px-4 pb-4 pt-2 border-t border-border/50 grid grid-cols-1 md:grid-cols-3 gap-3 text-xs animate-fade-in">
                  
                  {/* Why It Matters */}
                  <div className="p-3 rounded-lg bg-slate-900/80 border border-border/60">
                    <span className="font-bold text-slate-300 block mb-1 uppercase tracking-wider text-[10px]">
                      Why It Matters
                    </span>
                    <p className="text-slate-300 leading-relaxed">{f.whyItMatters}</p>
                  </div>

                  {/* Real-world Phishing Technique */}
                  <div className="p-3 rounded-lg bg-slate-900/80 border border-border/60">
                    <span className="font-bold text-warning block mb-1 uppercase tracking-wider text-[10px]">
                      Attacker Technique
                    </span>
                    <p className="text-slate-300 leading-relaxed">{f.realWorldTechnique}</p>
                  </div>

                  {/* Recommended Action */}
                  <div className="p-3 rounded-lg bg-slate-900/80 border border-border/60">
                    <span className="font-bold text-success block mb-1 uppercase tracking-wider text-[10px]">
                      Defensive Action
                    </span>
                    <p className="text-slate-300 leading-relaxed">{f.recommendedAction}</p>
                  </div>

                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
