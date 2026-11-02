"use client";

import React from "react";
import { ThreatClassification } from "@/types";
import { ShieldCheck, ShieldAlert, AlertTriangle, Info } from "lucide-react";

interface Props {
  score: number;
  classification: ThreatClassification;
  findingCount: number;
  recommendation: string;
}

export function VisualScoreMeter({ score, classification, findingCount, recommendation }: Props) {
  // SVG circular gauge calculation
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  let strokeColor = "#22C55E"; // Green
  let badgeClass = "bg-success/10 text-success border-success/30";
  let icon = <ShieldCheck className="w-5 h-5 text-success" />;

  if (classification === "HIGH RISK") {
    strokeColor = "#EF4444"; // Red
    badgeClass = "bg-danger/10 text-danger border-danger/30 shadow-[0_0_15px_rgba(239,68,68,0.2)]";
    icon = <ShieldAlert className="w-5 h-5 text-danger" />;
  } else if (classification === "MEDIUM RISK") {
    strokeColor = "#F59E0B"; // Amber
    badgeClass = "bg-warning/10 text-warning border-warning/30 shadow-[0_0_15px_rgba(245,158,11,0.2)]";
    icon = <AlertTriangle className="w-5 h-5 text-warning" />;
  } else if (classification === "LOW RISK") {
    strokeColor = "#3B82F6"; // Blue
    badgeClass = "bg-primary/10 text-primary border-primary/30";
    icon = <Info className="w-5 h-5 text-primary" />;
  }

  return (
    <div className="bg-card border border-border rounded-2xl p-6 shadow-xl flex flex-col items-center justify-between">
      
      {/* Header */}
      <div className="w-full flex items-center justify-between mb-4 border-b border-border/60 pb-3">
        <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
          Threat Risk Index
        </span>
        <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-950 border border-border text-slate-400">
          {findingCount} {findingCount === 1 ? "Indicator" : "Indicators"}
        </span>
      </div>

      {/* Circular Gauge */}
      <div className="relative w-36 h-36 flex items-center justify-center my-2">
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 130 130">
          {/* Background Track */}
          <circle
            cx="65"
            cy="65"
            r={radius}
            stroke="#1E293B"
            strokeWidth="10"
            fill="transparent"
          />
          {/* Progress Ring */}
          <circle
            cx="65"
            cy="65"
            r={radius}
            stroke={strokeColor}
            strokeWidth="10"
            fill="transparent"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-700 ease-out"
          />
        </svg>

        {/* Center Score Text */}
        <div className="absolute flex flex-col items-center justify-center text-center">
          <span className="text-3xl font-extrabold font-mono text-slate-50 tracking-tight">
            {score}
          </span>
          <span className="text-[10px] uppercase tracking-wider font-semibold text-slate-400">
            Out of 100
          </span>
        </div>
      </div>

      {/* Threat Badge */}
      <div className={`mt-3 flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg border font-bold text-xs tracking-wider uppercase ${badgeClass}`}>
        {icon}
        <span>{classification}</span>
      </div>

      {/* Recommendation Quote */}
      <div className="w-full mt-4 p-3 rounded-xl bg-slate-950/70 border border-border/80 text-xs text-slate-300 leading-relaxed text-center">
        <span className="text-slate-400 font-semibold block mb-0.5">Triage Recommendation:</span>
        {recommendation}
      </div>

    </div>
  );
}
