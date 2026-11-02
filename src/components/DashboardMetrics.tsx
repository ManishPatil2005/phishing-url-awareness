"use client";

import React from "react";
import { DashboardMetrics as MetricsType } from "@/types";
import { ShieldAlert, AlertTriangle, ShieldCheck, Activity, BarChart2 } from "lucide-react";

interface Props {
  metrics: MetricsType;
}

export function DashboardMetrics({ metrics }: Props) {
  const { totalScans, highRiskCount, mediumRiskCount, lowRiskCount, safeCount } = metrics;

  const highPct = totalScans > 0 ? (highRiskCount / totalScans) * 100 : 0;
  const medPct = totalScans > 0 ? (mediumRiskCount / totalScans) * 100 : 0;
  const lowPct = totalScans > 0 ? (lowRiskCount / totalScans) * 100 : 0;
  const safePct = totalScans > 0 ? (safeCount / totalScans) * 100 : 0;

  return (
    <div className="space-y-4">
      {/* 4 Metric Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        
        {/* Total Scans */}
        <div className="bg-card border border-border rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Total Scanned
            </span>
            <Activity className="w-4 h-4 text-primary" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100">
            {totalScans}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Local session history
          </p>
        </div>

        {/* High Risk */}
        <div className="bg-card border border-border rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-danger uppercase tracking-wider">
              High Risk
            </span>
            <ShieldAlert className="w-4 h-4 text-danger" />
          </div>
          <div className="text-2xl font-bold font-mono text-danger">
            {highRiskCount}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Score &ge; 71/100
          </p>
        </div>

        {/* Medium Risk */}
        <div className="bg-card border border-border rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-warning uppercase tracking-wider">
              Medium Risk
            </span>
            <AlertTriangle className="w-4 h-4 text-warning" />
          </div>
          <div className="text-2xl font-bold font-mono text-warning">
            {mediumRiskCount}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Score 41–70/100
          </p>
        </div>

        {/* Safe Looking */}
        <div className="bg-card border border-border rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-success uppercase tracking-wider">
              Safe-Looking
            </span>
            <ShieldCheck className="w-4 h-4 text-success" />
          </div>
          <div className="text-2xl font-bold font-mono text-success">
            {safeCount}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            0–20/100 (Unverified)
          </p>
        </div>

      </div>

      {/* Threat Distribution Stacked Bar */}
      {totalScans > 0 && (
        <div className="bg-card/70 border border-border rounded-xl p-3.5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2 font-medium">
            <span className="flex items-center gap-1.5">
              <BarChart2 className="w-3.5 h-3.5 text-primary" />
              Session Threat Distribution
            </span>
            <span>{totalScans} URLs Evaluated</span>
          </div>
          <div className="h-2 w-full rounded-full bg-slate-950 flex overflow-hidden">
            {highPct > 0 && (
              <div
                style={{ width: `${highPct}%` }}
                className="bg-danger h-full transition-all duration-500"
                title={`High Risk: ${highRiskCount}`}
              />
            )}
            {medPct > 0 && (
              <div
                style={{ width: `${medPct}%` }}
                className="bg-warning h-full transition-all duration-500"
                title={`Medium Risk: ${mediumRiskCount}`}
              />
            )}
            {lowPct > 0 && (
              <div
                style={{ width: `${lowPct}%` }}
                className="bg-primary h-full transition-all duration-500"
                title={`Low Risk: ${lowRiskCount}`}
              />
            )}
            {safePct > 0 && (
              <div
                style={{ width: `${safePct}%` }}
                className="bg-success h-full transition-all duration-500"
                title={`Safe-Looking: ${safeCount}`}
              />
            )}
          </div>
        </div>
      )}
    </div>
  );
}
