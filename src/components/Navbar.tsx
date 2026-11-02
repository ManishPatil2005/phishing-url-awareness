"use client";

import React from "react";
import { ShieldCheck, Monitor, Github, GraduationCap } from "lucide-react";

interface NavbarProps {
  viewMode?: "modern" | "win7";
  onToggleView?: () => void;
  onOpenQuiz?: () => void;
}

export function Navbar({ viewMode = "modern", onToggleView, onOpenQuiz }: NavbarProps) {
  return (
    <header className="border-b border-border bg-card/60 backdrop-blur-xl sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        
        {/* Brand & Identity */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center text-primary shadow-[0_0_15px_rgba(59,130,246,0.3)] shrink-0">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-slate-100 text-lg tracking-tight">
                PhishIntel<span className="text-primary">.ai</span>
              </span>
              <span className="text-[10px] font-semibold tracking-wider uppercase px-2 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/20">
                Threat Engine v2.0
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              Zero-Network Static URL Intelligence & Heuristic SOC Platform (114 Modular Rules)
            </p>
          </div>
        </div>

        {/* Tactical Status Indicators & Controls */}
        <div className="flex items-center gap-2.5 sm:gap-3">
          {onOpenQuiz && (
            <button
              type="button"
              onClick={onOpenQuiz}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 border border-indigo-500/40 text-indigo-300 text-xs font-semibold shadow-sm transition-all cursor-pointer"
              title="Open Phishing Awareness Quiz"
            >
              <GraduationCap className="w-3.5 h-3.5 text-indigo-400" />
              <span className="hidden sm:inline">Awareness Quiz</span>
            </button>
          )}

          {onToggleView && (
            <button
              type="button"
              onClick={onToggleView}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-blue-600/20 to-cyan-600/20 hover:from-blue-600/30 hover:to-cyan-600/30 border border-blue-500/40 text-cyan-300 text-xs font-semibold shadow-sm transition-all cursor-pointer"
              title="Toggle Windows 7 Aero Glass & Terminal View"
            >
              <Monitor className="w-3.5 h-3.5 text-cyan-400" />
              <span>{viewMode === "modern" ? "🪟 Win7 UI" : "🛡️ SOC Dark"}</span>
            </button>
          )}

          <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-950 border border-border text-xs text-slate-300">
            <span className="w-2 h-2 rounded-full bg-success animate-pulse" />
            <span className="font-mono text-slate-400">INVARIANT:</span>
            <span className="font-medium text-success">Zero Outbound Sockets</span>
          </div>

          <a
            href="https://github.com/ManishPatil2005/phishing-url-awareness"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-slate-200 text-xs font-medium transition-all shadow-sm"
          >
            <Github className="w-4 h-4 text-slate-400" />
            <span className="hidden sm:inline">GitHub</span>
          </a>
        </div>

      </div>
    </header>
  );
}
