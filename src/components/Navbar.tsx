"use client";

import React from "react";
import { ShieldCheck, Terminal, Github, Lock, Activity } from "lucide-react";

export function Navbar() {
  return (
    <header className="border-b border-border bg-card/60 backdrop-blur-xl sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        
        {/* Brand & Identity */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center text-primary shadow-[0_0_15px_rgba(59,130,246,0.3)]">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-slate-100 text-lg tracking-tight">
                PhishIntel<span className="text-primary">.ai</span>
              </span>
              <span className="text-[10px] font-semibold tracking-wider uppercase px-2 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/20">
                SaaS Threat Engine
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              Zero-Network Static URL Intelligence & Heuristic SOC Platform
            </p>
          </div>
        </div>

        {/* Tactical Status Indicators */}
        <div className="flex items-center gap-4">
          <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-950 border border-border text-xs text-slate-300">
            <span className="w-2 h-2 rounded-full bg-success animate-pulse" />
            <span className="font-mono text-slate-400">DEFENSIVE INVARIANT:</span>
            <span className="font-medium text-success">Zero Outbound Sockets</span>
          </div>

          <a
            href="https://github.com/ManishPatil2005/phishing-url-awareness"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-slate-200 text-xs font-medium transition-all shadow-sm"
          >
            <Github className="w-4 h-4 text-slate-400" />
            <span className="hidden sm:inline">GitHub</span>
          </a>
        </div>

      </div>
    </header>
  );
}
