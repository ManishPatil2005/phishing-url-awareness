"use client";

import React, { useState } from "react";
import { PRESET_SAMPLE_URLS } from "@/lib/constants";
import { Search, X, Sparkles, Shield, ArrowRight } from "lucide-react";

interface Props {
  onScan: (url: string) => void;
  isLoading?: boolean;
}

export function UrlInputForm({ onScan, isLoading }: Props) {
  const [inputUrl, setInputUrl] = useState("http://192.0.2.10/login");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputUrl.trim()) return;
    onScan(inputUrl.trim());
  };

  const handleSelectPreset = (url: string) => {
    setInputUrl(url);
    onScan(url);
  };

  return (
    <div className="bg-card border border-border rounded-2xl p-5 sm:p-6 shadow-xl relative overflow-hidden">
      
      {/* Background glow gradient */}
      <div className="absolute top-0 right-0 w-80 h-80 bg-primary/5 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20" />

      {/* Title & Instructions */}
      <div className="mb-4">
        <label
          htmlFor="url-target"
          className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2 mb-1.5"
        >
          <Search className="w-3.5 h-3.5 text-primary" />
          Target URL Security Inspection
        </label>
        <p className="text-xs text-slate-400">
          Enter any URL string for static structural decomposition, RFC 3986 analysis, and heuristic risk scoring.
        </p>
      </div>

      {/* Input Field + Action Button */}
      <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-2.5">
        <div className="relative flex-1">
          <input
            id="url-target"
            type="text"
            value={inputUrl}
            onChange={(e) => setInputUrl(e.target.value)}
            placeholder="e.g. http://192.0.2.10/login or https://example.com"
            className="w-full bg-slate-950/90 border border-border focus:border-primary text-slate-100 placeholder:text-slate-500 font-mono text-sm sm:text-base rounded-xl px-4 py-3.5 pr-10 outline-none transition-all focus:ring-2 focus:ring-primary/20 shadow-inner"
          />
          {inputUrl && (
            <button
              type="button"
              onClick={() => setInputUrl("")}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 transition-colors"
              title="Clear input"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        <button
          type="submit"
          disabled={isLoading || !inputUrl.trim()}
          className="bg-primary hover:bg-primary-hover disabled:opacity-50 text-white font-semibold text-sm px-6 py-3.5 rounded-xl transition-all shadow-[0_0_20px_rgba(59,130,246,0.35)] flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
        >
          <span>Inspect Link</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </form>

      {/* Preset Test Chips */}
      <div className="mt-4 pt-3.5 border-t border-border/60">
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-400 flex items-center gap-1 font-medium">
            <Sparkles className="w-3.5 h-3.5 text-primary" />
            Quick Test Lures:
          </span>
          {PRESET_SAMPLE_URLS.map((preset) => (
            <button
              key={preset.label}
              type="button"
              onClick={() => handleSelectPreset(preset.url)}
              title={preset.description}
              className="px-2.5 py-1 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700/80 text-slate-300 font-mono text-[11px] transition-all hover:border-primary/50 hover:text-white"
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

    </div>
  );
}
