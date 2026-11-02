"use client";

import React, { useState } from "react";
import { ALL_RULES, RuleCategory } from "@/rules";
import { Search, Filter, Shield, BookOpen, ExternalLink, Tag } from "lucide-react";

export function RuleCatalogBrowser() {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string>("ALL");

  const categories: Array<{ id: string; label: string }> = [
    { id: "ALL", label: "All Rules (114)" },
    { id: "structure", label: "Structure" },
    { id: "host", label: "Host & DNS" },
    { id: "encoding", label: "Encoding & Obfuscation" },
    { id: "tld", label: "TLD Extensions" },
    { id: "lexical", label: "Lexical & Social Eng." },
    { id: "brand", label: "Brand Typosquatting" },
    { id: "path", label: "Path & Payloads" },
    { id: "query", label: "Query & Redirects" },
  ];

  const filteredRules = ALL_RULES.filter((rule) => {
    const matchesCat = selectedCategory === "ALL" || rule.category === selectedCategory;
    const term = searchTerm.toLowerCase();
    const matchesSearch =
      !term ||
      rule.id.toLowerCase().includes(term) ||
      rule.name.toLowerCase().includes(term) ||
      rule.description.toLowerCase().includes(term) ||
      rule.tags.some((t) => t.toLowerCase().includes(term));

    return matchesCat && matchesSearch;
  });

  return (
    <div className="rounded-2xl border border-border bg-card p-5 sm:p-6 shadow-sm space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-base sm:text-lg font-bold text-slate-100 flex items-center gap-2">
            <BookOpen className="w-5 h-5 text-primary" />
            <span>Interactive Threat Rule Catalog</span>
            <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/20">
              {ALL_RULES.length} Pure Rules
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Comprehensive reference database of deterministic RFC 3986, OWASP, and MITRE ATT&CK heuristics.
          </p>
        </div>
      </div>

      {/* Filter and Search Controls */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3.5 top-3 text-slate-400" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search rules by ID, keyword, or tag (e.g. 'STR-002', 'punycode', 'sbi')..."
            className="w-full pl-9 pr-3.5 py-2 rounded-xl border border-border bg-slate-950 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-primary/40 font-mono"
          />
        </div>

        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
          <Filter className="w-3.5 h-3.5 text-slate-400 shrink-0" />
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="rounded-xl border border-border bg-slate-950 px-3 py-2 text-xs text-slate-300 focus:outline-none focus:ring-2 focus:ring-primary/40"
          >
            {categories.map((c) => (
              <option key={c.id} value={c.id}>
                {c.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Rule Count & List */}
      <div className="text-xs text-slate-400 font-mono">
        Showing {filteredRules.length} of {ALL_RULES.length} rules
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 max-h-[580px] overflow-y-auto pr-1">
        {filteredRules.map((rule) => {
          let badgeColor = "bg-slate-800 text-slate-300 border-slate-700";
          if (rule.severity === "critical") badgeColor = "bg-red-500/10 text-red-400 border-red-500/30";
          else if (rule.severity === "high") badgeColor = "bg-orange-500/10 text-orange-400 border-orange-500/30";
          else if (rule.severity === "medium") badgeColor = "bg-amber-500/10 text-amber-400 border-amber-500/30";
          else if (rule.severity === "low") badgeColor = "bg-yellow-500/10 text-yellow-300 border-yellow-500/30";

          return (
            <div
              key={rule.id}
              className="p-4 rounded-xl border border-border bg-slate-950 hover:border-slate-700 transition-all flex flex-col justify-between space-y-3"
            >
              <div>
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-bold text-primary">{rule.id}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono text-slate-400">+{rule.weight} pts</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase border ${badgeColor}`}>
                      {rule.severity}
                    </span>
                  </div>
                </div>

                <h3 className="text-sm font-bold text-slate-100 mt-1">{rule.name}</h3>
                <p className="text-xs text-slate-300 mt-1 leading-relaxed">{rule.description}</p>
              </div>

              <div className="pt-2 border-t border-border/60 space-y-2">
                <div className="text-[11px] text-slate-400">
                  <strong className="text-slate-300">Why It Matters: </strong>
                  <span>{rule.whyItMatters}</span>
                </div>

                <div className="flex items-center justify-between flex-wrap gap-1 pt-1">
                  <div className="flex items-center gap-1 flex-wrap">
                    {rule.tags.map((t, idx) => (
                      <span
                        key={idx}
                        className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400"
                      >
                        #{t}
                      </span>
                    ))}
                  </div>

                  <span className="text-[10px] font-mono text-slate-500">
                    Conf: {Math.round(rule.confidence * 100)}%
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
