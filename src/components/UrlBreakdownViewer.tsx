"use client";

import React from "react";
import { UrlBreakdown } from "@/types";
import { Globe, Layers, Link, FileText, HelpCircle, Key, Server } from "lucide-react";

interface Props {
  breakdown: UrlBreakdown;
}

export function UrlBreakdownViewer({ breakdown }: Props) {
  const items = [
    {
      label: "Scheme / Protocol",
      value: breakdown.scheme ? breakdown.scheme.toUpperCase() : "N/A",
      icon: <Globe className="w-3.5 h-3.5 text-primary" />,
      highlight: breakdown.scheme === "http" ? "text-danger font-bold" : "text-success font-bold",
      note: breakdown.scheme === "http" ? "Unencrypted" : "Encrypted (TLS)",
    },
    {
      label: "Authoritative Hostname",
      value: breakdown.hostname || "N/A",
      icon: <Server className="w-3.5 h-3.5 text-primary" />,
      highlight: "text-slate-100 font-mono",
      note: "DNS Authority Endpoint",
    },
    {
      label: "Root Domain",
      value: breakdown.rootDomain || "N/A",
      icon: <Link className="w-3.5 h-3.5 text-primary" />,
      highlight: "text-slate-200 font-mono font-medium",
      note: "Primary Registrable Label",
    },
    {
      label: "Subdomain Nesting",
      value: breakdown.subdomainString || "[None]",
      icon: <Layers className="w-3.5 h-3.5 text-primary" />,
      highlight: breakdown.subdomains.length >= 5 ? "text-warning font-mono" : "text-slate-300 font-mono",
      note: `${breakdown.subdomains.length} Nested Labels`,
    },
    {
      label: "Top-Level Domain (TLD)",
      value: breakdown.tld ? `.${breakdown.tld}` : "N/A",
      icon: <Globe className="w-3.5 h-3.5 text-primary" />,
      highlight: "text-slate-300 font-mono",
      note: "Registry Zone",
    },
    {
      label: "Path Segment",
      value: breakdown.path || "/",
      icon: <FileText className="w-3.5 h-3.5 text-primary" />,
      highlight: "text-slate-300 font-mono truncate",
      note: "Target Resource",
    },
    {
      label: "Query Parameters",
      value: breakdown.query || "[None]",
      icon: <HelpCircle className="w-3.5 h-3.5 text-primary" />,
      highlight: "text-slate-400 font-mono truncate",
      note: Object.keys(breakdown.queryParams).length > 0 ? `${Object.keys(breakdown.queryParams).length} parameters` : "Zero Parameters",
    },
    {
      label: "Userinfo Section (@)",
      value: breakdown.hasUserinfo ? breakdown.userinfo : "[None]",
      icon: <Key className="w-3.5 h-3.5 text-primary" />,
      highlight: breakdown.hasUserinfo ? "text-danger font-mono font-bold" : "text-slate-500 font-mono",
      note: breakdown.hasUserinfo ? "Disguise Risk Present" : "Clean Authority",
    },
  ];

  return (
    <div className="bg-card border border-border rounded-2xl p-5 sm:p-6 shadow-xl">
      <div className="flex items-center justify-between mb-4 border-b border-border/60 pb-3">
        <div>
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Layers className="w-4 h-4 text-primary" />
            RFC 3986 URL Structural Decomposition
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Component-level breakdown isolating authority, path, and credentials.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
        {items.map((item, idx) => (
          <div
            key={idx}
            className="p-3 rounded-xl bg-slate-950/70 border border-border/70 flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between text-[11px] text-slate-400 font-medium mb-1">
                <span className="flex items-center gap-1.5">{item.icon} {item.label}</span>
              </div>
              <div className={`text-xs break-all ${item.highlight}`}>
                {item.value}
              </div>
            </div>
            <div className="text-[10px] text-slate-500 font-medium mt-2 pt-1 border-t border-border/40">
              {item.note}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
