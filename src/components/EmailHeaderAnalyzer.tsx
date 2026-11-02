"use client";

import React, { useState } from "react";
import { analyzeThreatV2, EngineV2Result } from "@/services/scorerV2";
import { defangUrl } from "@/utils/defang";
import { Mail, ShieldAlert, CheckCircle2, AlertOctagon, ArrowRight, ExternalLink } from "lucide-react";

interface HeaderAnalysis {
  fromAddress: string;
  fromDisplayName: string;
  replyToAddress: string;
  isReplyToMismatch: boolean;
  isDisplayNameSpoofing: boolean;
  spfStatus: "PASS" | "FAIL" | "SOFTFAIL" | "NONE" | "UNKNOWN";
  dkimStatus: "PASS" | "FAIL" | "NONE" | "UNKNOWN";
  dmarcStatus: "PASS" | "FAIL" | "NONE" | "UNKNOWN";
  extractedUrls: string[];
  urlResults: EngineV2Result[];
}

export function EmailHeaderAnalyzer() {
  const [rawHeaders, setRawHeaders] = useState("");
  const [analysis, setAnalysis] = useState<HeaderAnalysis | null>(null);

  const sampleEmail = `Delivered-To: victim@company.com
Received: by 2002:a05:6838:2285 with SMTP id ...
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of evil-sender.net does not designate 198.51.100.1 as permitted sender)
       dkim=fail header.i=@paypal.com
       dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com
From: "PayPal Account Security" <attacker-bounce@evil-sender.net>
Reply-To: support@quick-phish-box.invalid
To: victim@company.com
Subject: URGENT: Your PayPal Account Has Been Suspended!
Date: Mon, 02 Nov 2026 21:00:00 +0000

Dear Customer,

We noticed unauthorized activity on your account. Please verify your identity immediately:
http://paypal.com@verify-account.invalid/signin

Failure to verify within 24 hours will result in permanent suspension.
Regards,
PayPal Team`;

  const handleAnalyze = () => {
    if (!rawHeaders.trim()) return;

    // Extract From
    const fromMatch = rawHeaders.match(/^From:\s*(?:["']?([^"']+)["']?\s*)?(?:<([^>]+)>|([^\s@]+@[^\s@]+))/im);
    const fromDisplayName = fromMatch ? (fromMatch[1] || "").trim() : "";
    const fromAddress = fromMatch ? (fromMatch[2] || fromMatch[3] || "").trim() : "";

    // Extract Reply-To
    const replyToMatch = rawHeaders.match(/^Reply-To:\s*(?:["']?([^"']+)["']?\s*)?(?:<([^>]+)>|([^\s@]+@[^\s@]+))/im);
    const replyToAddress = replyToMatch ? (replyToMatch[2] || replyToMatch[3] || "").trim() : "";

    // Check Mismatch
    const isReplyToMismatch = !!(replyToAddress && fromAddress && replyToAddress.toLowerCase() !== fromAddress.toLowerCase());

    // Check Display Name Spoofing: Display name contains known brand (e.g. "PayPal", "Microsoft") while email domain is unrelated
    const knownBrands = ["paypal", "microsoft", "google", "apple", "amazon", "chase", "bank of america", "sbi", "hdfc", "icici"];
    const isDisplayNameSpoofing = knownBrands.some((brand) => {
      const nameLower = fromDisplayName.toLowerCase();
      const addrLower = fromAddress.toLowerCase();
      return nameLower.includes(brand) && !addrLower.includes(brand.replace(/\s+/g, ""));
    });

    // Check Authentication-Results (SPF, DKIM, DMARC)
    let spfStatus: HeaderAnalysis["spfStatus"] = "UNKNOWN";
    if (/spf=pass/i.test(rawHeaders)) spfStatus = "PASS";
    else if (/spf=softfail/i.test(rawHeaders)) spfStatus = "SOFTFAIL";
    else if (/spf=fail/i.test(rawHeaders)) spfStatus = "FAIL";
    else if (/spf=none/i.test(rawHeaders)) spfStatus = "NONE";

    let dkimStatus: HeaderAnalysis["dkimStatus"] = "UNKNOWN";
    if (/dkim=pass/i.test(rawHeaders)) dkimStatus = "PASS";
    else if (/dkim=fail/i.test(rawHeaders)) dkimStatus = "FAIL";
    else if (/dkim=none/i.test(rawHeaders)) dkimStatus = "NONE";

    let dmarcStatus: HeaderAnalysis["dmarcStatus"] = "UNKNOWN";
    if (/dmarc=pass/i.test(rawHeaders)) dmarcStatus = "PASS";
    else if (/dmarc=fail/i.test(rawHeaders)) dmarcStatus = "FAIL";
    else if (/dmarc=none/i.test(rawHeaders)) dmarcStatus = "NONE";

    // Extract embedded URLs
    const urlMatches = rawHeaders.match(/https?:\/\/[^\s<>"')]+/gi) || [];
    const uniqueUrls = Array.from(new Set(urlMatches));
    const urlResults = uniqueUrls.map((u) => analyzeThreatV2(u));

    setAnalysis({
      fromAddress,
      fromDisplayName,
      replyToAddress,
      isReplyToMismatch,
      isDisplayNameSpoofing,
      spfStatus,
      dkimStatus,
      dmarcStatus,
      extractedUrls: uniqueUrls,
      urlResults,
    });
  };

  return (
    <div className="rounded-2xl border border-border bg-card p-5 sm:p-6 shadow-sm space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-base sm:text-lg font-bold text-slate-100 flex items-center gap-2">
            <Mail className="w-5 h-5 text-primary" />
            <span>Raw Email Header & SPF/DKIM/DMARC Spoofing Analyzer</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Offline RFC 5322 header inspection. Detects display name impersonation, Reply-To mismatches, and evaluates embedded links.
          </p>
        </div>

        <button
          onClick={() => {
            setRawHeaders(sampleEmail);
          }}
          className="text-xs text-primary hover:underline font-semibold cursor-pointer text-left sm:text-right"
        >
          Load Phishing Email Sample &rarr;
        </button>
      </div>

      {/* Input Textarea */}
      <div className="space-y-3">
        <textarea
          rows={6}
          value={rawHeaders}
          onChange={(e) => setRawHeaders(e.target.value)}
          placeholder="Paste raw email headers and body here (e.g. From: ..., Authentication-Results: ...)..."
          className="w-full rounded-xl border border-border bg-slate-950 p-3.5 font-mono text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-primary/40 resize-y"
        />

        <div className="flex justify-end">
          <button
            onClick={handleAnalyze}
            disabled={!rawHeaders.trim()}
            className="px-5 py-2 rounded-xl bg-primary hover:bg-blue-600 disabled:opacity-50 text-white font-bold text-xs shadow-md transition-all cursor-pointer"
          >
            Inspect Email Telemetry (Zero Network)
          </button>
        </div>
      </div>

      {/* Analysis Output */}
      {analysis && (
        <div className="space-y-4 pt-3 border-t border-border animate-fade-in">
          
          {/* Email Authentication Badges */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="p-3 rounded-xl border border-border bg-slate-950 flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300">SPF Verification:</span>
              <span
                className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold ${
                  analysis.spfStatus === "PASS"
                    ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                    : analysis.spfStatus === "FAIL" || analysis.spfStatus === "SOFTFAIL"
                    ? "bg-red-500/10 text-red-400 border border-red-500/30"
                    : "bg-slate-800 text-slate-400"
                }`}
              >
                {analysis.spfStatus}
              </span>
            </div>

            <div className="p-3 rounded-xl border border-border bg-slate-950 flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300">DKIM Signature:</span>
              <span
                className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold ${
                  analysis.dkimStatus === "PASS"
                    ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                    : analysis.dkimStatus === "FAIL"
                    ? "bg-red-500/10 text-red-400 border border-red-500/30"
                    : "bg-slate-800 text-slate-400"
                }`}
              >
                {analysis.dkimStatus}
              </span>
            </div>

            <div className="p-3 rounded-xl border border-border bg-slate-950 flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300">DMARC Policy:</span>
              <span
                className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold ${
                  analysis.dmarcStatus === "PASS"
                    ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                    : analysis.dmarcStatus === "FAIL"
                    ? "bg-red-500/10 text-red-400 border border-red-500/30"
                    : "bg-slate-800 text-slate-400"
                }`}
              >
                {analysis.dmarcStatus}
              </span>
            </div>
          </div>

          {/* Sender Spoofing Indicators */}
          <div className="space-y-2">
            {analysis.isDisplayNameSpoofing && (
              <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center gap-2">
                <AlertOctagon className="w-4 h-4 shrink-0" />
                <span>
                  <strong>CRITICAL - Display Name Spoofing:</strong> Sender uses brand name &apos;{analysis.fromDisplayName}&apos;
                  while transmitting from unrelated address &lt;{analysis.fromAddress}&gt;.
                </span>
              </div>
            )}

            {analysis.isReplyToMismatch && (
              <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 shrink-0" />
                <span>
                  <strong>WARNING - Reply-To Mismatch:</strong> Replies will be routed to &lt;{analysis.replyToAddress}&gt;
                  instead of displayed sender &lt;{analysis.fromAddress}&gt;.
                </span>
              </div>
            )}
          </div>

          {/* Embedded URL Inspection */}
          {analysis.urlResults.length > 0 && (
            <div className="space-y-2 pt-2">
              <h4 className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                <span>Extracted Body Links ({analysis.urlResults.length}):</span>
              </h4>
              <div className="space-y-2">
                {analysis.urlResults.map((r, i) => (
                  <div
                    key={i}
                    className="p-3 rounded-xl border border-border bg-slate-950 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                  >
                    <div>
                      <span className="font-mono text-slate-200 font-semibold">{defangUrl(r.rawUrl)}</span>
                      <p className="text-[11px] text-slate-400 mt-0.5">{r.executiveSummary}</p>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <span className="font-mono font-bold text-slate-300">{r.riskScore}/100</span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase ${
                          r.classification === "HIGH RISK"
                            ? "bg-red-500/10 text-red-400 border border-red-500/30"
                            : r.classification === "MEDIUM RISK"
                            ? "bg-amber-500/10 text-amber-400 border border-amber-500/30"
                            : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                        }`}
                      >
                        {r.classification}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>
      )}
    </div>
  );
}
