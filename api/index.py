import os
import sys
import json
import re
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, unquote

# ============================================================================
# SELF-CONTAINED BACKEND LOGIC (Ensures zero import failure on Vercel)
# ============================================================================

SUSPICIOUS_KEYWORDS = (
    "login", "verify", "secure", "account", "banking",
    "password", "reward", "free", "bonus", "update",
)

WEIGHT_IP_ADDRESS = 35
WEIGHT_KEYWORD_BASE = 25
WEIGHT_AT_SYMBOL = 25
WEIGHT_PUNYCODE = 20
WEIGHT_HTTP = 15
WEIGHT_LONG_URL = 10
WEIGHT_MANY_SEGMENTS = 10
WEIGHT_KEYWORD_ADDITIONAL = 5

def clean_and_normalize_url(raw_url: str) -> str:
    cleaned = raw_url.strip()
    if not cleaned:
        return ""
    if "://" not in cleaned:
        cleaned = "http://" + cleaned
    return cleaned

def is_valid_ipv4(host: str) -> bool:
    pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    match = re.fullmatch(pattern, host)
    if not match:
        return False
    return all(0 <= int(octet) <= 255 for octet in match.groups())

def scan_suspicious_keywords(url_string: str) -> list:
    found_keywords = []
    url_lower = url_string.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url_lower:
            found_keywords.append(kw)
    return found_keywords

def inspect_url(raw_url: str) -> dict:
    raw_cleaned = raw_url.strip()
    result = {
        "raw_url": raw_cleaned,
        "is_valid": False,
        "warnings": [],
        "risk_score": 0,
        "classification": "SAFE-LOOKING",
        "recommendation": "No listed warning signs found. This does NOT prove safety.",
        "error_message": None,
    }

    if not raw_cleaned:
        result["error_message"] = "No URL entered."
        return result

    candidate = clean_and_normalize_url(raw_cleaned)

    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
    except ValueError:
        result["error_message"] = "Malformed URL format (invalid structure)."
        return result

    if not host:
        result["error_message"] = "Could not identify a valid hostname."
        return result

    result["is_valid"] = True
    warnings = []
    score = 0

    if parsed.scheme.lower() == "http":
        warnings.append("HTTP detected")
        score += WEIGHT_HTTP

    if is_valid_ipv4(host):
        warnings.append("IP address detected")
        score += WEIGHT_IP_ADDRESS

    if "@" in candidate:
        warnings.append("@ symbol detected")
        score += WEIGHT_AT_SYMBOL

    labels = [part for part in host.split(".") if part]
    if len(labels) >= 5:
        warnings.append("Excessive hostname segments detected (5 or more parts)")
        score += WEIGHT_MANY_SEGMENTS

    if "xn--" in host:
        warnings.append("Punycode hostname detected (xn--)")
        score += WEIGHT_PUNYCODE

    if len(raw_cleaned) > 100:
        warnings.append("Unusually long URL (over 100 characters)")
        score += WEIGHT_LONG_URL

    detected_keywords = scan_suspicious_keywords(candidate)
    if detected_keywords:
        for kw in detected_keywords:
            warnings.append(f"Suspicious keyword: {kw}")
        kw_score = WEIGHT_KEYWORD_BASE + (len(detected_keywords) - 1) * WEIGHT_KEYWORD_ADDITIONAL
        score += min(kw_score, 30)

    score = min(max(score, 0), 100)
    result["warnings"] = warnings
    result["risk_score"] = score

    if score == 0:
        result["classification"] = "SAFE-LOOKING"
        result["recommendation"] = "No listed warning signs found. This does NOT prove safety. Always verify."
    elif 1 <= score <= 20:
        result["classification"] = "SAFE-LOOKING"
        result["recommendation"] = "Minimal structural anomalies detected. Exercise standard vigilance."
    elif 21 <= score <= 40:
        result["classification"] = "LOW RISK"
        result["recommendation"] = "Minor indicators observed. Verify authenticity before submitting credentials."
    elif 41 <= score <= 70:
        result["classification"] = "MEDIUM RISK"
        result["recommendation"] = "Notable suspicious indicators detected. Exercise high caution."
    else:
        result["classification"] = "HIGH RISK"
        result["recommendation"] = "Review carefully before interacting."

    return result

# ============================================================================
# WINDOWS 7 AERO GLASS INTERFACE TEMPLATE
# ============================================================================

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Windows 7 Security Center - Phishing URL Awareness Checker</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    
    body {
      background: radial-gradient(circle at 50% 30%, #1e5799 0%, #133966 50%, #0a1b33 100%);
      font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 24px 12px;
      color: #1e293b;
      overflow-x: hidden;
    }

    /* Ambient Wallpaper Lighting */
    body::before {
      content: '';
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: radial-gradient(circle at 80% 20%, rgba(255, 255, 255, 0.12) 0%, transparent 40%),
                  radial-gradient(circle at 20% 80%, rgba(0, 150, 255, 0.15) 0%, transparent 50%);
      pointer-events: none;
    }

    /* Windows 7 Aero Glass Container */
    .aero-window {
      width: 100%;
      max-width: 920px;
      background: rgba(240, 246, 255, 0.82);
      backdrop-filter: blur(20px) saturate(180%);
      -webkit-backdrop-filter: blur(20px) saturate(180%);
      border: 1px solid rgba(255, 255, 255, 0.85);
      border-radius: 8px;
      box-shadow: 0 25px 60px rgba(0, 0, 0, 0.55),
                  0 0 0 1px rgba(0, 0, 0, 0.3),
                  inset 0 1px 0 rgba(255, 255, 255, 0.9),
                  inset 0 0 15px rgba(255, 255, 255, 0.4);
      position: relative;
      z-index: 10;
      overflow: hidden;
    }

    /* Aero Glass Title Bar */
    .aero-titlebar {
      height: 38px;
      background: linear-gradient(180deg, 
        rgba(255, 255, 255, 0.6) 0%, 
        rgba(210, 230, 255, 0.45) 45%, 
        rgba(175, 210, 255, 0.25) 50%, 
        rgba(195, 225, 255, 0.5) 100%);
      border-bottom: 1px solid rgba(130, 165, 205, 0.6);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 8px 0 12px;
      user-select: none;
    }

    .aero-title {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 13px;
      font-weight: 600;
      color: #0f172a;
      text-shadow: 0 1px 1px rgba(255, 255, 255, 0.9), 0 0 8px rgba(255, 255, 255, 0.8);
    }

    .aero-icon {
      font-size: 16px;
      filter: drop-shadow(0 1px 2px rgba(0,0,0,0.3));
    }

    /* Aero Window Controls (Min, Max, Close) */
    .aero-controls {
      display: flex;
      align-items: center;
      gap: 2px;
    }

    .aero-btn {
      width: 28px;
      height: 20px;
      border: 1px solid rgba(120, 150, 180, 0.7);
      background: linear-gradient(180deg, #ffffff 0%, #d8e5f2 50%, #b8d2eb 51%, #cce0f5 100%);
      border-radius: 3px;
      font-size: 11px;
      font-weight: bold;
      color: #334155;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.9);
      transition: all 0.15s ease;
    }

    .aero-btn:hover {
      background: linear-gradient(180deg, #ffffff 0%, #eef5fc 50%, #d4e7fa 51%, #e5f1fd 100%);
      border-color: #60a5fa;
    }

    .aero-btn-close {
      width: 44px;
      background: linear-gradient(180deg, #fca5a5 0%, #ef4444 50%, #dc2626 51%, #ef4444 100%);
      border-color: #b91c1c;
      color: #ffffff;
      text-shadow: 0 1px 1px rgba(0, 0, 0, 0.4);
    }

    .aero-btn-close:hover {
      background: linear-gradient(180deg, #f87171 0%, #dc2626 50%, #b91c1c 51%, #f87171 100%);
      box-shadow: 0 0 8px rgba(239, 68, 68, 0.8), inset 0 1px 0 rgba(255, 255, 255, 0.4);
    }

    /* Ribbon / Menu Tabs */
    .aero-tabs {
      display: flex;
      background: linear-gradient(180deg, #e4edf8 0%, #d0e0f2 100%);
      padding: 6px 14px 0 14px;
      border-bottom: 1px solid #a8c4e0;
      gap: 4px;
    }

    .tab-btn {
      padding: 6px 16px;
      font-size: 12px;
      font-weight: 600;
      border: 1px solid transparent;
      border-bottom: none;
      border-radius: 4px 4px 0 0;
      cursor: pointer;
      background: transparent;
      color: #334155;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .tab-btn.active {
      background: #ffffff;
      border-color: #a8c4e0;
      color: #0f172a;
      box-shadow: 0 -2px 5px rgba(0, 0, 0, 0.04);
    }

    /* Window Body */
    .aero-content {
      background: #ffffff;
      padding: 22px;
      min-height: 440px;
    }

    /* Top Banner Inside App */
    .sec-banner {
      display: flex;
      align-items: center;
      gap: 16px;
      padding: 16px;
      background: linear-gradient(180deg, #f8fafc 0%, #edf2f7 100%);
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      margin-bottom: 20px;
    }

    .sec-shield {
      font-size: 38px;
      filter: drop-shadow(0 2px 4px rgba(0,0,0,0.15));
    }

    .sec-banner h2 {
      font-size: 18px;
      color: #0f172a;
      font-weight: 700;
      margin-bottom: 3px;
    }

    .sec-banner p {
      font-size: 13px;
      color: #64748b;
      line-height: 1.4;
    }

    /* Input Toolbar */
    .search-box {
      background: #f1f5f9;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      padding: 16px;
      margin-bottom: 20px;
    }

    .input-label {
      font-size: 12px;
      font-weight: 700;
      color: #475569;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 8px;
      display: block;
    }

    .input-row {
      display: flex;
      gap: 8px;
    }

    .aero-input {
      flex: 1;
      padding: 10px 14px;
      font-family: 'Consolas', 'Courier New', monospace;
      font-size: 14px;
      border: 1px solid #94a3b8;
      border-radius: 4px;
      outline: none;
      background: #ffffff;
      box-shadow: inset 0 1px 3px rgba(0,0,0,0.1);
      transition: all 0.2s ease;
    }

    .aero-input:focus {
      border-color: #3b82f6;
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.25);
    }

    .aero-action-btn {
      padding: 0 20px;
      background: linear-gradient(180deg, #3b82f6 0%, #1d4ed8 100%);
      border: 1px solid #1e40af;
      color: #ffffff;
      font-size: 13px;
      font-weight: 600;
      border-radius: 4px;
      cursor: pointer;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.35), 0 2px 4px rgba(0, 0, 0, 0.15);
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .aero-action-btn:hover {
      background: linear-gradient(180deg, #60a5fa 0%, #2563eb 100%);
    }

    .aero-action-btn:active {
      transform: translateY(1px);
    }

    /* Quick Test Preset Buttons */
    .presets-row {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
      margin-top: 10px;
    }

    .presets-title {
      font-size: 11px;
      font-weight: 600;
      color: #64748b;
    }

    .preset-chip {
      background: #e2e8f0;
      border: 1px solid #cbd5e1;
      border-radius: 3px;
      padding: 3px 8px;
      font-size: 11px;
      font-family: 'Consolas', monospace;
      color: #334155;
      cursor: pointer;
      transition: all 0.1s;
    }

    .preset-chip:hover {
      background: #3b82f6;
      border-color: #2563eb;
      color: #ffffff;
    }

    /* Result Dashboard Grid */
    .dashboard-grid {
      display: grid;
      grid-template-columns: 280px 1fr;
      gap: 16px;
      margin-bottom: 20px;
    }

    @media (max-width: 768px) {
      .dashboard-grid { grid-template-columns: 1fr; }
    }

    .score-card {
      background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      padding: 20px;
      text-align: center;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
    }

    .score-title {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #64748b;
      margin-bottom: 12px;
    }

    .score-meter {
      font-size: 46px;
      font-weight: 800;
      font-family: 'Consolas', monospace;
      margin-bottom: 8px;
      line-height: 1;
    }

    .risk-badge {
      display: inline-block;
      font-size: 12px;
      font-weight: 700;
      padding: 5px 14px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      box-shadow: 0 1px 2px rgba(0,0,0,0.1);
    }

    .badge-safe { background: #dcfce7; color: #15803d; border: 1px solid #86efac; }
    .badge-low { background: #dbeafe; color: #1d4ed8; border: 1px solid #93c5fd; }
    .badge-medium { background: #fef3c7; color: #b45309; border: 1px solid #fde047; }
    .badge-high { background: #fee2e2; color: #b91c1c; border: 1px solid #fca5a5; }

    /* Findings Panel */
    .findings-card {
      background: #ffffff;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      padding: 16px;
    }

    .findings-header {
      font-size: 12px;
      font-weight: 700;
      color: #475569;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 12px;
      padding-bottom: 6px;
      border-bottom: 1px solid #e2e8f0;
      display: flex;
      justify-content: space-between;
    }

    .warning-list {
      display: flex;
      flex-direction: column;
      gap: 6px;
      margin-bottom: 14px;
      max-height: 170px;
      overflow-y: auto;
    }

    .warning-row {
      display: flex;
      align-items: center;
      gap: 8px;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      padding: 8px 12px;
      border-radius: 4px;
      font-family: 'Consolas', monospace;
      font-size: 12px;
    }

    .warning-row.warn {
      background: #fff1f2;
      border-color: #fecdd3;
      color: #9f1239;
    }

    .warning-row.ok {
      background: #f0fdf4;
      border-color: #bbf7d0;
      color: #166534;
    }

    .rec-box {
      background: #eff6ff;
      border-left: 4px solid #3b82f6;
      padding: 10px 14px;
      border-radius: 0 4px 4px 0;
      font-size: 13px;
      color: #1e3a8a;
      line-height: 1.4;
    }

    /* Terminal Tab (Windows 7 cmd.exe look) */
    .terminal-container {
      display: none;
      background: #0c0c0c;
      border: 1px solid #333333;
      border-radius: 4px;
      padding: 14px;
      font-family: 'Consolas', 'Lucida Console', monospace;
      font-size: 13px;
      color: #cccccc;
      min-height: 380px;
      max-height: 500px;
      overflow-y: auto;
      line-height: 1.5;
    }

    .term-green { color: #22c55e; }
    .term-red { color: #ef4444; }
    .term-yellow { color: #eab308; }
    .term-cyan { color: #38bdf8; }
    .term-dim { color: #64748b; }

    /* Windows 7 Aero Status Bar */
    .aero-statusbar {
      height: 26px;
      background: linear-gradient(180deg, #f1f5f9 0%, #e2e8f0 100%);
      border-top: 1px solid #cbd5e1;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 12px;
      font-size: 11px;
      color: #475569;
      user-select: none;
    }

    .status-item {
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      background: #22c55e;
      border-radius: 50%;
      box-shadow: 0 0 6px #22c55e;
    }
  </style>
</head>
<body>

  <!-- Windows 7 Aero Window -->
  <div class="aero-window">
    
    <!-- Title Bar -->
    <div class="aero-titlebar">
      <div class="aero-title">
        <span class="aero-icon">🛡️</span>
        <span>Phishing URL Awareness Checker - Windows Security Center</span>
      </div>
      <div class="aero-controls">
        <button class="aero-btn" title="Minimize">_</button>
        <button class="aero-btn" title="Maximize">□</button>
        <button class="aero-btn aero-btn-close" title="Close">✕</button>
      </div>
    </div>

    <!-- Tabs / Navigation -->
    <div class="aero-tabs">
      <button class="tab-btn active" id="tabDashboard" onclick="switchView('dashboard')">
        <span>🛡️</span> Security Dashboard
      </button>
      <button class="tab-btn" id="tabTerminal" onclick="switchView('terminal')">
        <span>💻</span> Windows Command Prompt (cmd.exe)
      </button>
    </div>

    <!-- Window Main Body -->
    <div class="aero-content">
      
      <!-- Top Security Banner -->
      <div class="sec-banner">
        <div class="sec-shield">🛡️</div>
        <div>
          <h2>Heuristic URL Text Inspection</h2>
          <p>Zero network queries. Purely localized, static syntactic analysis protecting your credentials from phishing, obfuscation, and homoglyph attacks.</p>
        </div>
      </div>

      <!-- Search & Input Box -->
      <div class="search-box">
        <label class="input-label" for="urlInput">Enter Web Link to Inspect:</label>
        <div class="input-row">
          <input type="text" id="urlInput" class="aero-input" placeholder="e.g. http://192.0.2.10/login or https://example.com" value="http://192.0.2.10/login" onkeydown="if(event.key==='Enter') runAnalysis()">
          <button class="aero-action-btn" onclick="runAnalysis()">
            <span>🔍</span> Inspect Link
          </button>
        </div>

        <!-- Presets -->
        <div class="presets-row">
          <span class="presets-title">Quick Test:</span>
          <span class="preset-chip" onclick="setAndRun('http://192.0.2.10/login')">IP + HTTP + Login</span>
          <span class="preset-chip" onclick="setAndRun('https://www.example.com/')">Clean HTTPS</span>
          <span class="preset-chip" onclick="setAndRun('http://example.com@sample.invalid/login')">@ Disguise</span>
          <span class="preset-chip" onclick="setAndRun('https://xn--example.invalid/')">Punycode (xn--)</span>
          <span class="preset-chip" onclick="setAndRun('https://a.b.c.d.e.example.invalid/path')">5 Subdomains</span>
          <span class="preset-chip" onclick="setAndRun('https://claude.ai/chat/c6bfaa97-602e-4ba5-9087-69c654157747')">Claude.ai URL</span>
        </div>
      </div>

      <!-- DASHBOARD VIEW -->
      <div id="viewDashboard">
        <div class="dashboard-grid">
          
          <!-- Score Gauge Card -->
          <div class="score-card">
            <div class="score-title">Threat Risk Index</div>
            <div class="score-meter" id="scoreValue">75/100</div>
            <div class="risk-badge badge-high" id="classBadge">HIGH RISK</div>
          </div>

          <!-- Findings & Warnings -->
          <div class="findings-card">
            <div class="findings-header">
              <span>Observed Warnings & Red Flags</span>
              <span id="warningCountText">3 Warnings Found</span>
            </div>
            
            <div class="warning-list" id="warningRows">
              <!-- Dynamically populated -->
            </div>

            <div class="rec-box">
              <strong>Recommendation:</strong> <span id="recText">Review carefully before interacting.</span>
            </div>
          </div>

        </div>
      </div>

      <!-- TERMINAL VIEW (cmd.exe) -->
      <div id="viewTerminal" class="terminal-container">
        <div class="term-dim">Microsoft Windows [Version 6.1.7601] (Windows 7 Ultimate SP1)</div>
        <div class="term-dim">(c) 2009 Microsoft Corporation. All rights reserved.</div>
        <br>
        <div><span class="term-cyan">C:\Users\ManishPatil></span> <span id="termCmd">python phishing_checker.py</span></div>
        <br>
        <div id="termOutput">
          <!-- Terminal Output Formatted Here -->
        </div>
      </div>

    </div>

    <!-- Status Bar -->
    <div class="aero-statusbar">
      <div class="status-item">
        <span class="status-dot"></span>
        <span>Local Protection: Active (Zero Network Transmission)</span>
      </div>
      <div>
        <span>Candidate: <strong>Manish Pundlik Patil</strong> | ID: <code>EWB-OL-2026-CYB-0195</code></span>
      </div>
    </div>

  </div>

  <script>
    // ========================================================================
    // CLIENT-SIDE LOCAL HEURISTIC ENGINE (100% RELIABLE - NEVER FAILS)
    // ========================================================================
    const SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "account", "banking", "password", "reward", "free", "bonus", "update"];

    function isIpv4(host) {
      const parts = host.split('.');
      if (parts.length !== 4) return false;
      return parts.every(part => {
        if (!/^\d{1,3}$/.test(part)) return false;
        const n = parseInt(part, 10);
        return n >= 0 && n <= 255;
      });
    }

    function analyzeLocally(rawUrl) {
      const trimmed = (rawUrl || '').trim();
      if (!trimmed) {
        return {
          error_message: "No URL entered.",
          is_valid: false,
          warnings: [],
          risk_score: 0,
          classification: "SAFE-LOOKING",
          recommendation: "Provide a valid URL string for structural text analysis."
        };
      }

      let candidate = trimmed;
      if (!candidate.includes("://")) {
        candidate = "http://" + candidate;
      }

      let parsed;
      try {
        parsed = new URL(candidate);
      } catch (e) {
        return {
          error_message: "Malformed URL format (invalid structure).",
          is_valid: false,
          warnings: [],
          risk_score: 0,
          classification: "SAFE-LOOKING",
          recommendation: "Provide a valid URL string for structural text analysis."
        };
      }

      const host = (parsed.hostname || '').toLowerCase();
      if (!host) {
        return {
          error_message: "Could not identify a valid hostname.",
          is_valid: false,
          warnings: [],
          risk_score: 0,
          classification: "SAFE-LOOKING",
          recommendation: "Provide a valid URL string for structural text analysis."
        };
      }

      const warnings = [];
      let score = 0;

      // Check 1: HTTP
      if (parsed.protocol === "http:") {
        warnings.push("HTTP detected");
        score += 15;
      }

      // Check 2: IP address
      if (isIpv4(host)) {
        warnings.push("IP address detected");
        score += 35;
      }

      // Check 3: @ symbol
      if (candidate.includes("@")) {
        warnings.push("@ symbol detected");
        score += 25;
      }

      // Check 4: Hostname segments
      const labels = host.split('.').filter(Boolean);
      if (labels.length >= 5) {
        warnings.push("Excessive hostname segments detected (5 or more parts)");
        score += 10;
      }

      // Check 5: Punycode
      if (host.includes("xn--")) {
        warnings.push("Punycode hostname detected (xn--)");
        score += 20;
      }

      // Check 6: Length > 100
      if (trimmed.length > 100) {
        warnings.push("Unusually long URL (over 100 characters)");
        score += 10;
      }

      // Check 7: Keywords
      const candLower = candidate.toLowerCase();
      const detectedKw = [];
      for (const kw of SUSPICIOUS_KEYWORDS) {
        if (candLower.includes(kw)) {
          detectedKw.push(kw);
        }
      }
      if (detectedKw.length > 0) {
        detectedKw.forEach(kw => warnings.push("Suspicious keyword: " + kw));
        const kwScore = 25 + (detectedKw.length - 1) * 5;
        score += Math.min(kwScore, 30);
      }

      score = Math.min(Math.max(score, 0), 100);

      let classification = "SAFE-LOOKING";
      let recommendation = "No listed warning signs found. This does NOT prove safety. Always verify.";

      if (score === 0) {
        classification = "SAFE-LOOKING";
        recommendation = "No listed warning signs found. This does NOT prove safety. Always verify.";
      } else if (score <= 20) {
        classification = "SAFE-LOOKING";
        recommendation = "Minimal structural anomalies detected. Exercise standard vigilance.";
      } else if (score <= 40) {
        classification = "LOW RISK";
        recommendation = "Minor indicators observed. Verify authenticity before submitting credentials.";
      } else if (score <= 70) {
        classification = "MEDIUM RISK";
        recommendation = "Notable suspicious indicators detected. Exercise high caution.";
      } else {
        classification = "HIGH RISK";
        recommendation = "Review carefully before interacting.";
      }

      return {
        raw_url: trimmed,
        is_valid: true,
        warnings,
        risk_score: score,
        classification,
        recommendation,
        error_message: null
      };
    }

    // ========================================================================
    // UI CONTROLLER
    // ========================================================================

    function switchView(viewName) {
      const tabDash = document.getElementById('tabDashboard');
      const tabTerm = document.getElementById('tabTerminal');
      const viewDash = document.getElementById('viewDashboard');
      const viewTerm = document.getElementById('viewTerminal');

      if (viewName === 'dashboard') {
        tabDash.classList.add('active');
        tabTerm.classList.remove('active');
        viewDash.style.display = 'block';
        viewTerm.style.display = 'none';
      } else {
        tabTerm.classList.add('active');
        tabDash.classList.remove('active');
        viewDash.style.display = 'none';
        viewTerm.style.display = 'block';
      }
    }

    function setAndRun(url) {
      document.getElementById('urlInput').value = url;
      runAnalysis();
    }

    function runAnalysis() {
      const url = document.getElementById('urlInput').value;
      const res = analyzeLocally(url);
      renderResults(res);
    }

    function renderResults(data) {
      const scoreVal = document.getElementById('scoreValue');
      const classBadge = document.getElementById('classBadge');
      const warningRows = document.getElementById('warningRows');
      const warningCountText = document.getElementById('warningCountText');
      const recText = document.getElementById('recText');

      if (data.error_message) {
        scoreVal.innerText = 'N/A';
        scoreVal.style.color = '#ef4444';
        classBadge.className = 'risk-badge badge-high';
        classBadge.innerText = 'INVALID INPUT';
        warningCountText.innerText = 'Input Error';
        warningRows.innerHTML = `<div class="warning-row warn">[!] ${data.error_message}</div>`;
        recText.innerText = data.recommendation;
        updateTerminal(data);
        return;
      }

      scoreVal.innerText = data.risk_score + '/100';
      classBadge.innerText = data.classification;

      if (data.classification === 'HIGH RISK') {
        scoreVal.style.color = '#dc2626';
        classBadge.className = 'risk-badge badge-high';
      } else if (data.classification === 'MEDIUM RISK') {
        scoreVal.style.color = '#d97706';
        classBadge.className = 'risk-badge badge-medium';
      } else if (data.classification === 'LOW RISK') {
        scoreVal.style.color = '#2563eb';
        classBadge.className = 'risk-badge badge-low';
      } else {
        scoreVal.style.color = '#16a34a';
        classBadge.className = 'risk-badge badge-safe';
      }

      if (data.warnings && data.warnings.length > 0) {
        warningCountText.innerText = data.warnings.length + ' Warning(s) Detected';
        warningRows.innerHTML = data.warnings.map((w, idx) => `
          <div class="warning-row warn">
            <span>[${idx + 1}]</span>
            <span>${w}</span>
          </div>
        `).join('');
      } else {
        warningCountText.innerText = '0 Warnings Detected';
        warningRows.innerHTML = `
          <div class="warning-row ok">
            <span>[0]</span>
            <span>No listed warning signs found. This does NOT prove safety.</span>
          </div>
        `;
      }

      recText.innerText = data.recommendation;
      updateTerminal(data);
    }

    function updateTerminal(data) {
      const termOutput = document.getElementById('termOutput');
      let out = '';
      out += '<div class="term-cyan">================================</div>';
      out += '<div class="term-cyan">PHISHING URL AWARENESS CHECKER</div>';
      out += '<div class="term-cyan">================================</div><br>';

      if (data.error_message) {
        out += `<div class="term-red">Notice: ${data.error_message}</div><br>`;
      } else {
        out += '<div>Warnings Found:</div>';
        if (!data.warnings || data.warnings.length === 0) {
          out += '<div class="term-green">[0] No listed warning signs found.</div>';
        } else {
          data.warnings.forEach((w, i) => {
            out += `<div class="term-yellow">[${i + 1}] ${w}</div>`;
          });
        }
        out += '<br>';
        out += `<div>Risk Score: <span class="${data.risk_score >= 70 ? 'term-red' : 'term-cyan'}">${data.risk_score}/100</span></div><br>`;
        out += `<div>Classification:<br><span class="${data.risk_score >= 70 ? 'term-red' : 'term-green'}">${data.classification}</span></div><br>`;
        out += `<div>Recommendation:<br><span class="term-yellow">${data.recommendation}</span></div>`;
      }

      out += '<br><div class="term-cyan">================================</div>';
      termOutput.innerHTML = out;
    }

    // Auto-execute default benchmark on load
    window.addEventListener('DOMContentLoaded', runAnalysis);
  </script>
</body>
</html>
"""

# ============================================================================
# HTTP REQUEST HANDLER
# ============================================================================

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query = parse_qs(parsed_url.query)

        # API endpoint: /api/scan?url=...
        if path.startswith("/api/scan"):
            url = query.get("url", [""])[0]
            analysis = inspect_url(url)
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(analysis).encode("utf-8"))
            return

        # Serve Windows 7 Aero Glass Web Dashboard
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(HTML_TEMPLATE.encode("utf-8"))

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""

        url_to_inspect = ""
        try:
            body = json.loads(post_data)
            url_to_inspect = body.get("url", "")
        except json.JSONDecodeError:
            params = parse_qs(post_data)
            url_to_inspect = params.get("url", [""])[0]

        analysis = inspect_url(url_to_inspect)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(analysis).encode("utf-8"))
