import os
import sys
import json
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, unquote

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from phishing_checker import inspect_url, format_report

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Phishing URL Awareness Checker | Defensive Security</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --border: #1f293d;
      --accent-blue: #3b82f6;
      --accent-cyan: #06b6d4;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
      --safe: #10b981;
      --low: #3b82f6;
      --medium: #f59e0b;
      --high: #ef4444;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text-main);
      font-family: 'Plus Jakarta Sans', sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 40px 20px;
    }
    .container {
      width: 100%;
      max-width: 860px;
    }
    .header {
      text-align: center;
      margin-bottom: 32px;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(6, 182, 212, 0.12);
      color: var(--accent-cyan);
      border: 1px solid rgba(6, 182, 212, 0.3);
      padding: 6px 14px;
      border-radius: 9999px;
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 14px;
      letter-spacing: 0.5px;
    }
    h1 {
      font-size: 32px;
      font-weight: 700;
      letter-spacing: -0.5px;
      margin-bottom: 10px;
      background: linear-gradient(135deg, #ffffff 0%, #9ca3af 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    p.subtitle {
      color: var(--text-muted);
      font-size: 15px;
      max-width: 600px;
      margin: 0 auto;
      line-height: 1.5;
    }
    .card {
      background-color: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 28px;
      box-shadow: 0 20px 40px -15px rgba(0, 0, 0, 0.5);
      margin-bottom: 24px;
    }
    .input-group {
      display: flex;
      gap: 12px;
      margin-bottom: 20px;
    }
    input[type="text"] {
      flex: 1;
      background: #090d16;
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 14px 18px;
      font-size: 15px;
      font-family: 'JetBrains Mono', monospace;
      border-radius: 10px;
      outline: none;
      transition: all 0.2s ease;
    }
    input[type="text"]:focus {
      border-color: var(--accent-cyan);
      box-shadow: 0 0 0 3px rgba(6, 182, 212, 0.2);
    }
    button.btn-scan {
      background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%);
      color: #ffffff;
      border: none;
      font-weight: 600;
      font-size: 15px;
      padding: 0 24px;
      border-radius: 10px;
      cursor: pointer;
      transition: transform 0.15s ease, opacity 0.2s ease;
    }
    button.btn-scan:hover {
      opacity: 0.95;
      transform: translateY(-1px);
    }
    button.btn-scan:active {
      transform: translateY(0);
    }
    .presets {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
      font-size: 13px;
      color: var(--text-muted);
    }
    .preset-pill {
      background: #1a2234;
      border: 1px solid #28354f;
      color: #cbd5e1;
      padding: 5px 12px;
      border-radius: 6px;
      cursor: pointer;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      transition: all 0.15s ease;
    }
    .preset-pill:hover {
      background: #23304a;
      border-color: var(--accent-cyan);
      color: #ffffff;
    }
    .results-card {
      display: none;
      animation: fadeIn 0.3s ease;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .score-banner {
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid var(--border);
      padding-bottom: 20px;
      margin-bottom: 20px;
    }
    .score-circle-wrapper {
      display: flex;
      align-items: center;
      gap: 16px;
    }
    .score-metric {
      font-family: 'JetBrains Mono', monospace;
      font-size: 38px;
      font-weight: 700;
    }
    .class-tag {
      display: inline-block;
      font-weight: 700;
      font-size: 13px;
      letter-spacing: 0.5px;
      padding: 6px 14px;
      border-radius: 6px;
      text-transform: uppercase;
    }
    .class-safe { background: rgba(16, 185, 129, 0.15); color: var(--safe); border: 1px solid rgba(16, 185, 129, 0.3); }
    .class-low { background: rgba(59, 130, 246, 0.15); color: var(--low); border: 1px solid rgba(59, 130, 246, 0.3); }
    .class-medium { background: rgba(245, 158, 11, 0.15); color: var(--medium); border: 1px solid rgba(245, 158, 11, 0.3); }
    .class-high { background: rgba(239, 68, 68, 0.15); color: var(--high); border: 1px solid rgba(239, 68, 68, 0.3); }
    .findings-section {
      margin-bottom: 20px;
    }
    .findings-title {
      font-size: 13px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-muted);
      margin-bottom: 12px;
    }
    .finding-item {
      display: flex;
      align-items: center;
      gap: 10px;
      background: #090d16;
      border: 1px solid var(--border);
      padding: 10px 14px;
      border-radius: 8px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
      margin-bottom: 8px;
    }
    .finding-index {
      color: var(--accent-cyan);
      font-weight: 600;
    }
    .recommendation-box {
      background: rgba(17, 24, 39, 0.8);
      border-left: 4px solid var(--accent-cyan);
      padding: 14px 18px;
      border-radius: 0 8px 8px 0;
      font-size: 14px;
      line-height: 1.5;
    }
    .footer {
      text-align: center;
      color: var(--text-muted);
      font-size: 13px;
      margin-top: auto;
      line-height: 1.6;
    }
    .footer a {
      color: var(--accent-cyan);
      text-decoration: none;
    }
    .footer a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="badge">🛡️ DEFENSIVE SECURITY ENGINE</div>
      <h1>Phishing URL Awareness Checker</h1>
      <p class="subtitle">Deterministic, zero-network static heuristic inspection for detecting deceptive link structures and social engineering indicators.</p>
    </div>

    <div class="card">
      <div class="input-group">
        <input type="text" id="urlInput" placeholder="Enter a sample URL (e.g. http://192.0.2.10/login)" value="http://192.0.2.10/login">
        <button class="btn-scan" onclick="performScan()">Inspect Link</button>
      </div>

      <div class="presets">
        <span>Test Samples:</span>
        <button class="preset-pill" onclick="loadSample('https://www.example.com/')">Clean HTTPS</button>
        <button class="preset-pill" onclick="loadSample('http://192.0.2.10/login')">IP + HTTP + Login</button>
        <button class="preset-pill" onclick="loadSample('http://example.com@sample.invalid/login')">@ Disguise</button>
        <button class="preset-pill" onclick="loadSample('https://xn--example.invalid/')">Punycode (xn--)</button>
        <button class="preset-pill" onclick="loadSample('https://a.b.c.d.e.example.invalid/path')">5 Subdomains</button>
      </div>
    </div>

    <div class="card results-card" id="resultsCard">
      <div class="score-banner">
        <div class="score-circle-wrapper">
          <div>
            <div class="findings-title">Risk Threat Index</div>
            <div class="score-metric" id="scoreDisplay">0/100</div>
          </div>
        </div>
        <div>
          <div class="findings-title">Classification</div>
          <span class="class-tag" id="classDisplay">SAFE-LOOKING</span>
        </div>
      </div>

      <div class="findings-section">
        <div class="findings-title">Observed Warnings & Heuristics</div>
        <div id="warningsList"></div>
      </div>

      <div class="recommendation-box" id="recBox">
        <strong>Recommendation:</strong> <span id="recText">Loading...</span>
      </div>
    </div>

    <div class="footer">
      <p>Developed by <strong>Manish Pundlik Patil</strong> (Intern ID: <code>EWB-OL-2026-CYB-0195</code>)</p>
      <p>EWB Edutech Private Limited | <a href="https://github.com/ManishPatil2005/phishing-url-awareness" target="_blank">View GitHub Repository</a></p>
    </div>
  </div>

  <script>
    function loadSample(url) {
      document.getElementById('urlInput').value = url;
      performScan();
    }

    async function performScan() {
      const input = document.getElementById('urlInput').value.trim();
      const resultsCard = document.getElementById('resultsCard');
      const scoreDisplay = document.getElementById('scoreDisplay');
      const classDisplay = document.getElementById('classDisplay');
      const warningsList = document.getElementById('warningsList');
      const recText = document.getElementById('recText');

      if (!input) {
        alert('Please enter a URL string to inspect.');
        return;
      }

      try {
        const response = await fetch('/api/scan?url=' + encodeURIComponent(input));
        const data = await response.json();

        resultsCard.style.display = 'block';

        if (data.error_message) {
          scoreDisplay.innerText = 'N/A';
          scoreDisplay.style.color = '#ef4444';
          classDisplay.className = 'class-tag class-high';
          classDisplay.innerText = 'INVALID INPUT';
          warningsList.innerHTML = `<div class="finding-item"><span class="finding-index">[!]</span> ${data.error_message}</div>`;
          recText.innerText = 'Provide a valid URL string for structural text analysis.';
          return;
        }

        const score = data.risk_score;
        scoreDisplay.innerText = score + '/100';

        let color = '#10b981';
        let clsName = 'class-tag class-safe';

        if (data.classification === 'HIGH RISK') {
          color = '#ef4444';
          clsName = 'class-tag class-high';
        } else if (data.classification === 'MEDIUM RISK') {
          color = '#f59e0b';
          clsName = 'class-tag class-medium';
        } else if (data.classification === 'LOW RISK') {
          color = '#3b82f6';
          clsName = 'class-tag class-low';
        }

        scoreDisplay.style.color = color;
        classDisplay.className = clsName;
        classDisplay.innerText = data.classification;

        if (data.warnings && data.warnings.length > 0) {
          warningsList.innerHTML = data.warnings.map((w, idx) => `
            <div class="finding-item">
              <span class="finding-index">[${idx + 1}]</span>
              <span>${w}</span>
            </div>
          `).join('');
        } else {
          warningsList.innerHTML = `
            <div class="finding-item" style="color: #10b981;">
              <span class="finding-index">[0]</span>
              <span>No listed warning signs found.</span>
            </div>
          `;
        }

        recText.innerText = data.recommendation;
      } catch (err) {
        console.error(err);
        alert('Inspection request failed.');
      }
    }

    // Auto-run benchmark on first load
    window.addEventListener('DOMContentLoaded', performScan);
  </script>
</body>
</html>
"""

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

        # Serve Web UI
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(HTML_TEMPLATE.encode("utf-8"))

    def do_POST(self):
        # Support POST /api/scan with JSON or form
        parsed_url = urlparse(self.path)
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
