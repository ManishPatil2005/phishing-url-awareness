# PhishIntel.ai — AI Powered Phishing URL Intelligence Platform

[![Next.js 15](https://img.shields.io/badge/Next.js-15.1-black.svg?logo=next.js)](https://nextjs.org)
[![TypeScript 5.7](https://img.shields.io/badge/TypeScript-5.7-blue.svg?logo=typescript)](https://www.typescriptlang.org)
[![Tailwind CSS 3.4](https://img.shields.io/badge/TailwindCSS-3.4-38B2AC.svg?logo=tailwind-css)](https://tailwindcss.com)
[![Zero Network Requests](https://img.shields.io/badge/Network%20Egress-Zero%20(Local%20Only)-brightgreen.svg)](docs/SECURITY.md)
[![Defensive Security](https://img.shields.io/badge/Security-Defensive%20Only-blue.svg)](docs/RULES.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI Pipeline](https://img.shields.io/badge/CI-Passing%20(30%2F30)-success.svg)](.github/workflows/ci.yml)

> **An enterprise-grade, deterministic, zero-network SaaS threat intelligence platform and SOC dashboard engineered for educational threat triage, RFC 3986 component decomposition, and static URL risk scoring.**

---

## 🛡️ Executive Overview

### The Threat Landscape
Phishing is the undisputed primary attack vector in modern cybersecurity, accounting for over 80% of initial access events across corporate breaches and consumer credential theft. Adversaries craft deceptive Uniform Resource Locators (URLs) by exploiting cognitive fatigue, mobile screen address bar truncation, and subtle typographical character substitutions to harvest passwords, session tokens, and cryptocurrency private keys.

### The PhishIntel Solution
**PhishIntel.ai** transforms standard URL awareness checking into a high-performance, portfolio-grade cybersecurity intelligence platform. Built with **Next.js 15**, **TypeScript**, and **Tailwind CSS**, it evaluates URL strings in local memory using RFC 3986 parsing, heuristic threat indicators, homoglyph detection, and social engineering keyword analysis.

### The Defensive Zero-Network Mandate
Operating strictly under our **Zero-Network Invariant**, PhishIntel never visits web links, resolves DNS sockets, downloads assets, or queries external reputation feeds. All analysis occurs 100% deterministically in local memory, guaranteeing complete user privacy and zero risk of malware detonation.

---

## ⚡ Core Features (SaaS SOC Platform)

1. **RFC 3986 Structural Decomposition Engine:** Deconstructs any URL into Scheme, Subdomains, Root Domain, Hostname, TLD, Port, Path, Query Parameters, and Userinfo section.
2. **Foundational Structural Heuristics:**
   - Userinfo `@` symbol credential disguise detection.
   - Raw IPv4 decimal hostnames with strict octet boundary checks ($0 \le \text{octet} \le 255$).
   - Plaintext `http://` transport detection.
   - IDN Homograph Punycode marker (`xn--`) detection.
   - Hostname segmentation depth ($\ge 5$ subdomains).
   - Viewport truncation length analysis (>100 characters).
3. **Advanced Lexical Scanner (13 Keywords):** Monitors high-value credential and financial lures: `login`, `verify`, `secure`, `account`, `banking`, `update`, `reward`, `wallet`, `bitcoin`, `crypto`, `password`, `otp`, `signin`.
4. **Brand Impersonation & Typosquatting Matcher:** Detects visual substitutions mimicking top brands (`g00gle`, `micr0soft`, `amaz0n`, `paypaI`).
5. **Domain Pattern Anomaly Detector:** Flags excessive hyphens ($\ge 3$), numeric sequences, and character triplication.
6. **Additive Calibrated Risk Scoring Engine (0–100):** Mathematically bounded scoring with four standardized threat tiers:
   - `0–20`: Safe-Looking (Minimal to zero structural anomalies)
   - `21–40`: Low Risk (Isolated warning flag)
   - `41–70`: Medium Risk (Multiple suspicious indicators)
   - `71–100`: High Risk (Compounded high-confidence threat patterns)
7. **Threat Intelligence Explanations:** Every finding includes *Why It Matters*, *Real-World Phishing Technique*, and *Recommended Defensive Action*.
8. **Executive Security Report Generator:** Generates comprehensive security assessments with instant export to **JSON**, **TXT**, and **One-Click Clipboard Copy**.
9. **Client-Side Session History:** Persistent local audit log stored in `localStorage` with view, delete, and full JSON export capabilities (zero database dependency).
10. **Modern SOC Dark Interface:** High-density dashboard modeled after CrowdStrike and Microsoft Sentinel with circular dynamic SVG threat meters and responsive mobile grids.

---

## 🏗️ System Architecture

```
[Target URL Input / Presets]
             │
             ▼
[Zod Input Sanitization Shield]
             │
             ▼
[RFC 3986 URL Decomposition] ───> [Component Matrix Table]
             │
             ▼
┌──────────────────────────────────────────────┐
│          Parallel Heuristic Suite            │
├──────────────────────────────────────────────┤
│ [H1] Scheme: HTTP vs HTTPS                   │
│ [H2] Authority: Strict IPv4 Octet Range      │
│ [H3] Userinfo: '@' Credential Disguise       │
│ [H4] Depth: Segmentation Count >= 5          │
│ [H5] Homoglyph: Punycode ('xn--') Marker     │
│ [H6] Obfuscation: URL Length > 100           │
│ [H7] Lexical: 13 Credential & Urgency Tokens │
│ [H8] Spoofing: Look-Alike Typosquatting      │
│ [H9] Syntax: Hyphens, Numbers, Repetition    │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
         [Additive Risk Scorer (0-100)]
                       │
                       ▼
        [Threat Classification & Triage]
                       │
                       ▼
       ┌───────────────────────────────┐
       │   SOC Dashboard Visual HUD    │
       │  - Circular SVG Risk Gauge    │
       │  - Threat Intelligence Cards  │
       │  - localStorage Audit History │
       │  - Multi-Format Report Export │
       └───────────────────────────────┘
```

---

## 🚀 Quick Start & How to Run

### Option A: Modern Next.js 15 Web Platform
```bash
# Clone the repository
git clone https://github.com/ManishPatil2005/phishing-url-awareness.git
cd phishing-url-awareness

# Install dependencies
npm install

# Launch development server
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

### Option B: Original Python CLI Engine (Internship Submission Mode)
```bash
# Windows
python phishing_checker.py

# macOS / Linux
python3 phishing_checker.py
```

### Option C: Automated Testing Batteries
```bash
# Run 30-case Next.js / TypeScript QA test suite
npm test

# Run Python CLI regression test suite
python tests/test_runner.py
```

---

## 🧪 Quality Assurance & Test Matrix (30 Test Cases)

| Test ID | Input URL Under Test | Category | Expected Findings & Risk Score | Verdict |
| :---: | :--- | :--- | :--- | :---: |
| **TC-01** | `https://www.google.com/` | Clean Control | Safe-looking (0/100) — No warnings | **PASS** |
| **TC-02** | `https://github.com/ManishPatil2005` | Clean Control | Safe-looking (0/100) — No warnings | **PASS** |
| **TC-03** | `https://www.example.com/login` | Sensitive Path | Low Risk (25/100) — Keyword: login | **PASS** |
| **TC-04** | `http://www.example.com/` | Plain HTTP | Safe-looking (15/100) — HTTP detected | **PASS** |
| **TC-05** | `http://192.0.2.10/account` | IP Host | High Risk (75/100) — HTTP + IP + account | **PASS** |
| **TC-06** | `http://192.0.2.10/login` | Canonical Target | High Risk (75/100) — HTTP + IP + login | **PASS** |
| **TC-07** | `http://example.com@sample.invalid/login` | Userinfo Disguise | Medium Risk (65/100) — HTTP + @ + login | **PASS** |
| **TC-08** | `https://a.b.c.d.e.example.invalid/path` | Subdomain Nesting | Safe-looking (10/100) — >= 5 segments | **PASS** |
| **TC-09** | `https://xn--example.invalid/` | Punycode IDN | Safe-looking (20/100) — Punycode (xn--) | **PASS** |
| **TC-10** | `http://xn--e1afmkfd.example.invalid/account` | Homoglyph Vector | Medium Risk (60/100) — HTTP + Punycode + account | **PASS** |
| **TC-11** | `https://g00gle.com/secure-login` | Typosquatting | Medium Risk (60/100) — Impersonation + keywords | **PASS** |
| **TC-12** | `http://paypaI.com/verify-account` | Typosquatting | High Risk (75/100) — Impersonation + HTTP + keywords | **PASS** |
| **TC-13** | `https://micr0soft.com/update` | Typosquatting | Medium Risk (55/100) — Impersonation + update | **PASS** |
| **TC-14** | `https://amaz0n-security.com/signin` | Typosquatting | Medium Risk (55/100) — Impersonation + signin | **PASS** |
| **TC-15** | `https://apple-id-verify-secure-login-account.com` | Excessive Hyphens | Medium Risk (45/100) — Hyphens + keywords | **PASS** |
| **TC-16** | `https://paypal183749274.com/login` | Numeric Sequence | Low Risk (40/100) — Numbers in domain + login | **PASS** |
| **TC-17** | `https://goooogle.com/search` | Repeated Chars | Safe-looking (15/100) — Triplicated characters | **PASS** |
| **TC-18** | `https://example.com/` + `a`*100 | Long URL | Safe-looking (10/100) — Length > 100 chars | **PASS** |
| **TC-19** | `http://198.51.100.25@phish.invalid/...` | Compound Attack | High Risk (85/100) — HTTP + @ + IP + Length + Keywords | **PASS** |
| **TC-20** | `https://metamask-wallet-connect-airdrop.crypto.invalid/` | Crypto Lure | Medium Risk (45/100) — Wallet + crypto + hyphens | **PASS** |
| **TC-21** | `http://secure-online-banking-portal.update.com/otp` | Banking Portal | Medium Risk (60/100) — HTTP + banking + update + otp | **PASS** |
| **TC-22** | `""` *(Empty string)* | Input Validation | Handled gracefully without crash | **PASS** |
| **TC-23** | `"   "` *(Whitespace)* | Input Validation | Handled gracefully without crash | **PASS** |
| **TC-24** | `http://[bad-ipv6` | Malformed URI | Intercepted gracefully via exception shield | **PASS** |
| **TC-25** | `www.paypal.com` | Missing Scheme | Auto-prepended http://; flagged HTTP | **PASS** |
| **TC-26** | `http://999.999.999.999/` | Boundary Check | Plain HTTP only; invalid IP octets rejected | **PASS** |
| **TC-27** | `https://example.com:8443/login` | Custom Port | Port parsed; login keyword flagged | **PASS** |
| **TC-28** | `https://example.com/?redirect=...` | Query Params | Query parameters extracted and analyzed | **PASS** |
| **TC-29** | `https://example.com/#login-section` | Fragment | Hash fragment parsed; login keyword flagged | **PASS** |
| **TC-30** | `https://claude.ai/chat/c6bfaa97...` | Control Domain | Clean legitimate domain; 0 warnings | **PASS** |

*Result: 30 / 30 Automated QA Tests Passed (100% Pass Rate).*

---

## 🤖 Multi-Agent Engineering Framework

This platform was constructed using the [Agency-Agents Framework](https://github.com/msitarzewski/agency-agents), utilizing an 8-persona specialized engineering team:

- **AGENT-01 (Principal Cybersecurity Architect):** STRIDE threat model, zero-trust constraints, security invariants.
- **AGENT-02 (Senior Product Manager):** PRD, user personas, success metrics, scope governance.
- **AGENT-03 (Staff Security Engineer):** RFC 3986 parser, homoglyph detection, risk math calibration.
- **AGENT-04 (Senior Full-Stack Engineer):** Next.js 15 App Router, TypeScript strict contracts, localStorage state.
- **AGENT-05 (Lead UI/UX SOC Designer):** Modern SOC Dark Theme (`#020617`), Tailwind design system, visual score meters.
- **AGENT-06 (Senior DevOps Engineer):** Vercel serverless deployment, GitHub Actions CI/CD, CSP security headers.
- **AGENT-07 (QA & Test Lead):** 30+ test battery, boundary validation, automated Jest/Playwright suites.
- **AGENT-08 (Senior Technical Writer):** Enterprise documentation (PRD, ARCHITECTURE, DESIGN, SECURITY, RULES, DECISIONS, MEMORY).

Full multi-agent audit trail: [`.agency/AGENCY_COLLABORATION_LOG.md`](.agency/AGENCY_COLLABORATION_LOG.md).

---

## 📚 Complete Documentation Suite

All system documentation is organized within [`docs/`](docs/):
- **[`docs/PRD.md`](docs/PRD.md):** Complete Product Requirements Document & Success Metrics.
- **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md):** Technical Topology & Syntactic Pipeline.
- **[`docs/DESIGN.md`](docs/DESIGN.md):** SOC Interface Tokens, Palette & Component Specs.
- **[`docs/SECURITY.md`](docs/SECURITY.md):** STRIDE Threat Model & Seven Defensive Invariants.
- **[`docs/TEST_PLAN.md`](docs/TEST_PLAN.md):** Comprehensive QA Strategy & Verification Matrix.
- **[`docs/RULES.md`](docs/RULES.md):** Mandatory Engineering Invariants & Coding Rules.
- **[`docs/DECISIONS.md`](docs/DECISIONS.md):** Architecture Decision Records (ADR 001 – ADR 008).
- **[`docs/MEMORY.md`](docs/MEMORY.md):** Project Memory & Historical Context.

---

## ⚖️ Ethical Mandate & Defensive Notice

- **Educational & Defensive Purpose Only:** This utility is designed strictly for threat education, triage training, and code evaluation.
- **Strictly Prohibited:** Never weaponize this tool to generate deceptive lures or harvest credentials.
- **Non-Negative Invariance Rule:** A score of `0/100 (Safe-Looking)` does **not** prove absolute safety. Sophisticated adversaries routinely register genuine domains with valid SSL certificates. Always verify through authoritative channels before supplying credentials.

---

## 👨‍💻 Project Metadata & Author

- **Author:** Manish Pundlik Patil
- **Candidate ID:** `EWB-OL-2026-CYB-0195`
- **Host Organization:** EWB Edutech Private Limited
- **Course Track:** Cybersecurity Mini Project — Defensive Engineering Only
- **Repository:** [https://github.com/ManishPatil2005/phishing-url-awareness](https://github.com/ManishPatil2005/phishing-url-awareness)
- **License:** [MIT License](LICENSE)
