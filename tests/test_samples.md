# Test Evidence Documentation: Phishing URL Awareness Checker

**Student Name:** Manish Pundlik Patil  
**Internship Candidate ID:** EWB-OL-2026-CYB-0195  
**Course & Batch:** EWB Cybersecurity Mini Project (DEFENSIVE ONLY)  
**Organization:** EWB Edutech Private Limited  
**Python Version:** Python 3.11.9 (64-bit)  
**Operating System:** Microsoft Windows 11 Home Single Language  
**Analysis Protocol:** Static URL Text Analysis (Zero Network Sockets, Purely Local Heuristic)  

---

## 1. Quality Assurance Test Plan Overview

To ensure production-grade reliability, defensive safety, and comprehensive edge-case handling, the **Phishing URL Awareness Checker** was subjected to an extensive **20-test QA evaluation battery**. This test battery verifies:

1. **Workbook Canonical Samples (Tests 1–6):** Exact validation against benchmark targets provided in the EWB project curriculum.
2. **Assignment Specification Canonical Output (Test 7):** Precise alignment with required threat score, risk category, and warnings formatting.
3. **Defensive Input Edge Cases (Tests 8–10):** Empty strings, whitespace padding, and malformed IPv6 bracket inputs designed to trigger unhandled runtime exceptions.
4. **Protocol Scheme Normalization (Test 11):** Bare domains lacking transport schemes (`http://` or `https://`).
5. **Advanced Threat Combinations (Tests 12–18):** Compound attacks combining stacked subdomains, multi-keyword social engineering lures, Cyrillic IDN homograph punycode, and raw IP addresses.
6. **Boundary Condition & Control Testing (Tests 19–20):** Invalid IP octet ranges (>255) and authentic enterprise control domains.

---

## 2. Formal Test Execution Matrix (20 Test Cases)

| Test ID | Input URL Under Test | Category / Test Objective | Expected Finding & Score | Actual Program Output | Verdict |
| :---: | :--- | :--- | :--- | :--- | :---: |
| **TC-01** | `https://www.example.com/` | Legitimate control domain | Safe-looking; 0 warnings | SAFE-LOOKING (0/100) — No warnings | **PASS** |
| **TC-02** | `https://www.example.com/login` | Legitimate HTTPS with sensitive keyword | Suspicious keyword: login (25 pts) | LOW RISK (25/100) — Suspicious keyword: login | **PASS** |
| **TC-03** | `http://192.0.2.10/account` | Workbook Sample 2: IP + HTTP + keyword | HTTP + IP address + keyword: account (75 pts) | HIGH RISK (75/100) — HTTP; IP address; keyword: account | **PASS** |
| **TC-04** | `http://example.com@sample.invalid/login` | Workbook Sample 3: Userinfo @ disguise + HTTP | HTTP + @ symbol + keyword: login (65 pts) | MEDIUM RISK (65/100) — HTTP; @ symbol; keyword: login | **PASS** |
| **TC-05** | `https://a.b.c.d.e.example.invalid/path` | Workbook Sample 4: Excessive subdomains (>=5) | Hostname segments (>=5 parts) (10 pts) | SAFE-LOOKING (10/100) — Excessive hostname segments | **PASS** |
| **TC-06** | `https://xn--example.invalid/` | Workbook Sample 5: Punycode IDN homograph | Punycode hostname (xn--) (20 pts) | SAFE-LOOKING (20/100) — Punycode hostname (xn--) | **PASS** |
| **TC-07** | `http://192.0.2.10/login` | Specification canonical benchmark sample | HTTP + IP + keyword: login (75 pts) | HIGH RISK (75/100) — HTTP; IP address; keyword: login | **PASS** |
| **TC-08** | `""` *(Empty string)* | Input validation: Zero-length entry | Non-crashing notice: "No URL entered." | Notice: No URL entered. | **PASS** |
| **TC-09** | `"   "` *(Whitespace string)* | Input validation: Whitespace string stripping | Non-crashing notice: "No URL entered." | Notice: No URL entered. | **PASS** |
| **TC-10** | `http://[bad` | Exception handling: Malformed IPv6 URI syntax | Intercept ValueError gracefully; no crash | Notice: Malformed URL format (invalid structure). | **PASS** |
| **TC-11** | `www.example.com` | Scheme normalization: Missing protocol | Auto-prepend http://; flag HTTP (15 pts) | SAFE-LOOKING (15/100) — HTTP detected | **PASS** |
| **TC-12** | `https://banking-portal-verification-system.secure.user-credential-check.example.invalid/update` | Complex: Stacked subdomains + 4 keywords | Excessive segments + multiple keywords (40 pts) | LOW RISK (40/100) — Segments; banking, verify, secure, update | **PASS** |
| **TC-13** | `http://198.51.100.25@phish-domain.invalid/free-reward-bonus/verify-password.html?session_token=abcdef12345678901234567890` | Compound multi-vector: HTTP + @ + 5 keywords + length > 100 | HTTP + @ symbol + Length > 100 + 5 keywords (80 pts) | HIGH RISK (80/100) — HTTP; @; Length; 5 keywords | **PASS** |
| **TC-14** | `https://example.com/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` *(115 chars)* | Obfuscation: Excessive string length (>100 chars) | Unusually long URL (10 pts) | SAFE-LOOKING (10/100) — Unusually long URL (>100 chars) | **PASS** |
| **TC-15** | `http://xn--e1afmkfd.example.invalid/account` | Compound: Cyrillic homograph + HTTP + keyword | HTTP + Punycode + keyword: account (60 pts) | MEDIUM RISK (60/100) — HTTP; Punycode; keyword: account | **PASS** |
| **TC-16** | `https://192.168.1.1/` | Raw private network IP over HTTPS | IP address detected (35 pts) | LOW RISK (35/100) — IP address detected | **PASS** |
| **TC-17** | `http://company.com/secure-login` | Unencrypted HTTP + compound keywords | HTTP + keywords: login, secure (45 pts) | MEDIUM RISK (45/100) — HTTP; keywords: login, secure | **PASS** |
| **TC-18** | `https://secure-login.example.invalid` | Brand spoofing keyword in hostname label | Keywords: login, secure (30 pts) | LOW RISK (30/100) — Keywords: login, secure | **PASS** |
| **TC-19** | `http://999.999.999.999/test` | Boundary Check: Octets > 255 (not an IPv4) | Plain HTTP only (15 pts); IP regex rejected | SAFE-LOOKING (15/100) — HTTP detected (IP rejected) | **PASS** |
| **TC-20** | `https://my-legit-bank.example.org/dashboard` | Clean control domain: Standard HTTPS enterprise | Clean URL, zero warning flags (0 pts) | SAFE-LOOKING (0/100) — No warnings | **PASS** |

---

## 3. Deep-Dive Analytical Findings

### 3.1 RFC 3986 Normalization & Protocol Assumptions (TC-11)
Real-world computer users routinely omit the transport scheme when copying or entering URLs (e.g., entering `www.paypal.com` rather than `https://www.paypal.com`). In naive parsers, calling `urllib.parse.urlparse("www.paypal.com")` populates the `.path` field and leaves `.hostname` empty. Prepending `http://` normalizes the candidate structure, enabling correct hostname extraction while accurately flagging unencrypted protocol risks.

### 3.2 Defensive Boundary Parsing & IPv4 Octet Validation (TC-19)
Standard regular expressions such as `(?:\d{1,3}\.){3}\d{1,3}` falsely match invalid IP representations (such as `999.999.999.999`). Our implementation uses strict octet parsing ensuring $0 \le \text{octet} \le 255$. This prevents false-positive security alerts on non-routable hostnames.

### 3.3 Fault-Tolerant Exception Isolation (TC-10)
Standard Python programs crash with unhandled `ValueError` when confronted with malformed IPv6 URI brackets (e.g., `http://[bad`). By implementing robust `try ... except ValueError:` exception containment, the tool gracefully isolates malformed syntax without terminating the session or failing the test pipeline.

### 3.4 Multi-Factor Heuristic Risk Accumulation (TC-13)
Advanced phishing campaigns rarely employ a single deceptive technique. Instead, they compound obfuscation mechanisms:
- Embedding an IP before `@` to spoof user credentials
- Utilizing unencrypted HTTP transport
- Padding paths past 100 characters to truncate mobile URL displays
- Chaining urgent lures (`free`, `reward`, `verify`, `password`)

The calibrated additive risk scoring system accurately reflects this threat escalation, rating TC-13 at **80/100 (HIGH RISK)** with explicit remediation advice.

### 3.5 The Defensive Reality: Absence of Evidence is Not Evidence of Absence
As demonstrated by TC-01 and TC-20, receiving a score of `0/100` and `SAFE-LOOKING` is **never a certificate of absolute security**. Adversaries routinely register genuine domain names with active TLS/SSL certificates (`https://paypa1-update.com`) that possess no syntax anomalies. This program clearly emphasizes its role as an educational awareness companion rather than an absolute binary firewall.
