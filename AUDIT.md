# Architectural & Threat Heuristic Audit (Phase 0)
**Project**: PhishIntel.ai (Phishing URL Awareness & Threat Intelligence Platform)  
**Evaluation Target**: Heuristic Engine v1.0 (`src/services/analyzer.ts`, `phishing_checker.py`)  
**Auditor**: Principal Security Engineer & Staff Full-Stack Architect  
**Standard**: RFC 3986, RFC 3987, OWASP Top 10, MITRE ATT&CK T1566 (Phishing)  
**Defensive Invariant**: Zero-Network Local Inspection (Zero Socket / No External I/O)

---

## 1. Executive Summary

PhishIntel.ai currently provides deterministic, offline, text-only URL threat scoring across both a TypeScript/Next.js 15 App Router platform and a Python 3 CLI. The engine executes zero external network connections, preserving complete operational security (OPSEC) and adhering to strict academic and corporate safety boundaries.

However, the baseline engine (Heuristics H1–H9) exhibits critical structural and algorithmic limitations:
1. **Monolithic Architecture**: Rules are hardcoded in imperative procedural logic rather than modular, typed, composable data-driven plugins.
2. **Branding & Positioning Inconsistency**: Marketed under "AI Powered" branding while operating on pure deterministic heuristics; README historically referenced "Python CLI tool" alongside a full-stack Next.js SOC interface.
3. **Lexical Substring False Positives**: Keyword detection (`includes()`) creates false positives on legitimate compound words (e.g., `update` matching in `updated-news.com`, or `secure` in `biosecure.org`).
4. **Sub-optimal Scheme & Combo Weighting**: Plain HTTP scores only 15 points in isolation, failing to reflect severe credential exposure risk when combined with login forms or raw IP destinations.
5. **Lack of Legitimate Domain Exemption**: Well-known domains (e.g., `google.com`, `accounts.google.com`) can accumulate spurious risk points without an allowlist-aware registered domain resolver.

---

## 2. In-Depth Audit of Current Heuristics (H1 – H9)

| Rule Code | Heuristic Name | Current Weight | Trigger Condition | False Positive (FP) Risk | False Negative (FN) Risk | Remediation Strategy |
| :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| **H1** | Plain HTTP Protocol | +15 | `scheme === 'http:'` | **Medium**: Legacy internal intranets, local dev (`localhost`), non-sensitive static mirrors. | **Low**: Modern phishing campaigns increasingly deploy valid free Let's Encrypt TLS certificates. | Retain as structure finding; escalate weight dynamically via **Combination Bonus** when coupled with credential keywords or raw IP hosts. |
| **H2** | Strict IPv4 Host | +35 | Dotted-quad IPv4 regex `\d{1,3}(\.\d{1,3}){3}` | **Low**: Legitimate internal dashboards or RFC 5737 test documentation. | **High**: Obfuscated IP formats (hex `0x7f000001`, octal `0177.0.0.1`, dword integers `2130706433`), IPv6 literals (`[2001:db8::1]`). | Implement comprehensive IP representation detector for hex, octal, dword, and IPv6 bracketed literals in `structure.ts`. |
| **H3** | Userinfo Authentication `@` | +25 | `@` character present before host delimiter | **Very Low**: Extremely rare in benign modern web browsing. | **Low**: Percent-encoded `@` (`%40`) or double percent-encoded `@` (`%2540`) evading basic string checks. | Decode percent-encoding prior to structural analysis; flag both raw and encoded userinfo credentials. |
| **H4** | Excessive Host Subdomains | +10 | Hostname segments $\ge 5$ | **Medium**: Legitimate multi-tenant cloud platforms (`a.b.c.corp.service.internal`). | **Medium**: Short URLs using 1–2 subdomains hosting compromised third-party forms. | Separate public suffix (PSL) from registrant domain; count subdomains relative to effective TLD (eTLD+1). |
| **H5** | Punycode / IDN Homoglyph | +20 | Host contains `xn--` prefix | **Medium**: Benign internationalized domain names (e.g., German, Chinese, Arabic legitimate sites). | **High**: Cyrillic/Greek homoglyphs disguised without Punycode conversion or mixed-script ASCII injection. | Introduce confusable detection, mixed-script anomaly analysis, and invisible character / zero-width detection. |
| **H6** | Excessive URL Length | +10 | Total string length $> 100$ characters | **High**: Deep enterprise links, tracking UTM queries, REST URLs with UUIDs (e.g., `claude.ai/chat/<uuid>`). | **Low**: Shortened URLs (`bit.ly`) concealing destination length entirely. | Partition length scoring between Host length ($>40$ chars) and Path/Query length; ignore benign UUID and query parameters on clean domains. |
| **H7** | Suspicious Keywords | 25 base (+5/extra) | Substring search against 10–13 phishing tokens | **High**: Substring collision on words like `updated`, `secured`, `freefall`, `accountability`. | **Medium**: Leetspeak (`p@ssw0rd`, `l0gin`) or alternative multilingual tokens (`connexion`, `iniciar`). | **Mandatory boundary-aware token matching** (`\b` or hyphen/dot delimiter segmentation); add multilingual and financial token categories. |
| **H8** | Brand Typosquatting | +30 | Pattern search (`g00gle`, `micr0soft`, `paypaI`) | **Low**: Highly targeted phishing technique. | **High**: Only matches 4 predefined hardcoded variants. Misses thousands of known targeted brands and banks. | Expand to 100+ top financial, cloud, and Indian banking brands (SBI, HDFC, ICICI, PayTM) with normalized Levenshtein distance $\le 2$. |
| **H9** | Domain Anomalies | +15 | Hyphens $\ge 3$, Digits $\ge 4$, Repeated chars $> 2$ | **Medium**: Legitimate hyphens in corporate services; three 'w's in `www` (was previously triggering without strip). | **Medium**: Stealth DGA (Domain Generation Algorithm) strings with normal hyphen/digit counts. | Calculate Shannon entropy and consonant-vowel alternation ratio to detect algorithmic domain generation. |

---

## 3. Parser Edge Cases & RFC Conformance Gaps

```
                         PARSER ANOMALY MATRIX
+-----------------------+--------------------+-----------------------------+
| Raw Input Vector      | Standard Parser    | Vulnerability / Edge Case   |
+-----------------------+--------------------+-----------------------------+
| http://[bad-ipv6/path | WHATWG URL (crash) | Malformed bracket crashes   |
| http://127.0.0.1.nip.io| Detected as IP?   | Host is domain, not raw IP  |
| http://0x7F.1/login   | Missed by IPv4?    | Hex-encoded loopback bypass |
| https://paypaI.com    | Lowercase bypass?  | Latin 'I' vs lower 'l' homoglyph |
| https://google.com%23@evil.com | Delimiter | Parser confusion (%23 is #) |
| http://example.com:80/| Port anomaly       | Default port in explicit URL|
| https://bank.com/..\evil | Path traversal  | Mobile browser bar truncation|
+-----------------------+--------------------+-----------------------------+
```

1. **IPv6 Literal Handling**: WHATWG `URL` constructor throws a fatal `TypeError` on unclosed brackets (`http://[bad-ipv6`). Must be caught by defensive pre-parsing regex wrappers.
2. **Mixed-Case Homoglyphs**: Visual confusion between uppercase `I` (capital i) and lowercase `l` (L). A lowercase transformation (`"paypaI".toLowerCase()`) yields `"paypai"`, which avoids naive string comparisons unless homoglyph transliteration is executed.
3. **Trailing FQDN Dots**: `https://www.google.com./` is valid in DNS (fully qualified domain name) but breaks naive string splitters and comparison logic.
4. **Percent-Encoding Bypass**: Malicious URLs frequently encode suspicious tokens (`%6c%6f%67%69%6e` for `login`). The engine must decode normalized UTF-8 tokens before lexical evaluation.
5. **Userinfo Delimiter Ambiguity**: Browsers prioritize `@` for basic authentication (`http://target.com@attacker.com`), directing the victim to `attacker.com`. If percent-encoded as `%40`, some parsers fail to isolate the authentic destination host.

---

## 4. Architectural & Positioning Inconsistencies

1. **"AI Powered" vs. Deterministic Rule Engine**:
   - *Current State*: UI headers and metadata promote "AI Powered Phishing URL Intelligence Platform".
   - *Security Audit Finding*: Misleading to enterprise SOC teams and recruiters. The engine is a deterministic, rule-based heuristic platform.
   - *Resolution*: Transparently define the system as **"Heuristic & Intelligence Engine v2.0"** (Rule-Based Expert System with Statistical Calibration).
2. **README / Stack Discrepancy**:
   - *Current State*: Legacy README sections describe a standalone Python CLI script.
   - *Security Audit Finding*: Fails to showcase the dual architecture (Python 3 CLI + Next.js 15 App Router production SaaS).
   - *Resolution*: Harmonize documentation to reflect the dual-engine parity: TypeScript core for web + Python core for CLI/QA.
3. **HTTP Severity Underestimation**:
   - Plain HTTP (+15) with an unencrypted credential form is rated as "Low Risk" (15/100).
   - In modern web standards, submitting passwords or tokens over unencrypted HTTP is an immediate High Risk event.
   - *Resolution*: Implement Combination Bonuses: `HTTP + Credential Keyword = +30 Bonus Points`.

---

## 5. Token-Boundary Keyword Matching vs. Substring Collisions

### The Substring Defect:
```typescript
// VULNERABLE IMPLEMENTATION (v1.0):
SUSPICIOUS_KEYWORDS.filter(kw => url.toLowerCase().includes(kw))
// "https://news.example.com/updated-policy" -> triggers "update" (+25 pts) FALSE POSITIVE!
// "https://biosecure-research.org" -> triggers "secure" (+25 pts) FALSE POSITIVE!
```

### The Remediation (v2.0 Boundary-Aware Tokenizer):
1. Split URL host, path, and query into discrete tokens using non-alphanumeric delimiters (`/`, `.`, `-`, `_`, `?`, `=`, `&`, `#`).
2. Match keywords against discrete tokens, OR require regex boundaries: `(?:^|[^a-z0-9])(keyword)(?:$|[^a-z0-9])`.
3. Distinguish keyword risk based on location:
   - Keyword in Hostname/Subdomain: **High Severity** (e.g., `login.evil.com`).
   - Keyword in Path: **Medium Severity** (e.g., `evil.com/login`).
   - Keyword on Verified Allowlisted Domain: **Informational / Exempt** (e.g., `accounts.google.com/login`).

---

## 6. Target Architecture for Engine v2.0

```
┌─────────────────────────────────────────────────────────────────┐
│                    URL Input Pre-processor                      │
│        (Sanitize, RFC 3986 Decompose, Percent Decode, PSL)      │
└────────────────────────────────┬────────────────────────────────┘
                                 │
     ┌───────────────────────────┴───────────────────────────┐
     ▼                                                       ▼
┌───────────────────────────┐               ┌───────────────────────────┐
│  Allowlist Verification   │               │   Modular Rule Registry   │
│  (Google, MS, Apple, etc.)│               │     (80–120 Pure Rules)   │
└────────────┬──────────────┘               └─────────────┬─────────────┘
             │                                            │
             │           ┌────────────────────────────────┘
             ▼           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Scoring Engine v2.0                          │
│   - Category Diminishing Returns (Logarithmic Ceiling)          │
│   - Synergistic Combination Bonuses (e.g. IP + Login)           │
│   - Allowlist Mitigation Offsets                                │
└────────────────────────────────┬────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│            Comprehensive Threat Report & Breakdown              │
│  (0-100 Score, 4 Tiers, Defanged URI, Exact Evidence Substrings)│
└─────────────────────────────────────────────────────────────────┘
```

**Approved for Implementation**: Proceeding to Phase 1 (Modular Rule Registry) and Phase 2 (Rule Implementation).
