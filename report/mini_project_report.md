# MINI PROJECT REPORT

## PROJECT TITLE:
# DESIGN AND IMPLEMENTATION OF A STATIC HEURISTIC PHISHING URL AWARENESS AND RISK SCORING ENGINE

---

**Submitted by:**  
**Candidate Name:** Manish Pundlik Patil  
**Candidate ID:** EWB-OL-2026-CYB-0195  
**Discipline:** Cybersecurity Engineering Internship  
**Host Organization:** EWB Edutech Private Limited  
**Academic / Internship Year:** 2026  

---

## ABSTRACT

In modern enterprise and consumer computing environments, social engineering via phishing remains the paramount initial attack vector responsible for severe data breaches, identity theft, and financial loss. Deceptive Uniform Resource Locators (URLs) serve as the primary conduit for routing unsuspecting victims to malicious credential-harvesting interfaces. While dynamic scanning and reputation databases offer robust threat detection, they necessitate active network connections, expose user queries to third parties, and introduce computational latency. 

This project presents the design, mathematical calibration, implementation, and empirical validation of the **Phishing URL Awareness Checker**—a deterministic, high-performance static analysis tool developed in Python 3.10+. Operating strictly without network sockets, external APIs, or website visits, the software decomposes incoming URL strings pursuant to RFC 3986 and analyzes them across seven distinct syntactic threat vectors: protocol transport encryption, userinfo `@` obfuscation, dotted IPv4 decimal addressing, excessive subdomain segmentation, Internationalized Domain Name (IDN) homoglyph punycode prefixes (`xn--`), length-based viewport manipulation, and high-frequency social engineering lexical tokens. An additive, multi-tier risk scoring engine (0–100) maps observed vulnerabilities to standardized risk classifications (`Safe-looking`, `Low Risk`, `Medium Risk`, `High Risk`) and issues targeted defensive recommendations. The engine was validated across an exhaustive 20-case test matrix, achieving 100% test pass fidelity across legitimate, compound attack, and malformed inputs. This work serves as an indispensable educational and defensive foundation for understanding link-based threat mechanics.

---

## 1. INTRODUCTION

The rapid digitization of critical infrastructure, personal banking, and corporate collaboration platforms has exponentially increased the threat surface exploited by cyber adversaries. Phishing attacks, characterized by the masquerading of malicious entities as legitimate organizations, exploit human cognitive vulnerabilities rather than software zero-days.

The anatomy of a URL represents a critical communication boundary between user intent and remote server connectivity. Cybercriminals routinely manipulate URL syntax to deceive users into believing they are interacting with a legitimate destination. Key deceptive mechanisms include:
- Visual masking through long URLs that push the actual destination domain beyond the visible boundaries of mobile and desktop address bars.
- Userinfo misuse, where the `@` character tricks users into misidentifying authentication parameters as trusted domain names.
- Domain spoofing via raw numerical IP addresses, bypassing brand-centric domain reputation systems.
- Deep subdomain nesting, creating fabricated authority paths that visually simulate corporate hierarchies.
- IDN homograph attacks, where Cyrillic or Greek characters mimic Latin counterparts at the visual level while resolving to distinct network endpoints via Punycode (`xn--`).

Traditional endpoint security solutions often rely heavily on cloud-based threat intelligence lookups (e.g., Google Safe Browsing, VirusTotal). While highly effective against known malicious infrastructure, they suffer from significant limitations:
1. **Network Dependency:** Cannot operate in air-gapped, offline, or resource-constrained environments.
2. **Privacy Exposure:** Transmitting unvetted user browsing URLs to external services leaks private tokens and browsing telemetry.
3. **Zero-Day Evasion:** Newly registered domains (NRDs) and adversary-in-the-middle (AitM) infrastructure frequently evade reputation blacklists during the critical initial attack window.

The **Phishing URL Awareness Checker** bridges this gap by providing an instant, deterministic, and 100% offline heuristic assessment mechanism that educates end users and assists defensive triage without generating a single packet of network traffic.

---

## 2. OBJECTIVES

The core engineering and research objectives of this project are:
1. **Develop a Zero-Network Static Analyzer:** Create an ultra-lightweight, offline URL text inspection utility in Python 3 using solely standard library modules (`re`, `urllib.parse`, `sys`, `typing`).
2. **Implement Core Structural Heuristic Checks:** Engineer robust algorithmic detection for six foundational syntactic indicators:
   - Plaintext HTTP protocol usage.
   - Userinfo `@` symbol exploitation.
   - IPv4 address hostnames with strict octet validation ($0 \le \text{octet} \le 255$).
   - Excessive subdomain segmentation ($\ge 5$ distinct labels).
   - Punycode internationalization markers (`xn--`).
   - Obfuscated URL length (>100 characters).
3. **Integrate Social Engineering Keyword Detection:** Expand threat detection capabilities through lexical scanning of ten high-risk credential-harvesting tokens (`login`, `verify`, `secure`, `account`, `banking`, `password`, `reward`, `free`, `bonus`, `update`).
4. **Design a Calibrated Risk Scoring System:** Formulate a weighted additive scoring model (0–100) paired with a four-tier classification taxonomy (`Safe-looking`, `Low Risk`, `Medium Risk`, `High Risk`).
5. **Ensure Defensive Fault Tolerance:** Shield the application from unexpected crashes when handling malformed URI syntax (such as unclosed IPv6 brackets) or empty input strings.
6. **Provide Rigorous Empirical Verification:** Formulate an automated 20-case test suite verifying edge cases, boundary parameters, and compound multi-vector attacks.

---

## 3. METHODOLOGY

The project methodology follows an iterative, defensive software engineering life cycle adhering strictly to RFC 3986 (Uniform Resource Identifier: Generic Syntax).

```
+-------------------------------------------------------------+
|                      User Raw Input                         |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|              Phase 1: Input Preprocessing                   |
|  - Whitespace trimming (strip())                            |
|  - Zero-length boundary validation                          |
|  - Scheme normalization (Auto-prefix http:// if missing)    |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|              Phase 2: Syntactic Decomposition               |
|  - Exception-shielded urlparse() invocation                 |
|  - Hostname isolation and case normalization (.lower())     |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|              Phase 3: Parallel Heuristic Pipeline           |
|  [H1] Scheme Check: Is protocol == 'http'? (+15 pts)        |
|  [H2] Host Type: Dotted IPv4 octet match? (+35 pts)         |
|  [H3] Credential Token: '@' present in authority? (+25 pts) |
|  [H4] Segmentation: Host labels count >= 5? (+10 pts)       |
|  [H5] Homograph: 'xn--' present in hostname? (+20 pts)      |
|  [H6] Obfuscation: Length of raw URL > 100? (+10 pts)       |
|  [H7] Lexical: Presence of sensitive keywords? (25-30 pts)  |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|              Phase 4: Risk Scoring & Classification         |
|  - Score accumulation: S = sum(w_i), clamped to [0, 100]    |
|  - Category Mapping: Safe, Low, Medium, High Risk           |
|  - Contextual defensive recommendation generation           |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|              Phase 5: Output Presentation                   |
|  - Formatted terminal report generation                     |
+-------------------------------------------------------------+
```

### Risk Calculation Model
Let $W = \{w_{\text{HTTP}}, w_{\text{IP}}, w_{@}, w_{\text{SEG}}, w_{\text{PUNY}}, w_{\text{LEN}}, w_{\text{KW}}\}$ represent the set of heuristic penalty weights. The aggregate risk score $S$ is computed as:

$$S = \min\left(100, \sum_{i=1}^{n} w_i \cdot \mathbb{I}_i\right)$$

Where $\mathbb{I}_i \in \{0, 1\}$ is an indicator function denoting whether heuristic check $i$ evaluated to true.

The risk classifications are strictly bounded:
- **$0 \le S \le 20$:** `Safe-looking`
- **$21 \le S \le 40$:** `Low Risk`
- **$41 \le S \le 70$:** `Medium Risk`
- **$71 \le S \le 100$:** `High Risk`

---

## 4. IMPLEMENTATION DETAILS

The implementation is encapsulated within a modular Python script (`phishing_checker.py`), cleanly partitioned into five functional components:

### 4.1 Normalization and Boundary Sanitization
Real-world users often copy URLs without the leading scheme (e.g., `www.example.com`). Calling `urlparse` on a schemeless string causes the standard library to misinterpret the domain as a file path, leaving `parsed.hostname` null. Function `clean_and_normalize_url()` automatically prepends `http://` when `"://"` is absent, guaranteeing deterministic parsing.

### 4.2 Strict IPv4 Octet Validation
A frequent vulnerability in naive regex-based URL analyzers is using unbounded digit matching such as `r"(?:\d{1,3}\.){3}\d{1,3}"`. This matches non-routable strings like `999.999.999.999`. The `is_valid_ipv4()` function couples regular expression capture with numerical range checking:
```python
def is_valid_ipv4(host: str) -> bool:
    pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    match = re.fullmatch(pattern, host)
    if not match:
        return False
    return all(0 <= int(octet) <= 255 for octet in match.groups())
```

### 4.3 Defensive Parsing & Exception Containment
Malformed URLs containing unclosed brackets—such as `http://[bad`—raise unhandled `ValueError` exceptions within Python's `urllib.parse` module. By wrapping the parsing logic inside a structured `try ... except ValueError` block, the tool prevents runtime crashes, converting syntax anomalies into structured error messages.

### 4.4 Social Engineering Lexical Analyzer
The lexical analysis sub-engine searches the lower-cased candidate URL for ten high-confidence credential harvest keywords:
```python
SUSPICIOUS_KEYWORDS = (
    "login", "verify", "secure", "account", "banking",
    "password", "reward", "free", "bonus", "update"
)
```
The first identified keyword contributes 25 points to the threat index, while additional keywords incrementally add 5 points up to an upper ceiling of 30 points, preventing single-category score saturation.

---

## 5. TESTING AND QUALITY ASSURANCE

The system was evaluated against a rigorous 20-case test matrix covering all typical URL structures, advanced multi-vector attacks, and adverse edge cases.

### Summary Test Results Table

| ID | Test Target | Category | Expected Output | Actual Findings & Score | Status |
|:---:|:---|:---|:---|:---|:---:|
| 01 | `https://www.example.com/` | Clean Control | Safe-looking; 0 warnings | SAFE-LOOKING (0/100) — No warnings | PASS |
| 02 | `https://www.example.com/login` | Keyword Test | Flag keyword: login | LOW RISK (25/100) — Keyword: login | PASS |
| 03 | `http://192.0.2.10/account` | Workbook Benchmark 2 | HTTP + IP + account | HIGH RISK (75/100) — HTTP; IP; account | PASS |
| 04 | `http://example.com@sample.invalid/login` | Workbook Benchmark 3 | HTTP + @ + login | MEDIUM RISK (65/100) — HTTP; @; login | PASS |
| 05 | `https://a.b.c.d.e.example.invalid/path` | Workbook Benchmark 4 | Hostname segments ($\ge 5$) | SAFE-LOOKING (10/100) — Hostname segments | PASS |
| 06 | `https://xn--example.invalid/` | Workbook Benchmark 5 | Punycode marker (xn--) | SAFE-LOOKING (20/100) — Punycode (xn--) | PASS |
| 07 | `http://192.0.2.10/login` | Specification Target | HTTP + IP + login | HIGH RISK (75/100) — HTTP; IP; login | PASS |
| 08 | `""` *(Empty string)* | Input Validation | Error Notice | Notice: No URL entered. | PASS |
| 09 | `"   "` *(Whitespace)* | Whitespace Handling | Error Notice | Notice: No URL entered. | PASS |
| 10 | `http://[bad` | Exception Handling | Error Notice | Notice: Malformed URL format. | PASS |
| 11 | `www.example.com` | Normalization | Flag HTTP | SAFE-LOOKING (15/100) — HTTP detected | PASS |
| 12 | `https://banking-portal-verification-system.secure...` | Multi-keyword/Subdomains | Multiple warnings | LOW RISK (40/100) — Segments + 4 keywords | PASS |
| 13 | `http://198.51.100.25@phish-domain.invalid/...` | Compound Vector | High Risk ($>70$) | HIGH RISK (80/100) — HTTP; @; Length; Keywords | PASS |
| 14 | `https://example.com/a...` (115 chars) | Length Obfuscation | Flag Length | SAFE-LOOKING (10/100) — Long URL (>100) | PASS |
| 15 | `http://xn--e1afmkfd.example.invalid/account` | Punycode + HTTP + kw | Medium Risk | MEDIUM RISK (60/100) — HTTP; Punycode; account | PASS |
| 16 | `https://192.168.1.1/` | Raw IP over HTTPS | Flag IP | LOW RISK (35/100) — IP address detected | PASS |
| 17 | `http://company.com/secure-login` | HTTP + 2 keywords | Medium Risk | MEDIUM RISK (45/100) — HTTP; secure, login | PASS |
| 18 | `https://secure-login.example.invalid` | Subdomain Keywords | Low Risk | LOW RISK (30/100) — Keywords: secure, login | PASS |
| 19 | `http://999.999.999.999/test` | Non-routable Octets | HTTP only (IP rejected) | SAFE-LOOKING (15/100) — HTTP detected | PASS |
| 20 | `https://my-legit-bank.example.org/dashboard` | Legitimate Enterprise | Safe-looking | SAFE-LOOKING (0/100) — No warnings | PASS |

---

## 6. RESULTS AND DISCUSSION

The empirical test results demonstrate that the static heuristic engine delivers immediate, zero-latency detection across the most common social engineering vectors. 

### Key Findings:
1. **Multi-Factor Compound Escalation:** When an attacker stacks multiple obfuscation tactics (as in Test 13 with unencrypted HTTP, `@` userinfo spoofing, URL length exceeding 100 characters, and five urgent keywords), the additive scoring engine dynamically escalates the threat level to 80/100 (`HIGH RISK`).
2. **Defensive Awareness Limitation:** A crucial outcome highlighted by Test 01 and Test 20 is the principle of non-negative invariance. A result of `0/100 - SAFE-LOOKING` does **not** guarantee a website is benevolent. Attackers can register authentic domain names with valid SSL/TLS certificates that exhibit zero syntactic anomalies. Consequently, the tool's explicit recommendation banner ensures users never equate an absence of warnings with absolute security.

---

## 7. CONCLUSION

The **Phishing URL Awareness Checker** successfully fulfills all technical, educational, and safety requirements specified by the EWB Edutech internship program. By eliminating network socket calls, the software guarantees zero data exposure, prevents accidental malware detonation, and operates instantaneously in any standard Python environment. The inclusion of defensive exception shielding, strict IPv4 octet validation, social engineering keyword analysis, and an additive risk scoring system elevates this project to production-grade engineering standards.

---

## 8. FUTURE SCOPE

Prospective enhancements that preserve the zero-network defensive mandate include:
1. **Shannon Entropy Analysis:** Calculating the algorithmic information entropy of hostname strings to identify dynamically generated domains (DGAs) commonly utilized in malware command-and-control infrastructure.
2. **Levenshtein Distance Brand Matching:** Implementing minimum edit-distance algorithms to compare target domain labels against a localized dictionary of the top 500 global commercial brands, detecting subtle typosquatting variants (e.g., `micros0ft.com`).
3. **Generic TLD Risk Weighting:** Incorporating weighted risk modifiers for top-level domains statistically correlated with disposable phishing infrastructure (e.g., `.top`, `.xyz`, `.buzz`).

---

## 9. REFERENCES

1. Berners-Lee, T., Fielding, R., & Masinter, L. (2005). *Uniform Resource Identifier (URI): Generic Syntax*. RFC 3986, Internet Engineering Task Force (IETF).
2. Fette, I., Sadeh, N., & Tomasic, A. (2007). *Learning to Detect Phishing Emails*. Proceedings of the 16th International Conference on World Wide Web (WWW '07), pp. 649–656.
3. Anti-Phishing Working Group (APWG). (2024). *Phishing Activity Trends Report - 4th Quarter 2023 / 1st Quarter 2024*. APWG Global Advisory.
4. Python Software Foundation. (2024). *urllib.parse — Parse URLs into components*. Python 3.12 Documentation. https://docs.python.org/3/library/urllib.parse.html
5. EWB Edutech Private Limited. (2026). *Cybersecurity Mini Project Workbook: Phishing URL Awareness Checker*. Student Project Series.
