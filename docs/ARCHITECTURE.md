# System Architecture & Technical Specifications

**Project Name:** AI Powered Phishing URL Intelligence Platform  
**Document Version:** 2.0.0  
**Author:** Principal Cybersecurity Architect (`AGENT-01`)  
**Contributors:** Senior Full-Stack Engineer (`AGENT-04`), Staff Security Engineer (`AGENT-03`)  
**Status:** Approved for Production Architecture  

---

## 1. Why: Architectural Philosophy & Invariants

Traditional cybersecurity web applications rely heavily on centralized backend microservices to perform network lookups, query reputation databases, and resolve DNS records. While appropriate for enterprise firewalls, this model fails educational and privacy-sensitive criteria because:
1. It exposes users to drive-by malware risks if links are inadvertently visited.
2. It introduces latency, server hosting costs, and points of failure.
3. It leaks user inputs over the network.

To resolve this, the **AI Powered Phishing URL Intelligence Platform** is built upon the **Local Deterministic Invariant**: *All analysis must be mathematically reproducible, client-safe, and executed entirely within local memory without external network calls.*

---

## 2. What: System Decomposition & Component Topology

```
+-----------------------------------------------------------------------------------------+
|                                    NEXT.JS 15 APP RUNTIME                               |
+-----------------------------------------------------------------------------------------+
│                                                                                         │
│  +---------------------------+   User Input    +-------------------------------------+  │
│  |   SOC Dashboard (React)   | ──────────────> |      Zod Validation Shield          |  │
│  +---------------------------+                 +-------------------------------------+  │
│               ▲                                                   │                     │
│               │ Render State                                      ▼                     │
│  +---------------------------+                 +-------------------------------------+  │
│  | Visual Score Meter & Cards|                 |   RFC 3986 URL Decomposition Engine |  │
│  +---------------------------+                 +-------------------------------------+  │
│               ▲                                                   │                     │
│               │ Analysis Result                                   ▼                     │
│  +-----------------------------------------------------------------------------------+  │
│  |                        Parallel Security Heuristic Pipeline                       |  │
│  |  [Vector 1: Protocol Transport (HTTP vs HTTPS)]                                   |  │
│  |  [Vector 2: Host Authority (Strict IPv4 Octet Range Match 0-255)]                  |  │
│  |  [Vector 3: Userinfo Authentication Disguise (@ symbol)]                          |  │
│  |  [Vector 4: Domain Nesting Depth (Segmentation count >= 5)]                       |  │
│  |  [Vector 5: Homoglyph Punycode Indicator (xn-- check)]                            |  │
│  |  [Vector 6: Viewport Truncation Length (URL length > 100)]                        |  │
│  |  [Vector 7: Social Engineering Lexical Scanner (13 Keywords)]                     |  │
│  |  [Vector 8: Brand Impersonation & Typosquatting (g00gle, paypaI, etc.)]           |  │
│  |  [Vector 9: Domain Pattern Anomalies (Hyphens, Digits, Repeated Chars)]           |  │
│  +-----------------------------------------------------------------------------------+  │
│                                           │                                             │
│                                           ▼                                             │
│  +---------------------------+                 +-------------------------------------+  │
│  | localStorage Persistence  | <────────────── | Calibrated Risk Scoring Engine      |  │
│  | (History & Cache)         |                 | (0-100 Score & 4-Tier Taxonomy)     |  │
│  +---------------------------+                 +-------------------------------------+  │
│                                                                                         │
+-----------------------------------------------------------------------------------------+
```

---

## 3. How: Core Component Implementation Details

### 3.1 Input Validation Shield (`Zod`)
Before parsing, raw input passes through a strict Zod schema that trims whitespace, guards against string lengths beyond 4,096 characters (preventing client-side DoS), and validates that the candidate string can be normalized into a standard URI without throwing uncaught exceptions.

### 3.2 RFC 3986 Syntactic Decomposition Service
```typescript
interface UrlBreakdown {
  rawUrl: string;
  scheme: string;
  subdomain: string;
  rootDomain: string;
  hostname: string;
  tld: string;
  port: string;
  path: string;
  query: string;
  fragment: string;
  hasUserinfo: boolean;
  userinfo: string;
}
```
URLs missing a scheme prefix (e.g., `www.example.com`) are automatically prepended with `http://` for deterministic parsing while explicitly flagging the lack of transport encryption.

### 3.3 Heuristic Analysis Pipeline
The pipeline runs nine specialized evaluation rules against the parsed candidate:
1. **Plaintext Protocol Flag:** Flags unencrypted `http://` transport ($+15$ pts).
2. **Strict IPv4 Hostname Validator:** Checks for dotted-quad numeric hosts where each octet satisfies $0 \le \text{octet} \le 255$ ($+35$ pts).
3. **Userinfo `@` Symbol Matcher:** Checks for `@` characters in the authority section used to obscure the destination host ($+25$ pts).
4. **Subdomain Nesting Depth:** Detects 5 or more dot-separated hostname labels ($+10$ pts).
5. **IDN Homograph Punycode Detector:** Detects `xn--` prefix strings used for character substitution ($+20$ pts).
6. **Viewport Length Obfuscation:** Flags URLs exceeding 100 characters ($+10$ pts).
7. **Lexical Social Engineering Matcher:** Searches for 13 credential and urgency keywords (`login`, `verify`, `secure`, `account`, `banking`, `update`, `reward`, `wallet`, `bitcoin`, `crypto`, `password`, `otp`, `signin`) ($+25$ pts base, $+5$ per extra keyword up to 30 pts max).
8. **Brand Impersonation & Typosquatting:** Matches visual look-alike substitutions such as `g00gle`, `micr0soft`, `amaz0n`, and `paypaI` ($+30$ pts).
9. **Domain Structural Patterns:** Detects excessive hyphens ($\ge 3$), excessive numbers ($\ge 4$ digits in domain), or abnormal character repetition ($+15$ pts).

### 3.4 Mathematical Risk Scoring Formulation
The total risk score $S$ is computed as:
$$S = \min\left(100, \sum_{i=1}^{n} w_i \cdot \mathbb{I}_i\right)$$
Where $w_i$ is the calibrated weight for heuristic rule $i$, and $\mathbb{I}_i \in \{0, 1\}$ is the boolean detection state.

Categorization is mapped as follows:
- $0 \le S \le 20$: **Safe-looking** (Green)
- $21 \le S \le 40$: **Low Risk** (Blue)
- $41 \le S \le 70$: **Medium Risk** (Amber/Yellow)
- $71 \le S \le 100$: **High Risk** (Red)

---

## 4. Architectural Decisions & Trade-offs (ADR Summary)

- **ADR-001: Client-Side vs Server-Side Execution:** Selected client-side TypeScript execution with optional Next.js Server Action fallback. This guarantees zero network latency, offline capability, and prevents Vercel serverless cold-start timeouts.
- **ADR-002: Persistence Mechanism:** Selected browser `localStorage` instead of an external database (PostgreSQL/MongoDB). This ensures the application runs out-of-the-box on local dev machines and Vercel without requiring external database provisioning.
- **ADR-003: Modern SOC Dark Theme:** Designed around deep slate and obsidian tones (`#020617`, `#0F172A`) to match enterprise security dashboards like CrowdStrike Falcon, Splunk, and Microsoft Sentinel.

---

## 5. Security Considerations & Best Practices

1. **Strictly Text-Only Analysis:** No network sockets, DNS resolution, or HTTP client connections are instantiated under any circumstances.
2. **Defense against ReDoS (Regular Expression Denial of Service):** All regex patterns avoid nested repetition operators and unbounded backtracking.
3. **No Dynamic Code Evaluation:** Code strictly prohibits `eval()`, `new Function()`, or unescaped `dangerouslySetInnerHTML`.
4. **Content Security Policy (CSP):** Next.js headers enforce strict script-src and prohibit inline script injections.

---

## 6. Future Architectural Roadmap

- **Wasm Acceleration:** Compile heuristic string evaluators to WebAssembly for batch processing (>10,000 URLs/sec).
- **Shannon Entropy Sub-Engine:** Calculate character entropy scores to detect Algorithmic Domain Generation (DGA) malware signatures.
- **Levenshtein Distance Dictionary:** Expand typosquatting detection with an offline database of the top 1,000 global commercial brands.
