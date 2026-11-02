# Enterprise Security Architecture & Threat Model

**Project Name:** AI Powered Phishing URL Intelligence Platform  
**Document Version:** 2.0.0  
**Author:** Principal Cybersecurity Architect (`AGENT-01`)  
**Contributors:** Staff Security Engineer (`AGENT-03`)  
**Status:** Approved for Production  

---

## 1. Why: Security Principles & Defensive Mandate
Security tools must themselves be beyond reproach. A phishing analysis platform must never become an attack vector or introduce vulnerabilities to the host environment. This platform adheres to strict defensive-only computing practices.

---

## 2. What: STRIDE Threat Model & Mitigations

| Threat Category (STRIDE) | Attack Vector Considered | Defensive Mitigation Implemented |
| :--- | :--- | :--- |
| **Spoofing** | Adversary attempts to impersonate legitimate domains via homoglyphs or @ userinfo | Engine flags `xn--` Punycode markers and @ symbols in the authority segment. |
| **Tampering** | Malformed URLs with unclosed brackets (e.g. `http://[bad`) crash the parser | Parser uses structured `try/catch` and Zod validation, preventing crashes. |
| **Repudiation** | User claims analysis report is unverified or modified | Standardized JSON export includes UTC timestamps and complete heuristic state hashes. |
| **Information Disclosure** | Private or internal URLs leaked to external services | **Zero Network Requests.** All processing occurs in local memory. |
| **Denial of Service (DoS)** | ReDoS attack with exponential regular expression backtracking | All regular expressions are bounded (linear $O(n)$) without nested quantifiers. |
| **Elevation of Privilege** | Malicious script payloads injected via URL strings | Complete absence of `dangerouslySetInnerHTML`; text rendered via React DOM sanitization. |

---

## 3. How: The Seven Security Invariants

1. **INVARIANT 1: Zero Outbound Sockets.** The application must never invoke `fetch()`, `XMLHttpRequest`, `WebSocket`, or WebRTC to communicate with analyzed targets.
2. **INVARIANT 2: No Browser Automation or Rendering.** The platform must never launch headless browsers or render iframes pointing to analyzed URLs.
3. **INVARIANT 3: Client-Side Input Sanitization.** Input strings are trimmed, length-bounded (maximum 4,096 characters), and sanitized against XSS.
4. **INVARIANT 4: Safe Content Security Policy (CSP).** Strict CSP headers block inline eval, unauthorized scripts, and outside connections.
5. **INVARIANT 5: Zero Local Database Dependency.** No SQLite, PostgreSQL, or remote databases required. History stays on the user's machine via `localStorage`.
6. **INVARIANT 6: Cryptographic Transparency.** The mathematical scoring formula is deterministic, fully visible, and reproducible.
7. **INVARIANT 7: Safe Educational Framing.** Output reports explicitly state: "No listed warning signs found does NOT prove safety."
