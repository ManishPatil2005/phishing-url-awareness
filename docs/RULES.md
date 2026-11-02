# Engineering Rules, Coding Invariants & Operational Standards

**Project Name:** AI Powered Phishing URL Intelligence Platform  
**Document Version:** 2.0.0  
**Author:** Senior Technical Writer (`AGENT-08`)  
**Contributors:** Principal Cybersecurity Architect (`AGENT-01`)  
**Status:** Mandatory Standard  

---

## 1. Core Engineering Rules

1. **The Zero-Network Law:** Under no circumstance may any code introduce network requests, API calls to threat feeds, or socket connections to analyze URLs.
2. **Deterministic Analysis:** The risk score and warnings for any URL string must be identical across local dev, automated CI tests, and production Vercel builds.
3. **No Uncaught Exceptions:** Every parsing operation must be wrapped in safe boundaries. Malformed inputs must yield informative notices, never unhandled errors.
4. **Strict TypeScript Types:** No use of `any` in core analysis services. All data structures must be strictly typed and validated with Zod.
5. **No Secret Keys in Git:** No API keys, passwords, or tokens in source code or commits.
6. **Accessibility Standard:** All user-facing components must meet WCAG 2.1 AA standards and support full keyboard navigation.
7. **Educational Integrity:** The application must never present a score of zero as proof of safety. The disclaimer "Absence of warning signs does not guarantee safety" is required.
