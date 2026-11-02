# Architecture Decision Records (ADRs)

**Project Name:** AI Powered Phishing URL Intelligence Platform  
**Document Version:** 2.0.0  
**Author:** Senior Technical Writer (`AGENT-08`)  
**Contributors:** Full Multi-Agent Engineering Group  
**Status:** Approved  

---

## Summary of Decisions

- **ADR-001: Next.js 15 App Router:** Adopted Next.js 15 with React 19 for server/client boundary control, static generation, and seamless Vercel edge deployment.
- **ADR-002: Dual Execution Pipeline (Client + Server Action):** Engine implemented in TypeScript so it runs with zero latency directly in browser memory, with an identical Server Action backup.
- **ADR-003: localStorage for Scan History:** Selected browser localStorage to avoid external database overhead while enabling history viewing, deletion, and export.
- **ADR-004: Additive Calibrated Risk Math:** Adopted weighted additive scoring bounded to 0–100, providing predictable score accumulation across multiple indicators.
- **ADR-005: 13-Keyword Lexical Scope:** Expanded keyword scanning to cover modern financial, cryptocurrency, and identity theft lures.
- **ADR-006: Levenshtein & Regex Typosquatting:** Included pattern matching for known typosquatting substitutions (`g00gle`, `paypaI`, `micr0soft`, `amaz0n`).
- **ADR-007: Modern SOC Theme:** Applied Slate 950/900 palette with high-contrast indicator badges matching enterprise SOC dashboards.
- **ADR-008: Preservation of Python CLI:** Kept Python `phishing_checker.py` and test runner intact to ensure 100% compliance with original internship assignment guidelines.
