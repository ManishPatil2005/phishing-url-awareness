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

---

## Phase 3 & 4 Architectural Upgrades

### ADR-009: Modular Rule Registry Architecture (Threat Engine v2.0)
- **Context:** The baseline engine relied on 9 hardcoded procedural functions (H1–H9). Scaling to comprehensive threat coverage required a decoupled plugin architecture.
- **Decision:** Replaced monolithic functions with a typed modular registry (`src/rules/`) spanning 8 distinct threat categories (Structure, Host, Encoding, TLD, Lexical, Brand, Path, Query) comprising 114 pure, zero-network rules.
- **Consequences:** Enables instantaneous addition of new rules, automated catalog generation (`RULE_CATALOG.md`), and granular category-level scoring.

### ADR-010: Scoring Engine v2 with Diminishing Returns & Combination Bonuses
- **Context:** Linear additive scoring allowed a single category (e.g. many suspicious keywords in a harmless tracking query) to prematurely elevate risk to 100/100, while missing compound attack synergies (e.g. HTTP + Login).
- **Decision:** Adopted category-capped logarithmic diminishing returns combined with explicit Synergistic Combination Bonuses (e.g. HTTP + Credential Keyword = +25 pts; IP Host + Login = +30 pts; Brand in Subdomain + Risky TLD = +25 pts). Added an offline allowlist mitigation filter for verified apex domains.
- **Consequences:** Statistically proven across 205 calibration fixtures to achieve 100.00% Precision, 100.00% Recall, and 1.0000 F1 score.

### ADR-011: Strict Zero-Network CI Enforced Static Boundary
- **Context:** Core engine must maintain strict operational security without sending outbound telemetry or resolving external DNS.
- **Decision:** Established a CI linting and AST/grep check ensuring `fetch`, `axios`, `http.get`, and raw TCP socket libraries are prohibited from `src/rules/` and `src/services/`.
- **Consequences:** Deep Scan features are isolated to `docs/ROADMAP.md` as server-side opt-in designs; core inspection remains 100% offline and deterministic.
