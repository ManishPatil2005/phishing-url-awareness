# Contributing to PhishIntel.ai

Thank you for your interest in contributing to the **AI Powered Phishing URL Intelligence Platform**! This project is an open-source educational cybersecurity tool dedicated to deterministic, zero-network threat awareness.

---

## 1. Ground Rules & Invariants
Before submitting code, ensure your contribution strictly respects our core architectural boundaries:
- **Zero Network Invariant:** Never add HTTP network requests, web crawlers, socket connections, or external reputation API lookups.
- **RFC 3986 Compliance:** URL decomposition must remain strictly aligned with RFC 3986 URI specifications.
- **Deterministic Scoring:** The scoring formula must produce predictable, testable, and identical outputs across all environments.
- **Strict TypeScript:** No use of untyped `any` in core services.

---

## 2. Development Workflow

1. **Fork & Clone:**
   ```bash
   git clone https://github.com/ManishPatil2005/phishing-url-awareness.git
   cd phishing-url-awareness
   ```

2. **Install Dependencies:**
   ```bash
   npm install
   ```

3. **Run Development Server:**
   ```bash
   npm run dev
   ```

4. **Run Test Suite:**
   ```bash
   npm test
   python tests/test_runner.py
   ```

---

## 3. Pull Request Guidelines
- Branch naming convention: `feat/feature-name` or `fix/bug-name`.
- Include tests covering new heuristic rules or bug fixes.
- Ensure all 30 tests in `npm test` and the Python CLI test runner pass.
