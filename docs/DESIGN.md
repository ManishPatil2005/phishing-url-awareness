# UI/UX Design System Specification: SOC Dashboard

**Project Name:** AI Powered Phishing URL Intelligence Platform  
**Document Version:** 2.0.0  
**Author:** Lead UI/UX SOC Designer (`AGENT-05`)  
**Contributors:** Senior Full-Stack Engineer (`AGENT-04`)  
**Status:** Approved for Production  

---

## 1. Why: The Design Philosophy
Traditional phishing educational tools often resemble toy scripts or plain web forms. In high-stakes enterprise cybersecurity, Security Operations Center (SOC) dashboards must project authority, situational awareness, and high-density readability. This design system bridges educational clarity with an authentic cybersecurity SOC visual aesthetic inspired by CrowdStrike, Cloudflare Radar, and Darktrace.

---

## 2. What: Visual Tokens & Palette Specifications

| Token Name | Hex Code | Purpose & Semantic Role |
| :--- | :--- | :--- |
| **Background Dark** | `#020617` (Slate 950) | Deep obsidian canvas; reduces eye fatigue in low-light environments. |
| **Card Surface** | `#0F172A` (Slate 900) | Elevated interactive containers, toolbars, and inspection cards. |
| **Border Neutral** | `#1E293B` (Slate 800) | Subtle container separators and input borders. |
| **Primary Accent** | `#3B82F6` (Blue 500) | Brand primary, action buttons, active tab indicators, focus rings. |
| **Success (Safe)** | `#22C55E` (Green 500) | Safe-looking status, passing test badges, zero-threat indicators. |
| **Warning (Medium)** | `#F59E0B` (Amber 500) | Moderate risk, suspicious keywords, excessive segment flags. |
| **Danger (High Risk)** | `#EF4444` (Red 500) | Critical threat score, IP-based URLs, @ credential disguise. |
| **Text Primary** | `#F8FAFC` (Slate 50) | High-contrast body text and prominent headers. |
| **Text Muted** | `#94A3B8` (Slate 400) | Secondary metadata, explanations, and placeholder labels. |

---

## 3. How: Typography & Component Standards

### Typography
- **Primary Interface Font:** `Inter` / `Plus Jakarta Sans` for titles, navigation, and body copy.
- **Code & Token Font:** `JetBrains Mono` / `Consolas` for URL breakdown segments, query params, regex patterns, and terminal outputs.

### Key Visual Components
1. **The Tactical HUD Header:** Displays system health, local heuristic engine state, active rule count, and zero-egress security indicators.
2. **The Command URL Input Bar:** Monospace input with keyboard shortcut integration (`Enter` to inspect, `Esc` to clear), preset pill chips, and real-time status badges.
3. **The Circular Risk Threat Meter:** Color-shifting SVG circular progress ring indicating current score (0–100) with dynamic glow effects.
4. **The Component Breakdown Matrix:** Interactive grid displaying Scheme, Subdomain, Root Domain, Hostname, Path, Query Parameters, and TLD.
5. **Threat Intelligence Cards:** Expandable cards with indicator severity badges, 'Why It Matters', 'Real-World Phishing Technique', and 'Recommended Action'.
6. **Executive Report Modal / Panel:** Instant export to JSON, TXT, or one-click clipboard copy.
7. **Local Analysis History Drawer:** Real-time table of past evaluations stored in `localStorage` with clear and export capabilities.

---

## 4. Accessibility & Responsive Breakpoints

- **WCAG 2.1 AA Compliance:** Minimum 4.5:1 text-to-background contrast ratio on all interactive controls.
- **Keyboard Navigation:** Full tab order throughout the application, complete with visible focus rings (`ring-2 ring-blue-500`).
- **Responsive Layouts:**
  - *Mobile (< 640px):* Single-column vertical stack with full-width action buttons.
  - *Tablet (640px – 1024px):* 2-column metric cards and scrollable breakdown tables.
  - *Desktop (> 1024px):* High-density 3-column SOC layout with side-by-side threat intelligence and history panels.
