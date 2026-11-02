# Deep Scan Threat Intelligence Architecture & Roadmap
**Document**: `docs/ROADMAP.md`  
**Classification**: Architectural Design Specification (Optional Deep Scan Expansion)  
**Standard**: RFC 3986, RFC 7480 (RDAP), RFC 8484 (DoH), CA/Browser Forum Baseline Requirements  
**Status**: Planned / Isolated Network Module (Core Platform Remains 100% Zero-Network Default)

---

## 1. Architectural Boundary & Security Invariants

> [!IMPORTANT]
> **Strict Operational Boundary**: The primary PhishIntel.ai inspection engine is and will always remain **100% offline, zero-network, and deterministic**.
> Deep Scan capabilities documented below represent an isolated, opt-in enterprise server-side microservice that must NEVER be bundled into client-side packages or invoked without explicit analyst consent.

```
+-------------------------------------------------------------------------+
|                  CORE PLATFORM: ZERO-NETWORK ENGINE                     |
|           (Pure String Decomposition, 104 Modular Rules)                |
+-------------------------------------------------------------------------+
                                     │
                        Explicit User Consent Toggle
                     [ Initiate Deep Reconnaissance ]
                                     │
                                     ▼
+─────────────────────────────────────────────────────────────────────────+
|               ENTERPRISE OPT-IN DEEP SCAN SERVICE (ISOLATED)            |
|                                                                         |
|  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ |
|  │  RDAP / WHOIS│  │  Active DNS  │  │ TLS Cert X509│  │ Safe Browsing│ |
|  │  Domain Age  │  │  TTL / Flux  │  │ Validity Age │  │  Feeds (APWG)│ |
|  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘ |
+─────────────────────────────────────────────────────────────────────────+
```

---

## 2. Module Specifications

### Module 1: WHOIS & RDAP Domain Age Inspection (RFC 7480)
- **Objective**: Identify disposable, newly registered domains (NRDs). Over 70% of active phishing infrastructure is under 72 hours old.
- **Protocol**: Registration Data Access Protocol (RDAP) via JSON REST APIs (e.g. `https://rdap.org/domain/{domain}`).
- **Metrics Collected**:
  - `registrationDate`: ISO 8601 creation timestamp.
  - `domainAgeDays`: Calculated integer days since registration.
  - `registrarName`: Identifying bulletproof registrars known for lack of abuse responsiveness.
  - `privacyGuard`: Presence of domain proxy services masking registrant contact.
- **Scoring Weight**:
  - Age $< 7\text{ days}$: **+35 Points (Critical)**
  - Age $< 30\text{ days}$: **+20 Points (High)**
  - Age $> 365\text{ days}$: **0 Points (Neutral / Low Risk)**

### Module 2: Active DNS TTL & Fast-Flux Resolution
- **Objective**: Detect dynamic evasion networks where IP addresses rapidly cycle to prevent blocking.
- **Protocol**: DNS-over-HTTPS (DoH) querying Cloudflare (`1.1.1.1`) or Quad9 (`9.9.9.9`).
- **Metrics Collected**:
  - `dnsTTL`: Time-To-Live in seconds. Fast-flux networks typically exhibit TTL $< 300\text{ seconds}$.
  - `ipDiversity`: Autonomous System Number (ASN) and geographic distribution of resolved A/AAAA records.
  - `nameserverReputation`: Verification against known bulletproof hosting ASNs.
- **Scoring Weight**:
  - TTL $< 120\text{ seconds}$ across multiple disparate ASNs: **+30 Points (High Risk)**

### Module 3: TLS / X.509 Certificate Profile & Transparency
- **Objective**: Evaluate certificate issuer, validity duration, and Subject Alternative Name (SAN) bloat.
- **Protocol**: In-memory TLS handshake SNI extraction (no payload download).
- **Metrics Collected**:
  - `certIssuer`: Let's Encrypt / ZeroSSL (frequently abused by automated bots) vs. Enterprise Extended Validation (EV).
  - `certAge`: Certificate issue date relative to domain registration date.
  - `sanCount`: Excessive number of unrelated domain names grouped under a single shared free certificate ($> 50$ SANs).
  - `cnMismatch`: Common Name mismatch with target brand.
- **Scoring Weight**:
  - Issued $< 24\text{ hours}$ ago with free CA: **+15 Points (Medium Risk)**
  - CN Mismatch: **+25 Points (High Risk)**

### Module 4: Multi-Feed Threat Reputation Aggregation
- **Objective**: Query distributed reputation consortiums without leaking analyst IP.
- **Feeds Integrated**:
  - Google Safe Browsing API v4
  - APWG (Anti-Phishing Working Group) eCrime Exchange (eCX)
  - PhishTank Community Feed
  - OpenPhish Global Feed
- **Privacy Design**: K-anonymity 32-bit SHA256 prefix hashing to query Google Safe Browsing without revealing the full analyzed URL to Google.

---

## 3. Sandboxed Redirect Following (No Detonation)

```typescript
// Proposed Deep Scan Serverless Worker Contract:
export interface DeepScanRequest {
  url: string;
  maxRedirectHops: number; // default: 5
  timeoutMs: number;       // default: 3000
  enableWhois: boolean;
  enableDns: boolean;
  enableTls: boolean;
}

export interface DeepScanResponse {
  finalResolvedUrl: string;
  redirectChain: Array<{
    statusCode: number;
    sourceUrl: string;
    targetUrl: string;
    latencyMs: number;
  }>;
  whois: {
    domainAgeDays: number;
    registrar: string;
    isNewlyRegistered: boolean;
  };
  dns: {
    aRecords: string[];
    ttl: number;
    isFastFlux: boolean;
  };
  threatFeeds: {
    isFlagged: boolean;
    sources: string[];
  };
}
```

---

## 4. Security Sandbox Guidelines

1. **Strict Content Discard**: Deep Scan workers must only execute HTTP `HEAD` or socket handshakes; response bodies (HTML, JavaScript, binaries) are dropped at the network layer to prevent client detonation or drive-by infection.
2. **Egress Isolation**: Workers execute in disposable container sandboxes on isolated AWS Lambda / Cloudflare Workers networks with no access to internal corporate VPCs.
3. **No Cookies / Zero Session**: Requests send randomized, generic User-Agents (`Mozilla/5.0 DefensiveScanner/2.0`) and never persist cookies or local storage.
