import type { Rule, RuleFinding, ParsedUrlContext } from "./types.ts";

export const structureRules: Rule[] = [
  {
    id: "STR-001",
    category: "structure",
    name: "Plain HTTP Scheme (Unencrypted)",
    description: "The URL uses plaintext unencrypted HTTP instead of modern TLS/HTTPS.",
    severity: "medium",
    weight: 15,
    confidence: 0.95,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.scheme.toLowerCase() === "http:") {
        return {
          ruleId: "STR-001",
          ruleCode: "H1-HTTP",
          category: "structure",
          name: "Plain HTTP Scheme (Unencrypted)",
          description: "Transmission is unencrypted, exposing user data to intercept or tampering.",
          severity: "medium",
          weight: 15,
          confidence: 0.95,
          evidence: `Scheme: ${ctx.scheme}`,
          matchedString: ctx.scheme,
          whyItMatters: "Plaintext HTTP exposes user sessions, passwords, and tokens to network eavesdropping and adversary-in-the-middle attacks.",
          realWorldTechnique: "Adversaries host quick-drop phishing landing pages on non-SSL servers or use unencrypted tunnels to harvest credentials.",
          recommendedAction: "Never submit credentials or personal information over HTTP. Verify HTTPS encryption.",
          references: ["RFC 2616", "OWASP Transport Layer Protection Cheat Sheet"],
          tags: ["scheme", "http", "cleartext", "transport-security"],
        };
      }
      return null;
    },
    whyItMatters: "Plaintext HTTP exposes credentials to network eavesdropping.",
    realWorldTechnique: "Adversaries deploy unencrypted pages for short-lived phishing campaigns.",
    recommendedAction: "Avoid entering sensitive data on unencrypted sites.",
    references: ["RFC 2616", "OWASP A02:2021-Cryptographic Failures"],
    tags: ["scheme", "transport-security"],
  },
  {
    id: "STR-002",
    category: "structure",
    name: "Dotted-Decimal IPv4 Hostname",
    description: "Hostname is represented as a raw dotted-decimal IPv4 address instead of a domain name.",
    severity: "high",
    weight: 35,
    confidence: 0.99,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const parts = ctx.hostname.split(".");
      const isIpv4 =
        parts.length === 4 &&
        parts.every((p) => /^\d{1,3}$/.test(p) && parseInt(p, 10) >= 0 && parseInt(p, 10) <= 255);

      if (isIpv4) {
        return {
          ruleId: "STR-002",
          ruleCode: "H2-IP-HOST",
          category: "structure",
          name: "Dotted-Decimal IPv4 Hostname",
          description: `Direct IPv4 address used as host (${ctx.hostname}) to bypass domain reputation systems.`,
          severity: "high",
          weight: 35,
          confidence: 0.99,
          evidence: `Host: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "Legitimate web services almost universally use human-readable registered domain names with TLS certificates. Direct IP hosts bypass domain takedowns and reputation registries.",
          realWorldTechnique: "MITRE ATT&CK T1566.002: Attackers host landing pages directly on compromised IP addresses or short-lived VPS instances to evade brand domain monitoring.",
          recommendedAction: "Exercise extreme caution. Do not trust login pages hosted on raw IP addresses.",
          references: ["RFC 3986 §3.2.2", "MITRE ATT&CK T1566.002"],
          tags: ["host", "ip-address", "evasion", "t1566"],
        };
      }
      return null;
    },
    whyItMatters: "Direct IP addressing circumvents domain reputation and brand identification.",
    realWorldTechnique: "Attackers deploy phishing portals directly on unmanaged IP VPS hosts.",
    recommendedAction: "Do not enter authentication details on raw IP addresses.",
    references: ["RFC 3986", "MITRE ATT&CK T1566"],
    tags: ["host", "ip-address"],
  },
  {
    id: "STR-003",
    category: "structure",
    name: "Hex-Encoded IP Address Host",
    description: "Hostname is an obfuscated hexadecimal representation of an IP address.",
    severity: "critical",
    weight: 40,
    confidence: 0.95,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const clean = ctx.hostname.toLowerCase();
      if (/^0x[0-9a-f]{8}$/.test(clean) || /^(0x[0-9a-f]{1,2}\.){3}0x[0-9a-f]{1,2}$/.test(clean)) {
        return {
          ruleId: "STR-003",
          ruleCode: "STR-IP-HEX",
          category: "structure",
          name: "Hex-Encoded IP Address Host",
          description: `Obfuscated hexadecimal IP host (${ctx.hostname}) used to bypass simple IP string checks.`,
          severity: "critical",
          weight: 40,
          confidence: 0.95,
          evidence: `Host: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "Browsers normalize hexadecimal representations to IP addresses, but primitive security parsers frequently overlook them.",
          realWorldTechnique: "Hexadecimal encoding allows attackers to bypass keyword and regex filters that only search for standard decimal IP formats.",
          recommendedAction: "Block immediately. Hexadecimal host representations are strongly indicative of malicious evasion.",
          references: ["RFC 3986 §3.2.2", "CWE-116: Improper Encoding or Escaping"],
          tags: ["ip-address", "obfuscation", "evasion"],
        };
      }
      return null;
    },
    whyItMatters: "Hex encoding is an evasion tactic to disguise IP hosts.",
    realWorldTechnique: "Bypasses standard dotted-decimal regex filters.",
    recommendedAction: "Block navigation and flag for security operations review.",
    references: ["RFC 3986", "CWE-116"],
    tags: ["evasion", "obfuscation"],
  },
  {
    id: "STR-004",
    category: "structure",
    name: "Octal-Encoded IP Address Host",
    description: "Hostname utilizes leading-zero octal numbers to disguise an IP address.",
    severity: "critical",
    weight: 40,
    confidence: 0.95,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const parts = ctx.hostname.split(".");
      if (parts.length === 4 && parts.some((p) => p.length > 1 && p.startsWith("0") && /^\d+$/.test(p))) {
        return {
          ruleId: "STR-004",
          ruleCode: "STR-IP-OCTAL",
          category: "structure",
          name: "Octal-Encoded IP Address Host",
          description: `Octal-encoded IP representation detected (${ctx.hostname}).`,
          severity: "critical",
          weight: 40,
          confidence: 0.95,
          evidence: `Host: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "Leading zero notations are parsed by standard POSIX socket libraries as base-8 (octal), shifting the destination address silently.",
          realWorldTechnique: "Used by threat actors to disguise malicious redirect targets and evade static string analysis.",
          recommendedAction: "Do not navigate to octal-encoded hostnames.",
          references: ["RFC 3986", "POSIX.1-2017 inet_addr"],
          tags: ["ip-address", "obfuscation", "evasion"],
        };
      }
      return null;
    },
    whyItMatters: "Octal IP formats deceive casual users and static string filters.",
    realWorldTechnique: "Conceals true server destination using POSIX base-8 parsing quirks.",
    recommendedAction: "Block and investigate link origin.",
    references: ["POSIX inet_addr", "RFC 3986"],
    tags: ["evasion", "octal"],
  },
  {
    id: "STR-005",
    category: "structure",
    name: "Dword (Integer) IP Host",
    description: "Hostname is represented as a single large 32-bit integer (Dword).",
    severity: "critical",
    weight: 40,
    confidence: 0.98,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (/^\d{8,10}$/.test(ctx.hostname)) {
        const val = parseInt(ctx.hostname, 10);
        if (val > 0 && val <= 4294967295) {
          return {
            ruleId: "STR-005",
            ruleCode: "STR-IP-DWORD",
            category: "structure",
            name: "Dword (Integer) IP Host",
            description: `Dword integer IP host detected (${ctx.hostname}).`,
            severity: "critical",
            weight: 40,
            confidence: 0.98,
            evidence: `Host integer: ${ctx.hostname}`,
            matchedString: ctx.hostname,
            whyItMatters: "A 32-bit integer host is resolved directly by operating systems to an IPv4 address while completely bypassing standard domain heuristics.",
            realWorldTechnique: "Exploits URL parser resolution rules where integer numbers represent IPv4 addresses (e.g. 2130706433 translates to 127.0.0.1).",
            recommendedAction: "Treat as high-confidence evasion attempt. Do not interact.",
            references: ["RFC 3986", "OWASP Evasion Techniques"],
            tags: ["ip-address", "dword", "evasion"],
          };
        }
      }
      return null;
    },
    whyItMatters: "Dword IP numbers are standard evasion vectors in phishing campaigns.",
    realWorldTechnique: "Converts dotted-quad IP to a single 32-bit integer.",
    recommendedAction: "Treat with immediate suspicion.",
    references: ["RFC 3986 §3.2.2"],
    tags: ["dword", "ip-address"],
  },
  {
    id: "STR-006",
    category: "structure",
    name: "Bracketed IPv6 Literal Host",
    description: "Hostname contains a bracketed IPv6 address literal.",
    severity: "high",
    weight: 30,
    confidence: 0.95,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.hostname.startsWith("[") && ctx.hostname.endsWith("]")) {
        return {
          ruleId: "STR-006",
          ruleCode: "STR-IP-V6",
          category: "structure",
          name: "Bracketed IPv6 Literal Host",
          description: `Direct IPv6 address host detected (${ctx.hostname}).`,
          severity: "high",
          weight: 30,
          confidence: 0.95,
          evidence: `IPv6 Host: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "Legitimate consumer websites do not share links using raw IPv6 address literals. This is common in unauthorized tunneling or direct bot infrastructure.",
          realWorldTechnique: "Bypasses IPv4-only threat feeds and security middleboxes.",
          recommendedAction: "Validate sender identity before proceeding.",
          references: ["RFC 3986 §3.2.2", "RFC 4291"],
          tags: ["ipv6", "host", "evasion"],
        };
      }
      return null;
    },
    whyItMatters: "Raw IPv6 addresses in consumer URLs usually indicate unauthorized or direct machine communications.",
    realWorldTechnique: "Evades legacy IPv4 threat detection feeds.",
    recommendedAction: "Verify destination legitimacy.",
    references: ["RFC 3986", "RFC 4291"],
    tags: ["ipv6"],
  },
  {
    id: "STR-007",
    category: "structure",
    name: "Private or Loopback IP Range",
    description: "Host targets RFC 1918 private subnets or RFC 5735 loopback/link-local space.",
    severity: "medium",
    weight: 20,
    confidence: 0.90,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const h = ctx.hostname.toLowerCase();
      const isPrivate =
        h === "localhost" ||
        h.startsWith("127.") ||
        h.startsWith("10.") ||
        h.startsWith("192.168.") ||
        /^172\.(1[6-9]|2\d|3[0-1])\./.test(h) ||
        h.startsWith("169.254.");

      if (isPrivate) {
        return {
          ruleId: "STR-007",
          ruleCode: "STR-IP-PRIVATE",
          category: "structure",
          name: "Private or Loopback IP Range",
          description: `Target resolves to local intranet or loopback address (${ctx.hostname}).`,
          severity: "medium",
          weight: 20,
          confidence: 0.90,
          evidence: `Private Host: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "External emails linking to private IP ranges are indicative of Server-Side Request Forgery (SSRF) exploitation or internal network probing.",
          realWorldTechnique: "Used in SSRF attacks to coerce clients or servers into contacting internal administrative control panels.",
          recommendedAction: "Ensure this link was intended for internal diagnostics. Never click from external sources.",
          references: ["RFC 1918", "RFC 5735", "CWE-918: SSRF"],
          tags: ["ssrf", "private-ip", "loopback"],
        };
      }
      return null;
    },
    whyItMatters: "Private IP links in external communications often indicate SSRF or cross-site probing.",
    realWorldTechnique: "Coerces browser into attacking local routers or developer daemons.",
    recommendedAction: "Do not open links pointing to local/private IP addresses from unknown emails.",
    references: ["RFC 1918", "CWE-918"],
    tags: ["ssrf", "rfc1918"],
  },
  {
    id: "STR-008",
    category: "structure",
    name: "Userinfo Authentication Delimiter (@)",
    description: "The '@' symbol is embedded in the URL authority section.",
    severity: "high",
    weight: 25,
    confidence: 0.99,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.hasUserinfo || ctx.rawUrl.includes("@")) {
        return {
          ruleId: "STR-008",
          ruleCode: "H3-USERINFO",
          category: "structure",
          name: "Userinfo Authentication Delimiter (@)",
          description: "URL contains userinfo credentials before '@', disguising the real destination host.",
          severity: "high",
          weight: 25,
          confidence: 0.99,
          evidence: `Userinfo: ${ctx.username || "detected"}@`,
          matchedString: "@",
          whyItMatters: "RFC 3986 specifies that anything before '@' in the authority component represents user authentication details, not the destination host. Browsers ignore this prefix and connect to the host following '@'.",
          realWorldTechnique: "Attacker structures URL like 'http://bank.com@malicious-site.invalid/login'. Casual victims read 'bank.com' and assume it is authentic.",
          recommendedAction: "Inspect the domain AFTER the '@' character. Never enter credentials on sites using '@' disguise.",
          references: ["RFC 3986 §3.2.1", "APWG Phishing Attack Trends"],
          tags: ["userinfo", "authority", "visual-spoofing"],
        };
      }
      return null;
    },
    whyItMatters: "The '@' symbol tricks victims into mistaking the username field for the destination host.",
    realWorldTechnique: "Prefixes trusted brand names before the '@' sign to camouflage attacker domain.",
    recommendedAction: "Always check the domain that appears immediately AFTER the '@' symbol.",
    references: ["RFC 3986 §3.2.1"],
    tags: ["userinfo", "spoofing"],
  },
  {
    id: "STR-009",
    category: "structure",
    name: "Multiple Userinfo (@) Delimiters",
    description: "URL contains two or more '@' symbols in the string.",
    severity: "critical",
    weight: 35,
    confidence: 0.99,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const atCount = (ctx.rawUrl.match(/@/g) || []).length;
      if (atCount >= 2) {
        return {
          ruleId: "STR-009",
          ruleCode: "STR-MULTI-AT",
          category: "structure",
          name: "Multiple Userinfo (@) Delimiters",
          description: `Detected ${atCount} '@' delimiters designed to induce severe parser differential confusion.`,
          severity: "critical",
          weight: 35,
          confidence: 0.99,
          evidence: `Found ${atCount} '@' characters in URL`,
          matchedString: "@",
          whyItMatters: "Multiple '@' characters cause different web proxies, firewalls, and browsers to disagree on what the actual target hostname is.",
          realWorldTechnique: "Parser Differential Exploitation: Middleboxes inspect one component while the victim browser connects to another.",
          recommendedAction: "Immediately reject URL. High-probability active exploit vector.",
          references: ["Black Hat: A New Era of SSRF", "RFC 3986"],
          tags: ["parser-differential", "userinfo", "evasion"],
        };
      }
      return null;
    },
    whyItMatters: "Multiple '@' symbols cause parser discrepancies between firewalls and browsers.",
    realWorldTechnique: "Parser confusion to bypass enterprise security gateways.",
    recommendedAction: "Block immediately.",
    references: ["RFC 3986"],
    tags: ["parser-differential"],
  },
  {
    id: "STR-010",
    category: "structure",
    name: "Non-Standard HTTP/HTTPS Port",
    description: "The URL specifies a custom or non-standard port number.",
    severity: "medium",
    weight: 15,
    confidence: 0.85,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.port && ctx.port !== "80" && ctx.port !== "443") {
        return {
          ruleId: "STR-010",
          ruleCode: "STR-PORT-NONSTD",
          category: "structure",
          name: "Non-Standard HTTP/HTTPS Port",
          description: `Custom port :${ctx.port} is explicitly configured in destination authority.`,
          severity: "medium",
          weight: 15,
          confidence: 0.85,
          evidence: `Port: :${ctx.port}`,
          matchedString: `:${ctx.port}`,
          whyItMatters: "Phishing kits frequently run on auxiliary ports (e.g. 8080, 8443, 8888, 5000) on compromised home routers or development hosts.",
          realWorldTechnique: "Avoids administrative web server roots on shared hosting environments.",
          recommendedAction: "Confirm why standard TLS port 443 is not in use.",
          references: ["IANA Service Name and Port Number Registry"],
          tags: ["port", "custom-port", "infrastructure"],
        };
      }
      return null;
    },
    whyItMatters: "Non-standard ports often indicate ad-hoc, temporary, or compromised hosting environments.",
    realWorldTechnique: "Runs phishing scripts on alternate ports to bypass shared web server configurations.",
    recommendedAction: "Exercise vigilance on non-standard ports.",
    references: ["IANA Port Registry"],
    tags: ["port"],
  },
  {
    id: "STR-011",
    category: "structure",
    name: "Default Port Explicitly Declared",
    description: "The standard port (:80 or :443) is explicitly declared in the URL authority.",
    severity: "info",
    weight: 5,
    confidence: 0.75,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (
        (ctx.scheme === "http:" && ctx.port === "80") ||
        (ctx.scheme === "https:" && ctx.port === "443")
      ) {
        return {
          ruleId: "STR-011",
          ruleCode: "STR-PORT-EXPLICIT",
          category: "structure",
          name: "Default Port Explicitly Declared",
          description: `Default port :${ctx.port} explicitly specified.`,
          severity: "info",
          weight: 5,
          confidence: 0.75,
          evidence: `Port: :${ctx.port}`,
          matchedString: `:${ctx.port}`,
          whyItMatters: "Standard browser links omit default ports. Explicitly declaring them is often an artifact of automated phishing kit generator scripts.",
          realWorldTechnique: "Automated campaign generation tooling hardcodes explicit socket pairs.",
          recommendedAction: "Minor anomaly; evaluate in conjunction with other findings.",
          references: ["RFC 3986 §3.2.3"],
          tags: ["port", "redundant"],
        };
      }
      return null;
    },
    whyItMatters: "Explicit default ports frequently originate from automated generation scripts.",
    realWorldTechnique: "Tooling artifacts in mass phishing frameworks.",
    recommendedAction: "Low severity; check other indicators.",
    references: ["RFC 3986"],
    tags: ["port"],
  },
  {
    id: "STR-012",
    category: "structure",
    name: "High Overall URL Length (> 100 characters)",
    description: "Total character count of the URL exceeds standard benign length thresholds.",
    severity: "low",
    weight: 10,
    confidence: 0.80,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.rawUrl.length > 100 && ctx.rawUrl.length <= 250 && !ctx.isAllowlisted) {
        return {
          ruleId: "STR-012",
          ruleCode: "H6-LENGTH-100",
          category: "structure",
          name: "High Overall URL Length (> 100 characters)",
          description: `URL contains ${ctx.rawUrl.length} characters, exceeding benign threshold.`,
          severity: "low",
          weight: 10,
          confidence: 0.80,
          evidence: `Length: ${ctx.rawUrl.length} chars`,
          matchedString: ctx.rawUrl.substring(0, 40) + "...",
          whyItMatters: "Long URLs push suspicious subdomains or parameters beyond the visible address bar on mobile devices and narrow desktop windows.",
          realWorldTechnique: "Address bar padding: padding the query or path with harmless characters to hide the true payload.",
          recommendedAction: "Examine the full URL structure before clicking.",
          references: ["W3C URI Length Guidance", "MITRE ATT&CK T1566"],
          tags: ["length", "obfuscation", "mobile-truncation"],
        };
      }
      return null;
    },
    whyItMatters: "Excessive length conceals payload components from browser address bars.",
    realWorldTechnique: "Pads URL to hide malicious host behind mobile viewport boundaries.",
    recommendedAction: "Inspect full URL string.",
    references: ["RFC 3986"],
    tags: ["length"],
  },
  {
    id: "STR-013",
    category: "structure",
    name: "Extreme Obfuscated URL Length (> 250 characters)",
    description: "Total character count of the URL exceeds 250 characters.",
    severity: "medium",
    weight: 20,
    confidence: 0.88,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.rawUrl.length > 250 && !ctx.isAllowlisted) {
        return {
          ruleId: "STR-013",
          ruleCode: "STR-LENGTH-EXTREME",
          category: "structure",
          name: "Extreme Obfuscated URL Length (> 250 characters)",
          description: `Extreme URL length of ${ctx.rawUrl.length} characters detected.`,
          severity: "medium",
          weight: 20,
          confidence: 0.88,
          evidence: `Length: ${ctx.rawUrl.length} chars`,
          matchedString: ctx.rawUrl.substring(0, 40) + "...",
          whyItMatters: "URLs exceeding 250 characters frequently embed serialized data payloads, base64 redirection tokens, or aggressive search engine poisoning strings.",
          realWorldTechnique: "Embeds encrypted victim identifiers or entire JavaScript redirect payloads directly in the URL.",
          recommendedAction: "Verify authenticity of the transmission source.",
          references: ["RFC 3986 §3.2.1", "APWG Evasion Taxonomy"],
          tags: ["length", "obfuscation"],
        };
      }
      return null;
    },
    whyItMatters: "Extreme length is often used to embed serialized payloads or base64 tracking tokens.",
    realWorldTechnique: "Encodes entire redirection state in URL query.",
    recommendedAction: "Examine embedded query parameters closely.",
    references: ["RFC 3986"],
    tags: ["length"],
  },
  {
    id: "STR-014",
    category: "structure",
    name: "Backslash Confusion in Authority",
    description: "The URL contains backslashes ('\\') in the authority or scheme separator.",
    severity: "critical",
    weight: 35,
    confidence: 0.98,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.rawUrl.includes("\\")) {
        return {
          ruleId: "STR-014",
          ruleCode: "STR-BACKSLASH",
          category: "structure",
          name: "Backslash Confusion in Authority",
          description: "Backslash ('\\') detected in URL structure, causing parser desynchronization.",
          severity: "critical",
          weight: 35,
          confidence: 0.98,
          evidence: `Backslash found in URL string`,
          matchedString: "\\",
          whyItMatters: "Internet Explorer and Chromium browsers normalize '\\' to '/' while many security inspection gateways, firewalls, and filters do not.",
          realWorldTechnique: "Threat actors craft 'https://legit.com\\@evil.com' which browsers treat as host 'evil.com', while primitive regex filters match 'legit.com'.",
          recommendedAction: "Block URL immediately. Backslash usage in web links is anomalous and strongly malicious.",
          references: ["WHATWG URL Standard §4.2", "CWE-1286: Improper Handling of Syntactic Elements"],
          tags: ["backslash", "parser-confusion", "evasion"],
        };
      }
      return null;
    },
    whyItMatters: "Backslashes induce parser differences between browsers and security filtering proxies.",
    realWorldTechnique: "Exploits WHATWG browser path normalization to camouflage destination domain.",
    recommendedAction: "Reject URL unconditionally.",
    references: ["WHATWG URL Spec", "CWE-1286"],
    tags: ["parser-confusion", "backslash"],
  },
  {
    id: "STR-015",
    category: "structure",
    name: "High Special Character Ratio (> 20%)",
    description: "A high proportion of characters in the URL are non-alphanumeric punctuation marks.",
    severity: "medium",
    weight: 15,
    confidence: 0.85,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.rawUrl.length >= 30 && !ctx.isAllowlisted) {
        const specialCount = (ctx.rawUrl.match(/[^a-zA-Z0-9\/\:\.]/g) || []).length;
        const ratio = specialCount / ctx.rawUrl.length;
        if (ratio > 0.20) {
          return {
            ruleId: "STR-015",
            ruleCode: "STR-SPECIAL-RATIO",
            category: "structure",
            name: "High Special Character Ratio (> 20%)",
            description: `${Math.round(ratio * 100)}% of characters are punctuation or symbols.`,
            severity: "medium",
            weight: 15,
            confidence: 0.85,
            evidence: `Special character ratio: ${(ratio * 100).toFixed(1)}%`,
            matchedString: ctx.rawUrl,
            whyItMatters: "High special character density indicates encoding chaining, excessive query nesting, or delimiter manipulation common in obfuscation toolkits.",
            realWorldTechnique: "Uses complex delimiter sequences to break signature-based intrusion detection filters.",
            recommendedAction: "Inspect URL breakdown and sanitize query components.",
            references: ["OWASP Input Validation", "NIST SP 800-83"],
            tags: ["obfuscation", "lexical"],
          };
        }
      }
      return null;
    },
    whyItMatters: "High symbol density indicates encoding chains or evasion delimiter chaining.",
    realWorldTechnique: "Breaks IDS signature matching with excessive symbols.",
    recommendedAction: "Sanitize and inspect query parameters.",
    references: ["OWASP"],
    tags: ["obfuscation"],
  },
];
