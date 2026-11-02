import type { Rule, RuleFinding, ParsedUrlContext } from "./types.ts";

const DYNAMIC_DNS_DOMAINS = [
  "duckdns.org",
  "no-ip.biz",
  "no-ip.org",
  "no-ip.com",
  "ddns.net",
  "zapto.org",
  "hopto.org",
  "ngrok.io",
  "loca.lt",
  "pagekite.me",
  "serveo.net",
];

const FREE_PAAS_DOMAINS = [
  "vercel.app",
  "github.io",
  "firebaseapp.com",
  "web.app",
  "netlify.app",
  "pages.dev",
  "glitch.me",
  "herokuapp.com",
  "surge.sh",
];

const MAJOR_BRAND_NAMES = [
  "google",
  "microsoft",
  "apple",
  "amazon",
  "paypal",
  "netflix",
  "facebook",
  "instagram",
  "whatsapp",
  "chase",
  "bankofamerica",
  "wellsfargo",
  "sbi",
  "hdfc",
  "icici",
  "paytm",
  "binance",
  "coinbase",
  "metamask",
];

export const hostRules: Rule[] = [
  {
    id: "HST-001",
    category: "host",
    name: "Excessive Subdomain Segments (>= 5)",
    description: "Hostname has 5 or more dot-separated subdomain labels.",
    severity: "high",
    weight: 25,
    confidence: 0.90,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const parts = ctx.hostname.split(".");
      if (parts.length >= 5 && !ctx.isAllowlisted) {
        return {
          ruleId: "HST-001",
          ruleCode: "H4-SUBDOMAINS",
          category: "host",
          name: "Excessive Subdomain Segments (>= 5)",
          description: `Deep subdomain structure (${parts.length} segments) detected.`,
          severity: "high",
          weight: 25,
          confidence: 0.90,
          evidence: `Host: ${ctx.hostname} (${parts.length} segments)`,
          matchedString: ctx.hostname,
          whyItMatters: "Deeply nested subdomain chains push the authentic apex registered domain out of view on smaller screens, misleading the user into reading the leftmost subdomain as the site owner.",
          realWorldTechnique: "Attacker registers 'attacker.invalid' and creates 'paypal.com.account.verify.attacker.invalid' to deceive human readers.",
          recommendedAction: "Read domain from right to left before the first slash to identify the actual registrant.",
          references: ["RFC 1034 §3", "APWG Evasion Tactics"],
          tags: ["subdomains", "host", "nesting"],
        };
      }
      return null;
    },
    whyItMatters: "Deep subdomain nesting pushes apex domain out of view.",
    realWorldTechnique: "Hides true registered domain behind long prefix labels.",
    recommendedAction: "Inspect apex domain right before TLD.",
    references: ["RFC 1034"],
    tags: ["subdomains"],
  },
  {
    id: "HST-002",
    category: "host",
    name: "Moderate Subdomain Nesting (3-4 Segments)",
    description: "Hostname has 3 or 4 subdomain labels on non-allowlisted domain.",
    severity: "low",
    weight: 8,
    confidence: 0.75,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const parts = ctx.hostname.split(".");
      if (parts.length >= 4 && parts.length < 5 && !ctx.isAllowlisted) {
        return {
          ruleId: "HST-002",
          ruleCode: "HST-SUBDOM-MOD",
          category: "host",
          name: "Moderate Subdomain Nesting (3-4 Segments)",
          description: `Hostname contains ${parts.length} segments.`,
          severity: "low",
          weight: 8,
          confidence: 0.75,
          evidence: `Segments: ${parts.length}`,
          matchedString: ctx.hostname,
          whyItMatters: "Multiple subdomains can be used to structure phishing tiers or proxy tunnels.",
          realWorldTechnique: "Splits landing infrastructure across multiple dynamic subdomains.",
          recommendedAction: "Verify registered apex domain.",
          references: ["RFC 1034"],
          tags: ["subdomains"],
        };
      }
      return null;
    },
    whyItMatters: "Multiple subdomains may indicate layered redirect infrastructure.",
    realWorldTechnique: "Uses subdomains for ephemeral routing.",
    recommendedAction: "Check apex domain.",
    references: ["RFC 1034"],
    tags: ["subdomains"],
  },
  {
    id: "HST-003",
    category: "host",
    name: "Brand Keyword in Foreign Subdomain",
    description: "A major brand name is embedded as a subdomain on an unrelated domain.",
    severity: "critical",
    weight: 35,
    confidence: 0.96,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const sub = ctx.subdomainString.toLowerCase();
      for (const brand of MAJOR_BRAND_NAMES) {
        if (sub.includes(brand)) {
          return {
            ruleId: "HST-003",
            ruleCode: "HST-BRAND-SUBDOM",
            category: "host",
            name: "Brand Keyword in Foreign Subdomain",
            description: `Brand '${brand}' placed in subdomain on unrelated domain '${ctx.rootDomain}'.`,
            severity: "critical",
            weight: 35,
            confidence: 0.96,
            evidence: `Subdomain: ${sub} | Registered Domain: ${ctx.rootDomain}`,
            matchedString: brand,
            whyItMatters: "Placing a trusted brand in a subdomain on an unrelated registered domain is one of the most common and effective phishing techniques.",
            realWorldTechnique: "Attacker owns 'evil-server.net' and creates 'login.microsoft.com.evil-server.net'.",
            recommendedAction: "Do NOT enter credentials. The site belongs to the apex domain, NOT the brand in the subdomain.",
            references: ["MITRE ATT&CK T1566.002", "APWG Reports"],
            tags: ["brand", "subdomain", "spoofing"],
          };
        }
      }
      return null;
    },
    whyItMatters: "Trusted brand names in foreign subdomains are classic impersonation vectors.",
    realWorldTechnique: "Pretends to be legitimate brand via subdomain while apex domain belongs to attacker.",
    recommendedAction: "Inspect the registered apex domain.",
    references: ["MITRE ATT&CK T1566.002"],
    tags: ["brand", "spoofing"],
  },
  {
    id: "HST-004",
    category: "host",
    name: "Excessive Hyphens in Hostname (>= 3)",
    description: "The hostname contains 3 or more hyphens.",
    severity: "medium",
    weight: 15,
    confidence: 0.88,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const hyphenCount = (ctx.hostname.match(/-/g) || []).length;
      if (hyphenCount >= 3 && !ctx.isAllowlisted) {
        return {
          ruleId: "HST-004",
          ruleCode: "H9-HYPHENS",
          category: "host",
          name: "Excessive Hyphens in Hostname (>= 3)",
          description: `Hostname contains ${hyphenCount} hyphens, indicating artificial keyword stuffing.`,
          severity: "medium",
          weight: 15,
          confidence: 0.88,
          evidence: `Hyphen count: ${hyphenCount} in ${ctx.hostname}`,
          matchedString: "-",
          whyItMatters: "Legitimate corporate domains rarely chain multiple hyphens. Phishers use hyphen-separated brand strings (e.g., 'apple-id-verify-secure-account.com') to create convincing names.",
          realWorldTechnique: "Combosquatting: combining brand names and action words with hyphens.",
          recommendedAction: "Check official company directory for authentic URL structure.",
          references: ["US-CERT Alert on Combosquatting", "RFC 1035 §2.3.1"],
          tags: ["hyphen", "combosquatting", "host"],
        };
      }
      return null;
    },
    whyItMatters: "Multiple hyphens indicate combosquatting or keyword stitching.",
    realWorldTechnique: "Chains brand and security words using hyphens.",
    recommendedAction: "Verify against authentic company domain.",
    references: ["US-CERT Combosquatting Alert"],
    tags: ["hyphens", "combosquatting"],
  },
  {
    id: "HST-005",
    category: "host",
    name: "Suspicious Numeric Sequence in Hostname (>= 4 digits)",
    description: "Hostname contains 4 or more numbers, common in automated phishing domain generation.",
    severity: "medium",
    weight: 15,
    confidence: 0.85,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const match = ctx.hostname.match(/\d{4,}/);
      if (match && !ctx.isAllowlisted) {
        return {
          ruleId: "HST-005",
          ruleCode: "H9-NUMBERS",
          category: "host",
          name: "Suspicious Numeric Sequence in Hostname (>= 4 digits)",
          description: `Detected numeric sequence '${match[0]}' in hostname.`,
          severity: "medium",
          weight: 15,
          confidence: 0.85,
          evidence: `Digit sequence: ${match[0]}`,
          matchedString: match[0],
          whyItMatters: "Automated bulk domain registration toolkits append timestamps, random integer sequences, or campaign IDs to circumvent trademark suspensions.",
          realWorldTechnique: "Automated Domain Generation / Bulk disposable registration (e.g. 'paypal829372.com').",
          recommendedAction: "Exercise high caution when interacting with numbered brand domains.",
          references: ["APWG Global Phishing Survey"],
          tags: ["numeric", "dga", "automation"],
        };
      }
      return null;
    },
    whyItMatters: "Long numbers in domain names correlate strongly with disposable campaign domains.",
    realWorldTechnique: "Appends numbers to brand names for mass registration.",
    recommendedAction: "Confirm domain on company website.",
    references: ["APWG Survey"],
    tags: ["numeric", "automation"],
  },
  {
    id: "HST-006",
    category: "host",
    name: "Excessive Character Repetition (> 2 identical characters)",
    description: "Hostname repeats the same character 3 or more times (excluding 'www').",
    severity: "medium",
    weight: 15,
    confidence: 0.88,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const strippedHost = ctx.hostname.toLowerCase().replace(/^www\./, "");
      const match = strippedHost.match(/([a-zA-Z])\1{2,}/);
      if (match && !ctx.isAllowlisted) {
        return {
          ruleId: "HST-006",
          ruleCode: "H9-REPEATED-CHARS",
          category: "host",
          name: "Excessive Character Repetition (> 2 identical characters)",
          description: `Repeated sequence '${match[0]}' detected in domain.`,
          severity: "medium",
          weight: 15,
          confidence: 0.88,
          evidence: `Sequence: ${match[0]} in ${ctx.hostname}`,
          matchedString: match[0],
          whyItMatters: "Attackers register typosquatting domains with duplicated vowels or consonants (e.g. 'goooogle.com', 'amazzzon.com') banking on typing errors.",
          realWorldTechnique: "Fat-finger typosquatting exploiting user typing slips.",
          recommendedAction: "Verify spelling of the website address carefully.",
          references: ["Typosquatting Detection Standards", "RFC 1035"],
          tags: ["typosquatting", "repetition", "spelling"],
        };
      }
      return null;
    },
    whyItMatters: "Duplicated characters are designed to exploit user typing mistakes.",
    realWorldTechnique: "Registers domains with doubled or tripled letters.",
    recommendedAction: "Check domain spelling closely.",
    references: ["Typosquatting Standards"],
    tags: ["typosquatting"],
  },
  {
    id: "HST-007",
    category: "host",
    name: "Trailing Dot Fully Qualified Domain (FQDN)",
    description: "The hostname ends with a trailing dot (DNS root notation).",
    severity: "low",
    weight: 10,
    confidence: 0.90,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.rawUrl.includes(ctx.hostname + "./") || ctx.hostname.endsWith(".")) {
        return {
          ruleId: "HST-007",
          ruleCode: "HST-TRAILING-DOT",
          category: "host",
          name: "Trailing Dot Fully Qualified Domain (FQDN)",
          description: "Hostname uses trailing dot DNS notation.",
          severity: "low",
          weight: 10,
          confidence: 0.90,
          evidence: `Trailing dot in FQDN: ${ctx.hostname}.`,
          matchedString: ".",
          whyItMatters: "While valid in DNS RFC 1034, a trailing dot can bypass primitive string matching engines, Same-Origin Policy cookie scoping in older browsers, or strict URL filters.",
          realWorldTechnique: "Uses trailing dot to bypass blacklist filters that look for exact domain strings.",
          recommendedAction: "Normalize domain and verify standard browser resolution behavior.",
          references: ["RFC 1034 §3.1", "CWE-185: Incorrect Regular Expression"],
          tags: ["fqdn", "dns", "evasion"],
        };
      }
      return null;
    },
    whyItMatters: "Trailing dot can bypass strict regex string matching while resolving in DNS.",
    realWorldTechnique: "Evades string matching in firewalls.",
    recommendedAction: "Strip trailing dot and evaluate normalized host.",
    references: ["RFC 1034"],
    tags: ["fqdn", "dns"],
  },
  {
    id: "HST-008",
    category: "host",
    name: "Long Domain Label (> 40 characters)",
    description: "A single DNS label between dots exceeds 40 characters.",
    severity: "medium",
    weight: 15,
    confidence: 0.85,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const parts = ctx.hostname.split(".");
      const longLabel = parts.find((p) => p.length > 40);
      if (longLabel && !ctx.isAllowlisted) {
        return {
          ruleId: "HST-008",
          ruleCode: "HST-LABEL-LEN",
          category: "host",
          name: "Long Domain Label (> 40 characters)",
          description: `DNS label '${longLabel.substring(0, 20)}...' has length ${longLabel.length}.`,
          severity: "medium",
          weight: 15,
          confidence: 0.85,
          evidence: `Label length: ${longLabel.length}`,
          matchedString: longLabel,
          whyItMatters: "Standard domain labels are concise for branding. Exceptionally long labels are common in DGA malware domains and complex phishing masks.",
          realWorldTechnique: "DGA algorithms generate lengthy pseudo-random labels.",
          recommendedAction: "Examine domain reputation and source context.",
          references: ["RFC 1035 §2.3.4"],
          tags: ["label-length", "dga", "host"],
        };
      }
      return null;
    },
    whyItMatters: "Excessively long labels are characteristic of DGA or obfuscation.",
    realWorldTechnique: "DGA domain generation.",
    recommendedAction: "Inspect domain structure.",
    references: ["RFC 1035"],
    tags: ["label-length"],
  },
  {
    id: "HST-009",
    category: "host",
    name: "Long Overall Hostname (> 60 characters)",
    description: "Total length of the hostname exceeds 60 characters.",
    severity: "medium",
    weight: 15,
    confidence: 0.85,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.hostname.length > 60 && !ctx.isAllowlisted) {
        return {
          ruleId: "HST-009",
          ruleCode: "HST-TOTAL-LEN",
          category: "host",
          name: "Long Overall Hostname (> 60 characters)",
          description: `Total hostname length is ${ctx.hostname.length} characters.`,
          severity: "medium",
          weight: 15,
          confidence: 0.85,
          evidence: `Host length: ${ctx.hostname.length}`,
          matchedString: ctx.hostname,
          whyItMatters: "Extremely long hostnames are engineered to truncate mobile browser address bars and camouflage the real domain owner.",
          realWorldTechnique: "Address bar spoofing by length extension.",
          recommendedAction: "Verify full hostname before authenticating.",
          references: ["RFC 1035", "OWASP Mobile Security"],
          tags: ["length", "host", "mobile"],
        };
      }
      return null;
    },
    whyItMatters: "Excessively long hostnames truncate address bar viewports.",
    realWorldTechnique: "Conceals apex domain behind mobile browser limits.",
    recommendedAction: "Inspect full hostname.",
    references: ["RFC 1035"],
    tags: ["length"],
  },
  {
    id: "HST-010",
    category: "host",
    name: "Malformed Hyphen at Label Boundary",
    description: "Hostname label begins or ends with a hyphen, violating DNS specifications.",
    severity: "high",
    weight: 25,
    confidence: 0.95,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const parts = ctx.hostname.split(".");
      const badPart = parts.find((p) => p.startsWith("-") || p.endsWith("-"));
      if (badPart) {
        return {
          ruleId: "HST-010",
          ruleCode: "HST-HYPHEN-BOUNDARY",
          category: "host",
          name: "Malformed Hyphen at Label Boundary",
          description: `DNS label '${badPart}' has invalid hyphen placement.`,
          severity: "high",
          weight: 25,
          confidence: 0.95,
          evidence: `Invalid label: ${badPart}`,
          matchedString: badPart,
          whyItMatters: "RFC 1035 explicitly forbids DNS labels starting or ending with hyphens. URLs containing this are either malformed or attempting parser crash exploitation.",
          realWorldTechnique: "Attempts to trigger exceptions in DNS resolution middleboxes.",
          recommendedAction: "Block URL as malformed / RFC violation.",
          references: ["RFC 1035 §2.3.1"],
          tags: ["rfc-violation", "malformed", "dns"],
        };
      }
      return null;
    },
    whyItMatters: "Hyphens at boundaries violate RFC 1035 DNS specifications.",
    realWorldTechnique: "Parser fuzzing and exception generation.",
    recommendedAction: "Reject URL.",
    references: ["RFC 1035"],
    tags: ["rfc-violation"],
  },
  {
    id: "HST-011",
    category: "host",
    name: "Dynamic DNS (DDNS) Service Host",
    description: "Hostname resolves via a free dynamic DNS provider frequently abused in cyber attacks.",
    severity: "high",
    weight: 25,
    confidence: 0.90,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const lower = ctx.hostname.toLowerCase();
      const matched = DYNAMIC_DNS_DOMAINS.find((ddns) => lower.endsWith(ddns));
      if (matched) {
        return {
          ruleId: "HST-011",
          ruleCode: "HST-DDNS",
          category: "host",
          name: "Dynamic DNS (DDNS) Service Host",
          description: `Host resolves through dynamic DNS service '${matched}'.`,
          severity: "high",
          weight: 25,
          confidence: 0.90,
          evidence: `DDNS service: ${matched}`,
          matchedString: matched,
          whyItMatters: "Dynamic DNS providers allow free, anonymous subdomain generation without identity verification. Threat actors heavily exploit DDNS for fast-flux hosting and credential theft.",
          realWorldTechnique: "Attacker maps transient home or compromised bot IP to a DDNS domain for short-lived phishing runs.",
          recommendedAction: "Never enter financial credentials or corporate SSO logins on DDNS domains.",
          references: ["MITRE ATT&CK T1568.002: Dynamic Resolution", "CISA Insights on DDNS Abuse"],
          tags: ["ddns", "fast-flux", "anonymity"],
        };
      }
      return null;
    },
    whyItMatters: "Dynamic DNS is heavily leveraged for ephemeral, unverified phishing campaigns.",
    realWorldTechnique: "Bypasses domain registration costs and KYC checks.",
    recommendedAction: "Do not authenticate on DDNS sites.",
    references: ["MITRE ATT&CK T1568.002"],
    tags: ["ddns"],
  },
  {
    id: "HST-012",
    category: "host",
    name: "Free Cloud PaaS with Credential / Brand Context",
    description: "Hosted on a free developer platform while containing brand or credential lures.",
    severity: "high",
    weight: 30,
    confidence: 0.92,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const lower = ctx.hostname.toLowerCase();
      const matchedPaas = FREE_PAAS_DOMAINS.find((p) => lower.endsWith(p));
      if (matchedPaas) {
        const hasLure =
          ctx.allTokens.some((t) => ["login", "verify", "secure", "signin", "auth", "banking", "sbi", "paypal"].includes(t)) ||
          MAJOR_BRAND_NAMES.some((b) => ctx.subdomainString.toLowerCase().includes(b));

        if (hasLure) {
          return {
            ruleId: "HST-012",
            ruleCode: "HST-FREE-PAAS-LURE",
            category: "host",
            name: "Free Cloud PaaS with Credential / Brand Context",
            description: `Hosting on free developer platform '${matchedPaas}' while presenting authentication or brand keywords.`,
            severity: "high",
            weight: 30,
            confidence: 0.92,
            evidence: `Platform: ${matchedPaas} with lure keywords`,
            matchedString: matchedPaas,
            whyItMatters: "Legitimate enterprise services (e.g. PayPal, Chase, Microsoft) do not host authentication forms on free developer tiers like vercel.app or github.io.",
            realWorldTechnique: "Adversaries abuse free developer tiers to obtain legitimate SSL certificates and cloud IP reputation for phishing forms.",
            recommendedAction: "Block access. Major brands never authenticate customers through free developer hosting subdomains.",
            references: ["APWG Cloud Abuse Phishing Trends", "CISA Advisory"],
            tags: ["paas", "cloud-abuse", "credential-harvesting"],
          };
        }
      }
      return null;
    },
    whyItMatters: "Major brands never authenticate users on free developer subdomains.",
    realWorldTechnique: "Leverages cloud trust and free SSL to host phishing forms.",
    recommendedAction: "Never submit credentials on free PaaS subdomains.",
    references: ["APWG Cloud Abuse"],
    tags: ["paas", "cloud-abuse"],
  },
  {
    id: "HST-013",
    category: "host",
    name: "High Consonant-to-Vowel Ratio (DGA Indicator)",
    description: "Domain label contains an unnatural consonant-vowel ratio characteristic of automated generation.",
    severity: "medium",
    weight: 20,
    confidence: 0.85,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const { rootDomain } = ctx;
      const label = rootDomain.split(".")[0];
      if (label.length >= 8) {
        const vowels = (label.match(/[aeiou]/gi) || []).length;
        const consonants = (label.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
        if (vowels === 0 || consonants / (vowels || 1) >= 6) {
          return {
            ruleId: "HST-013",
            ruleCode: "HST-DGA-CONSONANTS",
            category: "host",
            name: "High Consonant-to-Vowel Ratio (DGA Indicator)",
            description: `Unnatural consonant/vowel distribution in label '${label}'.`,
            severity: "medium",
            weight: 20,
            confidence: 0.85,
            evidence: `Consonant ratio: ${consonants}/${vowels || 1} in '${label}'`,
            matchedString: label,
            whyItMatters: "Human linguistic words feature balanced vowel-consonant alternation. Extreme consonant clustering indicates algorithmic pseudo-random generation.",
            realWorldTechnique: "Domain Generation Algorithms (DGA) generate random strings to evade static domain blacklists.",
            recommendedAction: "Investigate domain age and DNS history.",
            references: ["SANS DGA Detection Heuristics", "MITRE ATT&CK T1568.002"],
            tags: ["dga", "linguistics", "entropy"],
          };
        }
      }
      return null;
    },
    whyItMatters: "Unbalanced consonant-to-vowel ratios indicate algorithmic generation.",
    realWorldTechnique: "DGA domain generation.",
    recommendedAction: "Check DNS records.",
    references: ["SANS DGA"],
    tags: ["dga"],
  },
  {
    id: "HST-014",
    category: "host",
    name: "Port Number Mimicry in Domain String",
    description: "Domain incorporates hyphenated port strings (e.g. '-80', '-443', '-8080') to mimic network authorities.",
    severity: "low",
    weight: 10,
    confidence: 0.80,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (/(?:-|_)(80|443|8080|8443)(?:\.|$)/.test(ctx.hostname) && !ctx.isAllowlisted) {
        return {
          ruleId: "HST-014",
          ruleCode: "HST-PORT-MIMIC",
          category: "host",
          name: "Port Number Mimicry in Domain String",
          description: "Domain name simulates port notation to deceive user analysis.",
          severity: "low",
          weight: 10,
          confidence: 0.80,
          evidence: `Host: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "Attackers construct hostnames that mimic networking syntax to look technical and authentic to inexperienced users.",
          realWorldTechnique: "Social engineering camouflage.",
          recommendedAction: "Evaluate apex domain ownership.",
          references: ["APWG"],
          tags: ["mimicry", "deception"],
        };
      }
      return null;
    },
    whyItMatters: "Simulating port numbers in domain strings is an evasion camouflage technique.",
    realWorldTechnique: "Social engineering camouflage.",
    recommendedAction: "Verify registered domain.",
    references: ["APWG"],
    tags: ["mimicry"],
  },
  {
    id: "HST-015",
    category: "host",
    name: "TLD Extension Masquerade in Subdomain",
    description: "A top-level domain suffix (like '.com', '.org', '.net') is embedded inside a subdomain or hyphenated string.",
    severity: "high",
    weight: 25,
    confidence: 0.94,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const lower = ctx.hostname.toLowerCase();
      if (ctx.isAllowlisted) return null;
      if (/(?:^|\.)[a-z0-9-]+(?:-|\.)(com|org|net|gov|edu)(?:-|\.)/i.test(lower)) {
        return {
          ruleId: "HST-015",
          ruleCode: "HST-TLD-MASQ",
          category: "host",
          name: "TLD Extension Masquerade in Subdomain",
          description: "Contains '.com-' or '.com.' inside host label to masquerade as an apex domain.",
          severity: "high",
          weight: 25,
          confidence: 0.94,
          evidence: `Host pattern in: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "Users are conditioned to look for '.com'. Attackers create domains like 'paypal.com-verify.account-update.net' where the '.com' is just part of a subdomain or hyphenated label.",
          realWorldTechnique: "Visual spoofing of TLD delimiters.",
          recommendedAction: "Notice that the REAL domain extension is the last one at the end of the host string.",
          references: ["US-CERT Alert on Combosquatting", "MITRE ATT&CK T1566.002"],
          tags: ["tld-spoofing", "visual-spoofing", "combosquatting"],
        };
      }
      return null;
    },
    whyItMatters: "Simulating TLDs inside subdomains tricks users into thinking they are on the official site.",
    realWorldTechnique: "Visual spoofing using fake '.com' prefixes.",
    recommendedAction: "Identify the authentic apex TLD at the end of the hostname.",
    references: ["MITRE ATT&CK T1566.002"],
    tags: ["tld-spoofing"],
  },
];
