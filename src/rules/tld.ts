import type { Rule, RuleFinding, ParsedUrlContext } from "./types.ts";

const HIGH_ABUSE_TLDS = new Set([
  "top",
  "xyz",
  "click",
  "buzz",
  "racing",
  "work",
  "icu",
  "cam",
  "loan",
  "surf",
  "fit",
  "rest",
  "monster",
  "gq",
  "cf",
  "tk",
  "ml",
  "ga",
]);

const FILE_EXTENSION_TLDS = new Set(["zip", "mov"]);

const CRYPTO_UNOFFICIAL_TLDS = new Set([
  "crypto",
  "eth",
  "wallet",
  "nft",
  "dao",
  "x",
  "polygon",
  "bitcoin",
]);

export const tldRules: Rule[] = [
  {
    id: "TLD-001",
    category: "tld",
    name: "File Extension Top-Level Domain (.zip, .mov)",
    description: "The domain uses a TLD that overlaps with dangerous archive or media file extensions.",
    severity: "high",
    weight: 25,
    confidence: 0.94,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const tldClean = ctx.tld.toLowerCase();
      if (FILE_EXTENSION_TLDS.has(tldClean)) {
        return {
          ruleId: "TLD-001",
          ruleCode: "TLD-FILE-EXT",
          category: "tld",
          name: "File Extension Top-Level Domain (.zip, .mov)",
          description: `Uses '.${ctx.tld}' TLD, which conflates web links with downloadable file archives.`,
          severity: "high",
          weight: 25,
          confidence: 0.94,
          evidence: `TLD: .${ctx.tld}`,
          matchedString: `.${ctx.tld}`,
          whyItMatters: "TLDs like .zip and .mov mimic common file extensions. Attackers send messages referencing 'invoice.zip' which operating systems and chat clients hyperlink as websites rather than local files.",
          realWorldTechnique: "Conflation of filename and URI destination to deliver malware or credential phishing.",
          recommendedAction: "Exercise extreme caution before opening links ending with archive TLD extensions.",
          references: ["US-CERT Alert on .zip TLD Risk", "SANS ISC InfoSec Diary"],
          tags: ["tld", "zip", "file-extension", "malware"],
        };
      }
      return null;
    },
    whyItMatters: ".zip and .mov TLDs conflate file attachments with web links.",
    realWorldTechnique: "Tricks users into navigating to attacker sites thinking they are opening a document.",
    recommendedAction: "Verify if link was intended as a file or website.",
    references: ["US-CERT .zip Alert"],
    tags: ["tld", "file-extension"],
  },
  {
    id: "TLD-002",
    category: "tld",
    name: "Free High-Abuse Freenom TLD (.tk, .ml, .ga, etc.)",
    description: "Domain utilizes a free registration country-code TLD with historically high abuse rates.",
    severity: "high",
    weight: 25,
    confidence: 0.92,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const freeTlds = ["tk", "ml", "ga", "cf", "gq"];
      if (freeTlds.includes(ctx.tld.toLowerCase())) {
        return {
          ruleId: "TLD-002",
          ruleCode: "TLD-FREE-FREENOM",
          category: "tld",
          name: "Free High-Abuse Freenom TLD (.tk, .ml, .ga, etc.)",
          description: `Uses disposable free TLD '.${ctx.tld}'.`,
          severity: "high",
          weight: 25,
          confidence: 0.92,
          evidence: `TLD: .${ctx.tld}`,
          matchedString: `.${ctx.tld}`,
          whyItMatters: "Historically, free domain registrars require no payment or identity verification, making them the preferred infrastructure for throwaway mass phishing campaigns.",
          realWorldTechnique: "Bulk disposable phishing campaigns operated at zero financial cost.",
          recommendedAction: "Avoid submitting credentials or downloading software from free ccTLDs.",
          references: ["APWG Global Phishing Survey", "Spamhaus The World's Most Abused TLDs"],
          tags: ["tld", "freenom", "free-domain"],
        };
      }
      return null;
    },
    whyItMatters: "Free TLDs are heavily abused for anonymous throwaway phishing.",
    realWorldTechnique: "Zero-cost mass domain registration.",
    recommendedAction: "Do not enter credentials.",
    references: ["Spamhaus Most Abused TLDs"],
    tags: ["tld", "freenom"],
  },
  {
    id: "TLD-003",
    category: "tld",
    name: "High-Abuse Generic TLD (.top, .xyz, .click, etc.)",
    description: "Domain is registered under a generic top-level domain frequently cited on threat feeds.",
    severity: "medium",
    weight: 15,
    confidence: 0.85,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (HIGH_ABUSE_TLDS.has(ctx.tld.toLowerCase()) && !ctx.isAllowlisted) {
        return {
          ruleId: "TLD-003",
          ruleCode: "TLD-HIGH-ABUSE",
          category: "tld",
          name: "High-Abuse Generic TLD (.top, .xyz, .click, etc.)",
          description: `Domain uses '.${ctx.tld}', a TLD with high threat-to-legitimate traffic ratio.`,
          severity: "medium",
          weight: 15,
          confidence: 0.85,
          evidence: `TLD: .${ctx.tld}`,
          matchedString: `.${ctx.tld}`,
          whyItMatters: "Low-cost registration promotions (e.g. $0.99 domains) attract high volumes of malicious registrants.",
          realWorldTechnique: "Cost-effective domain cycling for automated campaigns.",
          recommendedAction: "Verify sender legitimacy and domain ownership.",
          references: ["Spamhaus Top 10 Most Abused TLDs"],
          tags: ["tld", "abuse", "gTLD"],
        };
      }
      return null;
    },
    whyItMatters: "Inexpensive TLDs are statistical hotspots for disposable spam and phishing.",
    realWorldTechnique: "Cycles cheap domains to evade domain reputation filters.",
    recommendedAction: "Exercise vigilance on high-abuse TLDs.",
    references: ["Spamhaus"],
    tags: ["tld", "abuse"],
  },
  {
    id: "TLD-004",
    category: "tld",
    name: "Decentralized / Web3 Non-ICANN TLD (.crypto, .eth)",
    description: "Domain uses a blockchain or decentralized TLD not recognized by standard ICANN root servers.",
    severity: "medium",
    weight: 20,
    confidence: 0.88,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (CRYPTO_UNOFFICIAL_TLDS.has(ctx.tld.toLowerCase())) {
        return {
          ruleId: "TLD-004",
          ruleCode: "TLD-WEB3-UNOFFICIAL",
          category: "tld",
          name: "Decentralized / Web3 Non-ICANN TLD (.crypto, .eth)",
          description: `Decentralized domain extension '.${ctx.tld}' detected.`,
          severity: "medium",
          weight: 20,
          confidence: 0.88,
          evidence: `Web3 TLD: .${ctx.tld}`,
          matchedString: `.${ctx.tld}`,
          whyItMatters: "Decentralized domains are not subject to ICANN dispute policies, trademark takedowns, or registrar abuse reporting.",
          realWorldTechnique: "Crypto wallet drainers and unstoppable phishing portals.",
          recommendedAction: "Verify wallet connection requests with extreme scrutiny.",
          references: ["ICANN Root Zone Database", "Web3 Security Consortium"],
          tags: ["web3", "crypto", "blockchain"],
        };
      }
      return null;
    },
    whyItMatters: "Decentralized TLDs lack standard abuse reporting and trademark takedowns.",
    realWorldTechnique: "Immune to traditional domain takedown requests.",
    recommendedAction: "Scrutinize wallet connection requests.",
    references: ["ICANN Root Zone"],
    tags: ["web3", "crypto"],
  },
  {
    id: "TLD-005",
    category: "tld",
    name: "Low Governance ccTLD (.pw, .cc, .ws, .su)",
    description: "Domain uses a country-code TLD known for minimal registrar abuse enforcement.",
    severity: "medium",
    weight: 15,
    confidence: 0.82,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const lowGov = ["pw", "cc", "ws", "su", "to"];
      if (lowGov.includes(ctx.tld.toLowerCase()) && !ctx.isAllowlisted) {
        return {
          ruleId: "TLD-005",
          ruleCode: "TLD-LOW-GOV",
          category: "tld",
          name: "Low Governance ccTLD (.pw, .cc, .ws, .su)",
          description: `Country code '.${ctx.tld}' with relaxed compliance standards.`,
          severity: "medium",
          weight: 15,
          confidence: 0.82,
          evidence: `ccTLD: .${ctx.tld}`,
          matchedString: `.${ctx.tld}`,
          whyItMatters: "Threat actors register on permissive registries to avoid fast suspension.",
          realWorldTechnique: "Bulletproof domain hosting.",
          recommendedAction: "Check official organization domain.",
          references: ["APWG Registry Survey"],
          tags: ["tld", "cctld"],
        };
      }
      return null;
    },
    whyItMatters: "Permissive registries delay or resist phishing takedown requests.",
    realWorldTechnique: "Bulletproof infrastructure.",
    recommendedAction: "Verify official company domain.",
    references: ["APWG"],
    tags: ["tld"],
  },
  {
    id: "TLD-006",
    category: "tld",
    name: "Commercial Brand on Foreign ccTLD",
    description: "An international or Indian financial entity name hosted on an unexpected foreign ccTLD.",
    severity: "high",
    weight: 25,
    confidence: 0.90,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const host = ctx.hostname.toLowerCase();
      const foreignCc = ["ru", "cn", "ir", "kp", "sy"];
      const isFin = ["sbi", "hdfc", "icici", "paypal", "chase", "bank"].some((b) => host.includes(b));
      if (isFin && foreignCc.includes(ctx.tld.toLowerCase()) && !ctx.isAllowlisted) {
        return {
          ruleId: "TLD-006",
          ruleCode: "TLD-BRAND-FOREIGN-CCTLD",
          category: "tld",
          name: "Commercial Brand on Foreign ccTLD",
          description: `Financial entity brand hosted under foreign ccTLD '.${ctx.tld}'.`,
          severity: "high",
          weight: 25,
          confidence: 0.90,
          evidence: `Host: ${ctx.hostname} (Foreign TLD .${ctx.tld})`,
          matchedString: `.${ctx.tld}`,
          whyItMatters: "Domestic financial institutions do not serve legitimate retail banking customers from adversary or unrelated foreign country domains.",
          realWorldTechnique: "Jurisdiction evasion to avoid law enforcement takedown.",
          recommendedAction: "Block URL immediately.",
          references: ["FS-ISAC Guidance on Phishing Infrastructure"],
          tags: ["brand", "jurisdiction", "cctld"],
        };
      }
      return null;
    },
    whyItMatters: "Banks do not operate retail customer portals on foreign adversary ccTLDs.",
    realWorldTechnique: "Jurisdiction hopping to resist domestic court orders.",
    recommendedAction: "Block navigation.",
    references: ["FS-ISAC Guidance"],
    tags: ["brand", "cctld"],
  },
  {
    id: "TLD-007",
    category: "tld",
    name: "Missing or Unqualified TLD",
    description: "The hostname does not possess a valid top-level domain extension.",
    severity: "high",
    weight: 25,
    confidence: 0.95,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (!ctx.tld && !ctx.hostname.match(/^\d+(\.\d+){3}$/) && ctx.hostname !== "localhost") {
        return {
          ruleId: "TLD-007",
          ruleCode: "TLD-MISSING",
          category: "tld",
          name: "Missing or Unqualified TLD",
          description: `Hostname '${ctx.hostname}' lacks a valid root TLD.`,
          severity: "high",
          weight: 25,
          confidence: 0.95,
          evidence: `Host: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "Unqualified single-label hostnames depend on local search suffix lists or NetBIOS resolution, making them susceptible to local name spoofing (LLMNR/NBT-NS poisoning).",
          realWorldTechnique: "LLMNR / NetBIOS spoofing and local intranet credential capture.",
          recommendedAction: "Do not navigate to unqualified hostnames from untrusted links.",
          references: ["RFC 6761", "MITRE ATT&CK T1557.001: LLMNR/NBT-NS Poisoning"],
          tags: ["tld", "llmnr", "unqualified"],
        };
      }
      return null;
    },
    whyItMatters: "Single-label hostnames trigger local name resolution vulnerabilities.",
    realWorldTechnique: "MITRE ATT&CK T1557.001 LLMNR/NBT-NS Poisoning.",
    recommendedAction: "Use fully qualified domain names.",
    references: ["MITRE ATT&CK T1557.001"],
    tags: ["llmnr", "tld"],
  },
  {
    id: "TLD-008",
    category: "tld",
    name: "Exceptionally Long TLD (> 10 characters)",
    description: "TLD extension exceeds 10 characters, which can visually camouflage path separators.",
    severity: "low",
    weight: 10,
    confidence: 0.75,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.tld.length > 10 && !ctx.isAllowlisted) {
        return {
          ruleId: "TLD-008",
          ruleCode: "TLD-LONG-LEN",
          category: "tld",
          name: "Exceptionally Long TLD (> 10 characters)",
          description: `Long TLD extension '.${ctx.tld}' (${ctx.tld.length} chars).`,
          severity: "low",
          weight: 10,
          confidence: 0.75,
          evidence: `TLD: .${ctx.tld}`,
          matchedString: `.${ctx.tld}`,
          whyItMatters: "Unusually long TLDs can confuse users about where the hostname ends and the path begins.",
          realWorldTechnique: "Visual obfuscation in address bars.",
          recommendedAction: "Confirm destination site identity.",
          references: ["ICANN New gTLD Program"],
          tags: ["tld", "gtld"],
        };
      }
      return null;
    },
    whyItMatters: "Long TLDs blur the visual separation between domain and path.",
    realWorldTechnique: "Visual ambiguity in URL formatting.",
    recommendedAction: "Inspect full URL.",
    references: ["ICANN gTLD"],
    tags: ["tld"],
  },
  {
    id: "TLD-009",
    category: "tld",
    name: "New Low-Cost Generic TLD with Lure (.site, .online, .live, .shop)",
    description: "Registered under a heavily discounted gTLD while advertising financial/account keywords.",
    severity: "medium",
    weight: 18,
    confidence: 0.88,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const discountTlds = ["site", "online", "live", "shop", "store", "club", "space"];
      if (discountTlds.includes(ctx.tld.toLowerCase()) && !ctx.isAllowlisted) {
        const hasLure = ctx.allTokens.some((t) =>
          ["login", "secure", "verify", "account", "banking", "wallet", "bonus"].includes(t)
        );
        if (hasLure) {
          return {
            ruleId: "TLD-009",
            ruleCode: "TLD-DISCOUNT-LURE",
            category: "tld",
            name: "New Low-Cost Generic TLD with Lure (.site, .online, .live, .shop)",
            description: `Discount TLD '.${ctx.tld}' combined with social engineering keywords.`,
            severity: "medium",
            weight: 18,
            confidence: 0.88,
            evidence: `TLD: .${ctx.tld} with lure keywords`,
            matchedString: `.${ctx.tld}`,
            whyItMatters: "Discount gTLDs are the primary vehicle for high-volume credential phishing campaigns due to minimal setup cost.",
            realWorldTechnique: "Bulk deployment of short-lived phishing portals on $1 TLDs.",
            recommendedAction: "Do not provide passwords or OTPs on discount gTLDs.",
            references: ["APWG Global Phishing Survey"],
            tags: ["tld", "lure", "discount-domain"],
          };
        }
      }
      return null;
    },
    whyItMatters: "Discount TLDs combined with lures represent high statistical likelihood of phishing.",
    realWorldTechnique: "Low-cost mass phishing.",
    recommendedAction: "Verify site with official provider.",
    references: ["APWG"],
    tags: ["tld", "lure"],
  },
  {
    id: "TLD-010",
    category: "tld",
    name: "Hyphenated Compound TLD Spoofing",
    description: "Domain embeds fake TLD structures like '.com-account' in the hostname.",
    severity: "high",
    weight: 25,
    confidence: 0.92,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (/\.com-[a-z0-9]|\.org-[a-z0-9]|\.in-[a-z0-9]/i.test(ctx.hostname) && !ctx.isAllowlisted) {
        return {
          ruleId: "TLD-010",
          ruleCode: "TLD-HYPHEN-SPOOF",
          category: "tld",
          name: "Hyphenated Compound TLD Spoofing",
          description: "Hyphenated fake TLD pattern embedded in domain label.",
          severity: "high",
          weight: 25,
          confidence: 0.92,
          evidence: `Pattern in: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "Victims glance at '.com-' and assume the domain ends there, failing to notice the real registered domain following the hyphen.",
          realWorldTechnique: "Visual truncation deception.",
          recommendedAction: "Look for the actual dot-separated TLD at the very end of the hostname.",
          references: ["US-CERT Combosquatting Alert"],
          tags: ["tld-spoof", "visual-deception"],
        };
      }
      return null;
    },
    whyItMatters: "Hyphenated fake TLDs trick human visual scanning.",
    realWorldTechnique: "Visual spoofing of domain boundaries.",
    recommendedAction: "Check real apex domain.",
    references: ["US-CERT"],
    tags: ["tld-spoof"],
  },
  {
    id: "TLD-011",
    category: "tld",
    name: "Reserved / Test TLD Inappropriate Exposure (.test, .invalid)",
    description: "Domain uses an RFC 2606 reserved documentation or testing TLD.",
    severity: "info",
    weight: 5,
    confidence: 0.99,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const reserved = ["invalid", "test", "example", "localhost"];
      if (reserved.includes(ctx.tld.toLowerCase())) {
        return {
          ruleId: "TLD-011",
          ruleCode: "TLD-RFC2606-RESERVED",
          category: "tld",
          name: "Reserved / Test TLD Inappropriate Exposure (.test, .invalid)",
          description: `Uses RFC 2606 reserved documentation TLD '.${ctx.tld}'.`,
          severity: "info",
          weight: 5,
          confidence: 0.99,
          evidence: `TLD: .${ctx.tld}`,
          matchedString: `.${ctx.tld}`,
          whyItMatters: "RFC 2606 reserves .test, .example, and .invalid for testing. They cannot be registered publicly on the internet.",
          realWorldTechnique: "Used in QA test fixtures and penetration testing simulations.",
          recommendedAction: "Valid for simulation; cannot resolve on public Internet.",
          references: ["RFC 2606 §2"],
          tags: ["rfc2606", "reserved", "testing"],
        };
      }
      return null;
    },
    whyItMatters: "Reserved TLDs are guaranteed non-routable on public DNS.",
    realWorldTechnique: "Educational and QA simulation.",
    recommendedAction: "Safe for offline testing.",
    references: ["RFC 2606"],
    tags: ["rfc2606"],
  },
  {
    id: "TLD-012",
    category: "tld",
    name: "Multi-Part ccTLD Misinterpretation",
    description: "Domain structures deep subdomains imitating multi-part country codes.",
    severity: "low",
    weight: 10,
    confidence: 0.80,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const parts = ctx.hostname.split(".");
      if (parts.length >= 4 && parts[parts.length - 2] === "co" && parts[parts.length - 1] === "com") {
        return {
          ruleId: "TLD-012",
          ruleCode: "TLD-MULTIPART-DECEPTION",
          category: "tld",
          name: "Multi-Part ccTLD Misinterpretation",
          description: "Domain uses '.co.com' or similar commercial third-party proxy domain.",
          severity: "low",
          weight: 10,
          confidence: 0.80,
          evidence: `Host: ${ctx.hostname}`,
          matchedString: ".co.com",
          whyItMatters: "Third-party registry services sell subdomains under '.co.com' which mimic ccTLDs like '.co.uk' or '.co.in'.",
          realWorldTechnique: "Domain mimicry through central registry sub-leases.",
          recommendedAction: "Verify actual domain owner.",
          references: ["ICANN PSL Documentation"],
          tags: ["tld", "co-com"],
        };
      }
      return null;
    },
    whyItMatters: "Sub-leases mimic genuine ccTLDs.",
    realWorldTechnique: "Domain camouflage.",
    recommendedAction: "Check PSL status.",
    references: ["Public Suffix List"],
    tags: ["tld"],
  },
  {
    id: "TLD-013",
    category: "tld",
    name: "Dark Web / Onion Service Link (.onion)",
    description: "The URL targets a Tor hidden service (.onion).",
    severity: "high",
    weight: 30,
    confidence: 0.98,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.tld.toLowerCase() === "onion") {
        return {
          ruleId: "TLD-013",
          ruleCode: "TLD-TOR-ONION",
          category: "tld",
          name: "Dark Web / Onion Service Link (.onion)",
          description: "Tor hidden service (.onion) destination.",
          severity: "high",
          weight: 30,
          confidence: 0.98,
          evidence: "TLD: .onion",
          matchedString: ".onion",
          whyItMatters: "Onion services operate anonymously over the Tor network. They cannot be reached by standard web browsers without special proxy routing.",
          realWorldTechnique: "Anonymized ransomware payment portals or illicit data leak forums.",
          recommendedAction: "Do not open outside an isolated Tor sandbox.",
          references: ["RFC 7686: The .onion Special-Use Domain Name"],
          tags: ["tor", "onion", "darkweb"],
        };
      }
      return null;
    },
    whyItMatters: "Onion domains operate outside ICANN governance on anonymous overlay networks.",
    realWorldTechnique: "Ransomware extortion and black market forums.",
    recommendedAction: "Do not navigate without dedicated isolation.",
    references: ["RFC 7686"],
    tags: ["tor", "onion"],
  },
  {
    id: "TLD-014",
    category: "tld",
    name: "Suspicious Dynamic Redirection TLD (.link, .click)",
    description: "Domain uses a redirect-themed TLD often used in SMS phishing (smishing).",
    severity: "medium",
    weight: 15,
    confidence: 0.85,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const linkTlds = ["link", "click", "to", "ly"];
      if (linkTlds.includes(ctx.tld.toLowerCase()) && !ctx.isAllowlisted) {
        return {
          ruleId: "TLD-014",
          ruleCode: "TLD-LINK-REDIRECT",
          category: "tld",
          name: "Suspicious Dynamic Redirection TLD (.link, .click)",
          description: `Uses short redirect TLD '.${ctx.tld}'.`,
          severity: "medium",
          weight: 15,
          confidence: 0.85,
          evidence: `TLD: .${ctx.tld}`,
          matchedString: `.${ctx.tld}`,
          whyItMatters: "Short link extensions are heavily favored in SMS text messages (smishing) to keep message length low and evade SMS gateway spam filters.",
          realWorldTechnique: "SMS phishing (Smishing) lure delivery.",
          recommendedAction: "Never click unsolicited short links in SMS messages.",
          references: ["CISA Tip on Smishing", "MITRE ATT&CK T1566.002"],
          tags: ["smishing", "shortlink", "tld"],
        };
      }
      return null;
    },
    whyItMatters: "Short TLDs are common in SMS phishing.",
    realWorldTechnique: "Smishing payload delivery.",
    recommendedAction: "Avoid clicking in text messages.",
    references: ["CISA Smishing"],
    tags: ["smishing", "tld"],
  },
  {
    id: "TLD-015",
    category: "tld",
    name: "Non-Standard Numeric TLD Format",
    description: "TLD component contains digits, which is prohibited under ICANN root zone guidelines.",
    severity: "high",
    weight: 25,
    confidence: 0.95,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (/\d/.test(ctx.tld) && !ctx.hostname.match(/^\d+(\.\d+){3}$/)) {
        return {
          ruleId: "TLD-015",
          ruleCode: "TLD-NUMERIC-INVALID",
          category: "tld",
          name: "Non-Standard Numeric TLD Format",
          description: `TLD '.${ctx.tld}' contains numbers, violating ICANN root rules.`,
          severity: "high",
          weight: 25,
          confidence: 0.95,
          evidence: `TLD: .${ctx.tld}`,
          matchedString: ctx.tld,
          whyItMatters: "ICANN does not permit numbers in top-level domains. A numeric TLD indicates an improperly parsed IP address or DNS spoofing attempt.",
          realWorldTechnique: "Exploits parser errors in legacy DNS resolvers.",
          recommendedAction: "Reject URL.",
          references: ["ICANN Root Zone Rules §3.1"],
          tags: ["tld", "icann", "rfc-violation"],
        };
      }
      return null;
    },
    whyItMatters: "ICANN prohibits numeric TLDs.",
    realWorldTechnique: "Parser confusion / IP misinterpretation.",
    recommendedAction: "Reject URL.",
    references: ["ICANN Root Rules"],
    tags: ["icann", "tld"],
  },
];
