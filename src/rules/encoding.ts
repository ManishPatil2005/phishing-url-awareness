import type { Rule, RuleFinding, ParsedUrlContext } from "./types.ts";

function calculateShannonEntropy(str: string): number {
  if (!str) return 0;
  const freqs: Record<string, number> = {};
  for (const ch of str) {
    freqs[ch] = (freqs[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freqs)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export const encodingRules: Rule[] = [
  {
    id: "ENC-001",
    category: "encoding",
    name: "Punycode (xn--) Internationalized Domain",
    description: "The domain uses the 'xn--' Punycode prefix to render Unicode characters.",
    severity: "high",
    weight: 20,
    confidence: 0.92,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.hostname.toLowerCase().includes("xn--")) {
        return {
          ruleId: "ENC-001",
          ruleCode: "H5-PUNYCODE",
          category: "encoding",
          name: "Punycode (xn--) Internationalized Domain",
          description: `Punycode identifier detected in host: ${ctx.hostname}.`,
          severity: "high",
          weight: 20,
          confidence: 0.92,
          evidence: `Punycode host: ${ctx.hostname}`,
          matchedString: "xn--",
          whyItMatters: "Punycode (RFC 3492) allows non-ASCII characters to be represented using ASCII. Attackers use this to craft homoglyphs—domains that look identical to genuine sites (e.g., 'apple.com' with a Cyrillic 'а') but resolve to malicious IP addresses.",
          realWorldTechnique: "IDN Homograph Attack: Registering Punycode domains visually indistinguishable from major financial and tech institutions.",
          recommendedAction: "Examine the raw ASCII Punycode string. Do not trust internationalized character representations for sensitive accounts.",
          references: ["RFC 3492", "Unicode Technical Report #36", "ICANN IDN Guidelines"],
          tags: ["punycode", "idn", "homoglyph"],
        };
      }
      return null;
    },
    whyItMatters: "Punycode is frequently abused for visual homograph spoofing of major brands.",
    realWorldTechnique: "IDN homoglyph impersonation.",
    recommendedAction: "Inspect the raw Punycode string.",
    references: ["RFC 3492"],
    tags: ["punycode"],
  },
  {
    id: "ENC-002",
    category: "encoding",
    name: "Cyrillic Character in Hostname (Homoglyph)",
    description: "Host contains Cyrillic characters that visually mimic Latin letters.",
    severity: "critical",
    weight: 35,
    confidence: 0.98,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      // Cyrillic unicode block: U+0400 to U+04FF
      const cyrillicMatch = ctx.hostname.match(/[\u0400-\u04FF]/);
      if (cyrillicMatch) {
        return {
          ruleId: "ENC-002",
          ruleCode: "ENC-CYRILLIC-HOMOGLYPH",
          category: "encoding",
          name: "Cyrillic Character in Hostname (Homoglyph)",
          description: `Cyrillic glyph '${cyrillicMatch[0]}' embedded in hostname.`,
          severity: "critical",
          weight: 35,
          confidence: 0.98,
          evidence: `Cyrillic character: ${cyrillicMatch[0]} in ${ctx.hostname}`,
          matchedString: cyrillicMatch[0],
          whyItMatters: "Cyrillic letters such as 'а', 'е', 'о', 'р', 'с', 'у', and 'х' are visually identical in standard fonts to Latin letters, allowing perfect visual spoofing of domains.",
          realWorldTechnique: "Homoglyph Attack: spoofing domain names with cross-alphabet glyph substitutes.",
          recommendedAction: "Block immediately. Visual spoofing attack in progress.",
          references: ["Unicode TR #39: Security Mechanisms", "MITRE ATT&CK T1566.002"],
          tags: ["cyrillic", "homoglyph", "visual-spoofing"],
        };
      }
      return null;
    },
    whyItMatters: "Cyrillic homoglyphs look visually identical to Latin letters.",
    realWorldTechnique: "Homograph brand spoofing.",
    recommendedAction: "Block navigation.",
    references: ["Unicode TR #39"],
    tags: ["cyrillic", "homoglyph"],
  },
  {
    id: "ENC-003",
    category: "encoding",
    name: "Greek Character in Hostname",
    description: "Host contains Greek alphabet characters that mimic Latin characters.",
    severity: "critical",
    weight: 35,
    confidence: 0.96,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      // Greek unicode block: U+0370 to U+03FF
      const greekMatch = ctx.hostname.match(/[\u0370-\u03FF]/);
      if (greekMatch) {
        return {
          ruleId: "ENC-003",
          ruleCode: "ENC-GREEK-HOMOGLYPH",
          category: "encoding",
          name: "Greek Character in Hostname",
          description: `Greek glyph '${greekMatch[0]}' embedded in hostname.`,
          severity: "critical",
          weight: 35,
          confidence: 0.96,
          evidence: `Greek character: ${greekMatch[0]}`,
          matchedString: greekMatch[0],
          whyItMatters: "Greek omicron ('ο'), nu ('ν'), and rho ('ρ') can visually substitute for English letters.",
          realWorldTechnique: "Cross-script homograph spoofing.",
          recommendedAction: "Block navigation and inspect raw string.",
          references: ["Unicode TR #36"],
          tags: ["greek", "homoglyph"],
        };
      }
      return null;
    },
    whyItMatters: "Greek characters visually imitate Latin counterparts.",
    realWorldTechnique: "Homograph spoofing.",
    recommendedAction: "Reject URL.",
    references: ["Unicode TR #36"],
    tags: ["greek"],
  },
  {
    id: "ENC-004",
    category: "encoding",
    name: "Zero-Width or Invisible Character",
    description: "The URL contains invisible or zero-width unicode characters.",
    severity: "critical",
    weight: 40,
    confidence: 0.99,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      // Zero-width space, non-joiner, joiner, BOM, etc.
      const match = ctx.rawUrl.match(/[\u200B-\u200D\uFEFF\u2060]/);
      if (match) {
        return {
          ruleId: "ENC-004",
          ruleCode: "ENC-ZERO-WIDTH",
          category: "encoding",
          name: "Zero-Width or Invisible Character",
          description: "Invisible character detected in URL payload.",
          severity: "critical",
          weight: 40,
          confidence: 0.99,
          evidence: `Invisible code point: U+${match[0].charCodeAt(0).toString(16).toUpperCase()}`,
          matchedString: match[0],
          whyItMatters: "Zero-width characters render invisibly in user interfaces while altering string signatures, allowing attackers to bypass string filters and deceive human eyes simultaneously.",
          realWorldTechnique: "Zero-width fingerprinting and signature evasion.",
          recommendedAction: "Block immediately. Zero-width characters in web links are almost universally malicious.",
          references: ["Unicode Standard Annex #9", "OWASP Evasion Cheatsheet"],
          tags: ["zero-width", "invisible", "evasion"],
        };
      }
      return null;
    },
    whyItMatters: "Invisible characters bypass text filters while remaining unseen by humans.",
    realWorldTechnique: "Zero-width evasion.",
    recommendedAction: "Block URL.",
    references: ["Unicode Annex #9"],
    tags: ["zero-width"],
  },
  {
    id: "ENC-005",
    category: "encoding",
    name: "Right-to-Left Override (RLO) Inversion",
    description: "The URL contains the Unicode Right-to-Left Override control character (U+202E).",
    severity: "critical",
    weight: 40,
    confidence: 0.99,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.rawUrl.includes("\u202E")) {
        return {
          ruleId: "ENC-005",
          ruleCode: "ENC-RLO-OVERRIDE",
          category: "encoding",
          name: "Right-to-Left Override (RLO) Inversion",
          description: "Unicode RLO (U+202E) detected, flipping text display direction.",
          severity: "critical",
          weight: 40,
          confidence: 0.99,
          evidence: "Unicode U+202E found in URL",
          matchedString: "\u202E",
          whyItMatters: "The RLO character causes subsequent text to be displayed in reverse order. An executable file like 'invoice_exe.pdf' will appear visually as 'invoice_fdp.exe' or vice-versa.",
          realWorldTechnique: "File extension and domain spoofing via bidirectional text rendering inversion.",
          recommendedAction: "Block URL immediately. Highly dangerous file spoofing exploit.",
          references: ["Unicode BiDi Algorithm (UAX #9)", "MITRE ATT&CK T1036.002: Right-to-Left Override"],
          tags: ["rlo", "bidi", "t1036"],
        };
      }
      return null;
    },
    whyItMatters: "RLO flips visual text direction to disguise file extensions and hostnames.",
    realWorldTechnique: "MITRE ATT&CK T1036.002 Right-to-Left Override.",
    recommendedAction: "Block immediately.",
    references: ["MITRE ATT&CK T1036.002"],
    tags: ["rlo"],
  },
  {
    id: "ENC-006",
    category: "encoding",
    name: "High Shannon Entropy in Hostname (> 3.8 bits)",
    description: "Hostname displays unusually high information entropy, indicative of algorithmic generation.",
    severity: "medium",
    weight: 20,
    confidence: 0.88,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const { rootDomain } = ctx;
      const label = rootDomain.split(".")[0];
      if (label.length >= 10) {
        const entropy = calculateShannonEntropy(label);
        if (entropy > 3.8) {
          return {
            ruleId: "ENC-006",
            ruleCode: "ENC-HIGH-ENTROPY",
            category: "encoding",
            name: "High Shannon Entropy in Hostname (> 3.8 bits)",
            description: `Entropy of '${label}' is ${entropy.toFixed(2)} bits/char, indicating algorithmic randomness.`,
            severity: "medium",
            weight: 20,
            confidence: 0.88,
            evidence: `Entropy: ${entropy.toFixed(2)} in label '${label}'`,
            matchedString: label,
            whyItMatters: "Benign human language has predictable letter distribution with lower entropy (~2.5 to 3.2). High entropy signifies machine-generated random strings.",
            realWorldTechnique: "Malware Command & Control (C2) and phishing DGA domains.",
            recommendedAction: "Treat domain as suspicious and check registration telemetry.",
            references: ["Shannon Entropy in Malware Detection", "IEEE Communications"],
            tags: ["entropy", "dga", "randomness"],
          };
        }
      }
      return null;
    },
    whyItMatters: "High entropy reveals pseudo-random machine generated strings.",
    realWorldTechnique: "DGA domain generation.",
    recommendedAction: "Flag for threat analysis.",
    references: ["Shannon Entropy Standards"],
    tags: ["entropy"],
  },
  {
    id: "ENC-007",
    category: "encoding",
    name: "Excessive Percent-Encoding (> 3 Sequences)",
    description: "URL contains multiple percent-encoded character sequences.",
    severity: "medium",
    weight: 15,
    confidence: 0.85,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const matches = ctx.rawUrl.match(/%[0-9a-fA-F]{2}/g) || [];
      if (matches.length > 3 && !ctx.isAllowlisted) {
        return {
          ruleId: "ENC-007",
          ruleCode: "ENC-PERCENT-EXCESS",
          category: "encoding",
          name: "Excessive Percent-Encoding (> 3 Sequences)",
          description: `Found ${matches.length} percent-encoded tokens in URL.`,
          severity: "medium",
          weight: 15,
          confidence: 0.85,
          evidence: `Encoded sequences count: ${matches.length}`,
          matchedString: matches.slice(0, 3).join(", "),
          whyItMatters: "Percent-encoding standard letters (like '%6c%6f%67%69%6e' for 'login') is a textbook evasion technique to bypass keyword detection.",
          realWorldTechnique: "Obfuscates sensitive keywords and IP strings from static filters.",
          recommendedAction: "Decode and inspect the plaintext string.",
          references: ["RFC 3986 §2.1", "OWASP Evasion"],
          tags: ["encoding", "percent", "obfuscation"],
        };
      }
      return null;
    },
    whyItMatters: "Excess percent-encoding obfuscates keywords from detection rules.",
    realWorldTechnique: "Hides malicious words via hex escaping.",
    recommendedAction: "Decode URL before inspection.",
    references: ["RFC 3986 §2.1"],
    tags: ["percent-encoding"],
  },
  {
    id: "ENC-008",
    category: "encoding",
    name: "Double Percent-Encoding (%25)",
    description: "URL contains '%25' sequence, indicating double-layer percent-encoding.",
    severity: "high",
    weight: 25,
    confidence: 0.95,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (/%25[0-9a-fA-F]{2}/i.test(ctx.rawUrl)) {
        return {
          ruleId: "ENC-008",
          ruleCode: "ENC-DOUBLE-PERCENT",
          category: "encoding",
          name: "Double Percent-Encoding (%25)",
          description: "Double percent-encoding (%25) detected in URL string.",
          severity: "high",
          weight: 25,
          confidence: 0.95,
          evidence: "Sequence %25 detected",
          matchedString: "%25",
          whyItMatters: "Double-encoding exploits differences between filtering reverse proxies (which decode once) and backend applications (which decode twice), smuggling payloads.",
          realWorldTechnique: "WAF bypass and path traversal smuggling via double decoding.",
          recommendedAction: "Block URL as an active evasion attempt.",
          references: ["OWASP Double Encoding", "CWE-173"],
          tags: ["double-encoding", "waf-bypass", "smuggling"],
        };
      }
      return null;
    },
    whyItMatters: "Double-encoding exploits parser discrepancies to bypass security filters.",
    realWorldTechnique: "WAF and filter evasion.",
    recommendedAction: "Block URL.",
    references: ["OWASP Double Encoding"],
    tags: ["double-encoding"],
  },
  {
    id: "ENC-009",
    category: "encoding",
    name: "Percent-Encoded Forward Slash (%2F)",
    description: "The path delimiter forward slash is obfuscated as '%2F'.",
    severity: "high",
    weight: 25,
    confidence: 0.92,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (/%2f/i.test(ctx.rawUrl)) {
        return {
          ruleId: "ENC-009",
          ruleCode: "ENC-SLASH-ENCODED",
          category: "encoding",
          name: "Percent-Encoded Forward Slash (%2F)",
          description: "Encoded slash '%2F' found in URL.",
          severity: "high",
          weight: 25,
          confidence: 0.92,
          evidence: "%2F detected",
          matchedString: "%2F",
          whyItMatters: "Encoding '/' conceals subpaths and file targets from reverse-proxy routing rules.",
          realWorldTechnique: "Path traversal and ACL bypass.",
          recommendedAction: "Normalize paths and verify server authorization.",
          references: ["RFC 3986 §2.2", "CWE-22"],
          tags: ["slash", "path-traversal", "evasion"],
        };
      }
      return null;
    },
    whyItMatters: "Encoded slashes bypass URL routing and firewall path rules.",
    realWorldTechnique: "Smuggles prohibited paths past perimeter filters.",
    recommendedAction: "Decode and inspect normalized path.",
    references: ["RFC 3986"],
    tags: ["slash"],
  },
  {
    id: "ENC-010",
    category: "encoding",
    name: "Percent-Encoded Userinfo Delimiter (%40)",
    description: "The authentication delimiter '@' is encoded as '%40'.",
    severity: "high",
    weight: 25,
    confidence: 0.95,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (/%40/i.test(ctx.rawUrl)) {
        return {
          ruleId: "ENC-010",
          ruleCode: "ENC-AT-ENCODED",
          category: "encoding",
          name: "Percent-Encoded Userinfo Delimiter (%40)",
          description: "Encoded '@' symbol (%40) detected in URL authority/path.",
          severity: "high",
          weight: 25,
          confidence: 0.95,
          evidence: "%40 detected in URL",
          matchedString: "%40",
          whyItMatters: "Encoding '@' allows threat actors to disguise userinfo credential spoofing from naive parsers that only look for a literal '@'.",
          realWorldTechnique: "Concealed authority spoofing.",
          recommendedAction: "Decode before determining destination host.",
          references: ["RFC 3986 §3.2.1"],
          tags: ["userinfo", "encoded-at", "spoofing"],
        };
      }
      return null;
    },
    whyItMatters: "Hides userinfo '@' symbol from security parsers.",
    realWorldTechnique: "Concealed authority spoofing.",
    recommendedAction: "Decode before identifying destination host.",
    references: ["RFC 3986"],
    tags: ["userinfo"],
  },
  {
    id: "ENC-011",
    category: "encoding",
    name: "Percent-Encoded Fragment Hash (%23)",
    description: "The fragment delimiter '#' is encoded as '%23' to alter path parsing.",
    severity: "medium",
    weight: 15,
    confidence: 0.88,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (/%23/i.test(ctx.rawUrl)) {
        return {
          ruleId: "ENC-011",
          ruleCode: "ENC-HASH-ENCODED",
          category: "encoding",
          name: "Percent-Encoded Fragment Hash (%23)",
          description: "Encoded fragment delimiter '%23' detected.",
          severity: "medium",
          weight: 15,
          confidence: 0.88,
          evidence: "%23 in URL",
          matchedString: "%23",
          whyItMatters: "Encodes '#' to trick backend web servers into processing client-side fragment state as server query strings.",
          realWorldTechnique: "Parser confusion and SSRF delimiter smuggling.",
          recommendedAction: "Inspect full URL parameters.",
          references: ["RFC 3986 §3.5"],
          tags: ["fragment", "delimiter"],
        };
      }
      return null;
    },
    whyItMatters: "Manipulates fragment vs query parsing boundaries.",
    realWorldTechnique: "Smuggles client-side parameters.",
    recommendedAction: "Inspect query components.",
    references: ["RFC 3986"],
    tags: ["fragment"],
  },
  {
    id: "ENC-012",
    category: "encoding",
    name: "Base64 or Hex Encoded Blob in Path (> 24 chars)",
    description: "URL contains a long base64 or hexadecimal data blob in the path component.",
    severity: "medium",
    weight: 15,
    confidence: 0.85,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      for (const seg of ctx.pathSegments) {
        if (seg.length > 24 && /^[a-zA-Z0-9+/=_-]{24,}$/.test(seg) && !ctx.isAllowlisted) {
          return {
            ruleId: "ENC-012",
            ruleCode: "ENC-BLOB-PATH",
            category: "encoding",
            name: "Base64 or Hex Encoded Blob in Path (> 24 chars)",
            description: `Path segment contains encoded data blob (${seg.length} chars).`,
            severity: "medium",
            weight: 15,
            confidence: 0.85,
            evidence: `Blob: ${seg.substring(0, 20)}...`,
            matchedString: seg,
            whyItMatters: "Threat actors pass base64-encoded victim email addresses, campaign tokens, or secondary redirection URLs in path segments.",
            realWorldTechnique: "Embeds pre-filled victim telemetry in phishing links.",
            recommendedAction: "Decode the blob to review what information is being transmitted.",
            references: ["APWG Phishing Analysis Techniques"],
            tags: ["base64", "blob", "telemetry"],
          };
        }
      }
      return null;
    },
    whyItMatters: "Base64 blobs typically encode victim identities or dynamic redirect targets.",
    realWorldTechnique: "Carries victim metadata in URL paths.",
    recommendedAction: "Decode blob to identify victim data.",
    references: ["APWG Techniques"],
    tags: ["base64"],
  },
  {
    id: "ENC-013",
    category: "encoding",
    name: "Mixed-Script Hostname Anomaly",
    description: "The hostname mixes Latin characters with non-Latin characters in the same label.",
    severity: "critical",
    weight: 35,
    confidence: 0.98,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      // Check if host contains both Latin and Cyrillic/Greek
      const hasLatin = /[a-zA-Z]/.test(ctx.hostname);
      const hasCyrillicOrGreek = /[\u0400-\u04FF\u0370-\u03FF]/.test(ctx.hostname);
      if (hasLatin && hasCyrillicOrGreek) {
        return {
          ruleId: "ENC-013",
          ruleCode: "ENC-MIXED-SCRIPT",
          category: "encoding",
          name: "Mixed-Script Hostname Anomaly",
          description: "Hostname mixes Latin with Cyrillic/Greek characters in single domain.",
          severity: "critical",
          weight: 35,
          confidence: 0.98,
          evidence: `Mixed scripts in: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "ICANN security guidelines heavily restrict mixed-script domain registrations because there is rarely a legitimate linguistic need to mix Latin and Cyrillic/Greek within a single domain label.",
          realWorldTechnique: "Homoglyph insertion: substituting a single Latin 'o' with Cyrillic 'о'.",
          recommendedAction: "Block URL unconditionally. Highly indicative of active spoofing.",
          references: ["ICANN IDN Implementation Guidelines §4", "Unicode TR #39"],
          tags: ["mixed-script", "homoglyph", "icann"],
        };
      }
      return null;
    },
    whyItMatters: "Mixing alphabets in a single domain label is a primary homoglyph spoofing signal.",
    realWorldTechnique: "Replaces single characters with foreign lookalikes.",
    recommendedAction: "Block URL.",
    references: ["ICANN Guidelines §4"],
    tags: ["mixed-script"],
  },
  {
    id: "ENC-014",
    category: "encoding",
    name: "Null Byte Injection (%00)",
    description: "URL contains a null byte (%00 or \\0) in the string.",
    severity: "critical",
    weight: 40,
    confidence: 0.99,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (/%00/i.test(ctx.rawUrl) || ctx.rawUrl.includes("\0")) {
        return {
          ruleId: "ENC-014",
          ruleCode: "ENC-NULL-BYTE",
          category: "encoding",
          name: "Null Byte Injection (%00)",
          description: "Null byte (%00) found in URL payload.",
          severity: "critical",
          weight: 40,
          confidence: 0.99,
          evidence: "Null byte sequence detected",
          matchedString: "%00",
          whyItMatters: "In C-based web servers and older applications, a null byte terminates string processing, allowing attackers to truncate file extensions or sanitize checks.",
          realWorldTechnique: "Null byte injection to truncate file paths (e.g., 'payload.php%00.jpg').",
          recommendedAction: "Reject immediately. Malicious exploit vector.",
          references: ["OWASP Null Byte Injection", "CWE-626"],
          tags: ["null-byte", "injection", "exploit"],
        };
      }
      return null;
    },
    whyItMatters: "Null bytes truncate strings in C/C++ backends, bypassing file extension filters.",
    realWorldTechnique: "Bypasses extension checks on uploaded shells.",
    recommendedAction: "Reject immediately.",
    references: ["OWASP Null Byte"],
    tags: ["null-byte"],
  },
  {
    id: "ENC-015",
    category: "encoding",
    name: "Non-ASCII Control Character in URL",
    description: "URL contains non-printable ASCII control characters (bytes 0-31 or 127).",
    severity: "high",
    weight: 30,
    confidence: 0.95,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const match = ctx.rawUrl.match(/[\x00-\x1F\x7F]/);
      if (match) {
        return {
          ruleId: "ENC-015",
          ruleCode: "ENC-CONTROL-CHAR",
          category: "encoding",
          name: "Non-ASCII Control Character in URL",
          description: "Non-printable ASCII control character detected in URL.",
          severity: "high",
          weight: 30,
          confidence: 0.95,
          evidence: `Control byte: 0x${match[0].charCodeAt(0).toString(16)}`,
          matchedString: match[0],
          whyItMatters: "RFC 3986 specifies that control characters are illegal in URI syntax. Their presence indicates parser fuzzing, smuggling, or terminal injection.",
          realWorldTechnique: "Terminal escape injection and CRLF header injection.",
          recommendedAction: "Sanitize and block.",
          references: ["RFC 3986 §2", "CWE-93: CRLF Injection"],
          tags: ["control-char", "rfc-violation", "crlf"],
        };
      }
      return null;
    },
    whyItMatters: "Control characters are illegal in standard RFC 3986 URLs.",
    realWorldTechnique: "CRLF injection and terminal log poisoning.",
    recommendedAction: "Reject URL.",
    references: ["RFC 3986 §2"],
    tags: ["control-char"],
  },
];
