import type { Rule, RuleFinding, ParsedUrlContext } from "./types.ts";

const EXECUTABLE_EXTENSIONS = new Set([
  "exe", "scr", "bat", "cmd", "ps1", "apk", "vbs", "iso", "dmg", "jar", "msi", "hta", "wsf"
]);

const SENSITIVE_PATHS = [
  "/.env", "/.git", "/.aws", "/id_rsa", "/web.config", "/wp-config.php",
  "/etc/passwd", "/phpmyadmin", "/cpanel", "/webmail", "/.well-known/acme-challenge"
];

export const pathRules: Rule[] = [
  {
    id: "PTH-001",
    category: "path",
    name: "Dangerous Executable File Extension",
    description: "The path ends with an executable or scripting file extension.",
    severity: "critical",
    weight: 40,
    confidence: 0.98,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const lowerPath = ctx.path.toLowerCase();
      for (const ext of EXECUTABLE_EXTENSIONS) {
        if (lowerPath.endsWith(`.${ext}`) || lowerPath.includes(`.${ext}?`)) {
          return {
            ruleId: "PTH-001",
            ruleCode: "PTH-EXECUTABLE-EXT",
            category: "path",
            name: "Dangerous Executable File Extension",
            description: `URL points directly to an executable binary or script (.${ext}).`,
            severity: "critical",
            weight: 40,
            confidence: 0.98,
            evidence: `Executable extension: .${ext} in path`,
            matchedString: `.${ext}`,
            whyItMatters: "Direct links to executables, installer scripts, or mobile packages (.apk) in unsolicited communications represent drive-by download malware distribution.",
            realWorldTechnique: "MITRE ATT&CK T1204.001: Malicious Link execution delivering payload binaries.",
            recommendedAction: "Do NOT download or execute this file. Quarantine and report to InfoSec.",
            references: ["MITRE ATT&CK T1204.001", "CISA Drive-By Download Guidance"],
            tags: ["executable", "malware", "drive-by-download", "t1204"],
          };
        }
      }
      return null;
    },
    whyItMatters: "Direct links to executables deliver drive-by downloads or droppers.",
    realWorldTechnique: "Delivers malware payloads via unsolicited web links.",
    recommendedAction: "Block download immediately.",
    references: ["MITRE ATT&CK T1204.001"],
    tags: ["executable", "malware"],
  },
  {
    id: "PTH-002",
    category: "path",
    name: "Double File Extension Deception (e.g. invoice.pdf.exe)",
    description: "Path utilizes a double extension to disguise an executable as a document.",
    severity: "critical",
    weight: 45,
    confidence: 0.99,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const lower = ctx.path.toLowerCase();
      if (/\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|bat|cmd|vbs|ps1|apk|jar|msi)$/i.test(lower)) {
        return {
          ruleId: "PTH-002",
          ruleCode: "PTH-DOUBLE-EXTENSION",
          category: "path",
          name: "Double File Extension Deception (e.g. invoice.pdf.exe)",
          description: "Double extension masquerading an executable payload as a document.",
          severity: "critical",
          weight: 45,
          confidence: 0.99,
          evidence: `Path: ${ctx.path}`,
          matchedString: ctx.path,
          whyItMatters: "Windows default settings hide known file extensions. A file named 'invoice.pdf.exe' appears to the victim as 'invoice.pdf', leading them to click what they believe is an innocent PDF document.",
          realWorldTechnique: "MITRE ATT&CK T1036.007: Double File Extension masquerading.",
          recommendedAction: "Block URL and alert incident responders. High-confidence targeted malware delivery.",
          references: ["MITRE ATT&CK T1036.007", "CISA Malicious File Extensions"],
          tags: ["double-extension", "masquerade", "t1036", "malware"],
        };
      }
      return null;
    },
    whyItMatters: "Double extensions exploit default Windows shell settings to trick victims into executing malware.",
    realWorldTechnique: "MITRE ATT&CK T1036.007 Double Extension.",
    recommendedAction: "Block immediately.",
    references: ["MITRE ATT&CK T1036.007"],
    tags: ["double-extension", "malware"],
  },
  {
    id: "PTH-003",
    category: "path",
    name: "Administrative CMS Login Path (/wp-admin, /cpanel)",
    description: "Path targets web content management or server control panels.",
    severity: "medium",
    weight: 15,
    confidence: 0.85,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const lower = ctx.path.toLowerCase();
      if (lower.includes("/wp-login.php") || lower.includes("/wp-admin") || lower.includes("/cpanel")) {
        return {
          ruleId: "PTH-003",
          ruleCode: "PTH-CMS-ADMIN",
          category: "path",
          name: "Administrative CMS Login Path (/wp-admin, /cpanel)",
          description: "URL points to administrative portal on potentially compromised site.",
          severity: "medium",
          weight: 15,
          confidence: 0.85,
          evidence: `Path contains CMS admin endpoint: ${ctx.path}`,
          matchedString: ctx.path,
          whyItMatters: "Compromised WordPress blogs and shared hosting cPanels are frequently repurposed by threat actors to host phishing landing pages or brute-force portals.",
          realWorldTechnique: "Hosting phishing kits on compromised legitimate CMS platforms.",
          recommendedAction: "Verify if this domain was compromised by inspecting parent company ownership.",
          references: ["OWASP Top 10 A01: Broken Access Control"],
          tags: ["cms", "cpanel", "wordpress", "compromised"],
        };
      }
      return null;
    },
    whyItMatters: "Compromised WordPress sites host phishing kits in administrative subdirectories.",
    realWorldTechnique: "Abuses compromised third-party websites to bypass domain reputation.",
    recommendedAction: "Verify site owner.",
    references: ["OWASP A01"],
    tags: ["cms", "wordpress"],
  },
  {
    id: "PTH-004",
    category: "path",
    name: "Sensitive Configuration File Exposure Target (/.env, /.git)",
    description: "Path requests sensitive credentials, secrets, or source control metadata.",
    severity: "critical",
    weight: 35,
    confidence: 0.95,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const lower = ctx.path.toLowerCase();
      const matched = SENSITIVE_PATHS.find((sp) => lower.includes(sp));
      if (matched) {
        return {
          ruleId: "PTH-004",
          ruleCode: "PTH-SENSITIVE-CONFIG",
          category: "path",
          name: "Sensitive Configuration File Exposure Target (/.env, /.git)",
          description: `URL attempts to probe or retrieve sensitive configuration (${matched}).`,
          severity: "critical",
          weight: 35,
          confidence: 0.95,
          evidence: `Sensitive path: ${matched}`,
          matchedString: matched,
          whyItMatters: "Probing for .env, .git, or AWS credentials indicates active reconnaissance or automated vulnerability harvesting.",
          realWorldTechnique: "MITRE ATT&CK T1552.001: Credentials in Files.",
          recommendedAction: "Block IP and audit web server directory listing permissions.",
          references: ["MITRE ATT&CK T1552.001", "CWE-538: File and Directory Information Exposure"],
          tags: ["reconnaissance", "env", "git", "secrets"],
        };
      }
      return null;
    },
    whyItMatters: "Requests for .env or .git repositories attempt to harvest database credentials and API keys.",
    realWorldTechnique: "Automated secret harvesting.",
    recommendedAction: "Block scanning client.",
    references: ["MITRE ATT&CK T1552.001"],
    tags: ["secrets", "reconnaissance"],
  },
  {
    id: "PTH-005",
    category: "path",
    name: "SSL Validation Abuse Path (/.well-known/pki-validation/)",
    description: "Path targets automated ACME or PKI certificate challenge paths inappropriately.",
    severity: "medium",
    weight: 20,
    confidence: 0.88,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.path.toLowerCase().includes("/.well-known/pki-validation/")) {
        return {
          ruleId: "PTH-005",
          ruleCode: "PTH-PKI-ABUSE",
          category: "path",
          name: "SSL Validation Abuse Path (/.well-known/pki-validation/)",
          description: "Deep path points inside SSL validation directory.",
          severity: "medium",
          weight: 20,
          confidence: 0.88,
          evidence: "PKI validation directory present",
          matchedString: "/.well-known/pki-validation/",
          whyItMatters: "Attackers drop phishing kits into hidden '.well-known' directories on compromised web servers because site owners rarely audit hidden configuration folders.",
          realWorldTechnique: "Concealed directory residency on compromised web servers.",
          recommendedAction: "Inspect web server file integrity.",
          references: ["RFC 8555 (ACME)", "APWG Phishing Techniques"],
          tags: ["acme", "ssl-abuse", "hidden-path"],
        };
      }
      return null;
    },
    whyItMatters: "Phishers hide kits inside '.well-known' folders to evade webmaster detection.",
    realWorldTechnique: "Stealth directory residency.",
    recommendedAction: "Audit server files.",
    references: ["RFC 8555"],
    tags: ["ssl-abuse", "hidden-path"],
  },
  {
    id: "PTH-006",
    category: "path",
    name: "Directory Traversal Sequence (../ or ..\\)",
    description: "The path contains directory traversal sequences attempting to break out of web roots.",
    severity: "critical",
    weight: 35,
    confidence: 0.98,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.path.includes("../") || ctx.path.includes("..\\") || ctx.rawUrl.includes("%2e%2e")) {
        return {
          ruleId: "PTH-006",
          ruleCode: "PTH-TRAVERSAL",
          category: "path",
          name: "Directory Traversal Sequence (../ or ..\\)",
          description: "Path traversal sequence detected in URL string.",
          severity: "critical",
          weight: 35,
          confidence: 0.98,
          evidence: "Traversal sequence '../' or '..\\' detected",
          matchedString: "../",
          whyItMatters: "Directory traversal allows attackers to escape designated web server directories and access arbitrary system files.",
          realWorldTechnique: "CWE-22: Improper Limitation of a Pathname to a Restricted Directory.",
          recommendedAction: "Block request and inspect application input validation.",
          references: ["OWASP Path Traversal", "CWE-22"],
          tags: ["traversal", "cwe22", "exploit"],
        };
      }
      return null;
    },
    whyItMatters: "Directory traversal attempts to read unauthorized system files from the web server.",
    realWorldTechnique: "Path traversal exploit.",
    recommendedAction: "Reject request.",
    references: ["OWASP Path Traversal"],
    tags: ["traversal", "exploit"],
  },
  {
    id: "PTH-007",
    category: "path",
    name: "Excessive Path Depth (> 5 Segments)",
    description: "The URL path contains 6 or more nested directory levels.",
    severity: "low",
    weight: 10,
    confidence: 0.78,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.pathSegments.length > 5 && !ctx.isAllowlisted) {
        return {
          ruleId: "PTH-007",
          ruleCode: "PTH-DEPTH-EXCESSIVE",
          category: "path",
          name: "Excessive Path Depth (> 5 Segments)",
          description: `Path has deep nesting (${ctx.pathSegments.length} levels).`,
          severity: "low",
          weight: 10,
          confidence: 0.78,
          evidence: `Path levels: ${ctx.pathSegments.length}`,
          matchedString: ctx.path,
          whyItMatters: "Deep directory hierarchies are used to bury phishing kits inside obscure subfolders on compromised servers.",
          realWorldTechnique: "Obscured path nesting to evade webmaster deletion.",
          recommendedAction: "Inspect the root domain identity.",
          references: ["APWG"],
          tags: ["path-depth", "nesting"],
        };
      }
      return null;
    },
    whyItMatters: "Deep paths hide phishing scripts inside complex directory structures.",
    realWorldTechnique: "Obscured directory hosting.",
    recommendedAction: "Check apex domain.",
    references: ["APWG"],
    tags: ["path-depth"],
  },
  {
    id: "PTH-008",
    category: "path",
    name: "Excessive Path Length (> 80 characters)",
    description: "The path string alone exceeds 80 characters in length.",
    severity: "low",
    weight: 8,
    confidence: 0.75,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.path.length > 80 && !ctx.isAllowlisted) {
        return {
          ruleId: "PTH-008",
          ruleCode: "PTH-LEN-80",
          category: "path",
          name: "Excessive Path Length (> 80 characters)",
          description: `Path length is ${ctx.path.length} characters.`,
          severity: "low",
          weight: 8,
          confidence: 0.75,
          evidence: `Path length: ${ctx.path.length}`,
          matchedString: ctx.path.substring(0, 30) + "...",
          whyItMatters: "Long paths contribute to visual address bar truncation on mobile screens.",
          realWorldTechnique: "Address bar padding.",
          recommendedAction: "Inspect full URL.",
          references: ["RFC 3986"],
          tags: ["length", "path"],
        };
      }
      return null;
    },
    whyItMatters: "Long paths push suspicious parameters out of mobile browser views.",
    realWorldTechnique: "Mobile address bar truncation.",
    recommendedAction: "Inspect full URL string.",
    references: ["RFC 3986"],
    tags: ["path-length"],
  },
  {
    id: "PTH-009",
    category: "path",
    name: "Consecutive Path Slashes (///)",
    description: "URL path contains 3 or more consecutive forward slashes.",
    severity: "medium",
    weight: 15,
    confidence: 0.88,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (/\/{3,}/.test(ctx.path)) {
        return {
          ruleId: "PTH-009",
          ruleCode: "PTH-CONSECUTIVE-SLASHES",
          category: "path",
          name: "Consecutive Path Slashes (///)",
          description: "Multiple redundant forward slashes in path.",
          severity: "medium",
          weight: 15,
          confidence: 0.88,
          evidence: "Redundant slashes in path",
          matchedString: "///",
          whyItMatters: "Redundant slashes bypass naive reverse proxy path ACLs while being collapsed into a single slash by backend application frameworks.",
          realWorldTechnique: "URL normalization bypass.",
          recommendedAction: "Normalize path before access control evaluation.",
          references: ["OWASP URL Normalization Cheatsheet", "CWE-1286"],
          tags: ["slashes", "normalization-bypass"],
        };
      }
      return null;
    },
    whyItMatters: "Consecutive slashes bypass naive proxy authorization rules.",
    realWorldTechnique: "Reverse proxy authorization bypass.",
    recommendedAction: "Normalize paths in middleware.",
    references: ["OWASP Normalization"],
    tags: ["slashes"],
  },
  {
    id: "PTH-010",
    category: "path",
    name: "Trailing Dot in File Extension",
    description: "The path ends with a dot following the file extension (e.g. 'doc.exe.').",
    severity: "high",
    weight: 25,
    confidence: 0.95,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (/\.[a-z0-9]+\.$/i.test(ctx.path)) {
        return {
          ruleId: "PTH-010",
          ruleCode: "PTH-TRAILING-DOT-FILE",
          category: "path",
          name: "Trailing Dot in File Extension",
          description: "File extension ends with trailing dot anomaly.",
          severity: "high",
          weight: 25,
          confidence: 0.95,
          evidence: `Path: ${ctx.path}`,
          matchedString: ctx.path,
          whyItMatters: "Windows file systems automatically strip trailing dots. Attackers use this to bypass extension filters that check for '.exe'.",
          realWorldTechnique: "File extension filter bypass using Windows NTFS dot stripping.",
          recommendedAction: "Strip trailing dots before evaluating file extensions.",
          references: ["CWE-20: Improper Input Validation"],
          tags: ["trailing-dot", "ntfs", "filter-bypass"],
        };
      }
      return null;
    },
    whyItMatters: "Trailing dots exploit Windows NTFS filename normalization to bypass extension blocks.",
    realWorldTechnique: "NTFS filename filter bypass.",
    recommendedAction: "Block download.",
    references: ["CWE-20"],
    tags: ["trailing-dot"],
  },
  {
    id: "PTH-011",
    category: "path",
    name: "Compressed Archive with Invoice / Financial Name",
    description: "Path links to a zip, rar, or 7z archive combined with financial keywords.",
    severity: "high",
    weight: 30,
    confidence: 0.94,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const lower = ctx.path.toLowerCase();
      if (/\.(zip|rar|7z|tar\.gz)$/i.test(lower)) {
        const hasFin = ["invoice", "statement", "payment", "receipt", "order", "document"].some((w) =>
          lower.includes(w)
        );
        if (hasFin) {
          return {
            ruleId: "PTH-011",
            ruleCode: "PTH-ARCHIVE-FINANCIAL",
            category: "path",
            name: "Compressed Archive with Invoice / Financial Name",
            description: `Compressed archive file named with financial lure (${ctx.path}).`,
            severity: "high",
            weight: 30,
            confidence: 0.94,
            evidence: `Path: ${ctx.path}`,
            matchedString: ctx.path,
            whyItMatters: "Zip and RAR files containing password-protected archives or nested executables bypass email gateway content filters to deliver ransomware droppers.",
            realWorldTechnique: "Archive-based payload delivery in Business Email Compromise.",
            recommendedAction: "Do NOT extract or open this archive without sandbox inspection.",
            references: ["CISA Ransomware Best Practices Guide"],
            tags: ["archive", "zip", "ransomware", "bec"],
          };
        }
      }
      return null;
    },
    whyItMatters: "Archives containing financial names are primary vehicles for ransomware droppers.",
    realWorldTechnique: "Archive payload delivery in BEC scams.",
    recommendedAction: "Sandboxed inspection only.",
    references: ["CISA Ransomware Guide"],
    tags: ["archive", "ransomware"],
  },
  {
    id: "PTH-012",
    category: "path",
    name: "Visual Space Padding in Path",
    description: "Path contains repeated spaces or percent-encoded %20 sequences.",
    severity: "medium",
    weight: 20,
    confidence: 0.88,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.rawUrl.includes("%20%20") || ctx.rawUrl.includes("  ")) {
        return {
          ruleId: "PTH-012",
          ruleCode: "PTH-SPACE-PADDING",
          category: "path",
          name: "Visual Space Padding in Path",
          description: "Multiple consecutive spaces or %20 sequences in URL.",
          severity: "medium",
          weight: 20,
          confidence: 0.88,
          evidence: "Repeated spaces or %20 found",
          matchedString: "%20%20",
          whyItMatters: "Repeated spaces force the browser address bar to truncate, visually severing the legitimate-looking prefix from the actual file extension.",
          realWorldTechnique: "Visual truncation attack.",
          recommendedAction: "Examine the ending of the URL path.",
          references: ["APWG"],
          tags: ["padding", "truncation", "visual-spoofing"],
        };
      }
      return null;
    },
    whyItMatters: "Spaces push malicious extensions out of address bar viewports.",
    realWorldTechnique: "Visual truncation in mobile browsers.",
    recommendedAction: "Inspect full URL string.",
    references: ["APWG"],
    tags: ["padding", "truncation"],
  },
];
