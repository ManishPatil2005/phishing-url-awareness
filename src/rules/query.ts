import type { Rule, RuleFinding, ParsedUrlContext } from "./types.ts";

const REDIRECT_PARAM_KEYS = new Set([
  "redirect", "redirect_uri", "redirect_url", "url", "next", "dest", "destination",
  "target", "return", "return_url", "r", "link", "go", "goto", "out"
]);

const SENSITIVE_CRED_KEYS = new Set([
  "password", "passwd", "pwd", "secret", "passcode", "auth_token"
]);

const TOKEN_PARAM_KEYS = new Set([
  "token", "apikey", "api_key", "access_token", "secret_key", "bearer"
]);

export const queryRules: Rule[] = [
  {
    id: "QRY-001",
    category: "query",
    name: "Open Redirect Parameter Present",
    description: "Query contains parameter keys known to facilitate open redirects.",
    severity: "medium",
    weight: 20,
    confidence: 0.88,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      for (const [key, val] of Object.entries(ctx.queryParams)) {
        if (REDIRECT_PARAM_KEYS.has(key.toLowerCase())) {
          return {
            ruleId: "QRY-001",
            ruleCode: "QRY-OPEN-REDIRECT-KEY",
            category: "query",
            name: "Open Redirect Parameter Present",
            description: `Query parameter '${key}' commonly used to steer victims to third-party destinations.`,
            severity: "medium",
            weight: 20,
            confidence: 0.88,
            evidence: `Parameter: ${key}=${val.substring(0, 30)}`,
            matchedString: key,
            whyItMatters: "Open redirects allow attackers to abuse legitimate domain trust (e.g. 'https://trusted-site.com?redirect=http://evil.com'). Victims trust the initial domain, but are automatically forwarded to a malicious landing site.",
            realWorldTechnique: "CWE-601: URL Redirection to Untrusted Site ('Open Redirect').",
            recommendedAction: "Inspect the destination value before proceeding through intermediate redirect links.",
            references: ["OWASP Open Redirect Prevention Cheat Sheet", "CWE-601"],
            tags: ["redirect", "open-redirect", "cwe601", "query"],
          };
        }
      }
      return null;
    },
    whyItMatters: "Open redirects leverage trusted domains to bounce users to attacker-controlled phishing pages.",
    realWorldTechnique: "CWE-601 Open Redirect.",
    recommendedAction: "Check target destination inside query parameter.",
    references: ["OWASP Open Redirect"],
    tags: ["open-redirect", "query"],
  },
  {
    id: "QRY-002",
    category: "query",
    name: "Open Redirect Target with External Protocol (http:// or https://)",
    description: "Query parameter value contains an explicit secondary web protocol scheme.",
    severity: "high",
    weight: 30,
    confidence: 0.95,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      for (const [key, val] of Object.entries(ctx.queryParams)) {
        if (REDIRECT_PARAM_KEYS.has(key.toLowerCase()) && /^https?:\/\//i.test(val)) {
          return {
            ruleId: "QRY-002",
            ruleCode: "QRY-REDIRECT-SCHEME",
            category: "query",
            name: "Open Redirect Target with External Protocol (http:// or https://)",
            description: `Parameter '${key}' points explicitly to external web destination '${val}'.`,
            severity: "high",
            weight: 30,
            confidence: 0.95,
            evidence: `${key}=${val}`,
            matchedString: val,
            whyItMatters: "An absolute external URL in a redirect parameter confirms that clicking this link will immediately navigate the user away from the displayed domain to a foreign server.",
            realWorldTechnique: "Active Open Redirect exploitation for phishing landing page delivery.",
            recommendedAction: "Do NOT click. The link will navigate you to the destination specified inside the parameter.",
            references: ["MITRE ATT&CK T1566.002", "OWASP A01:2021"],
            tags: ["open-redirect", "phishing-delivery", "cwe601"],
          };
        }
      }
      return null;
    },
    whyItMatters: "An absolute URL inside a redirect parameter will forward user traffic to a foreign site.",
    realWorldTechnique: "Active Open Redirect exploitation.",
    recommendedAction: "Do not navigate.",
    references: ["MITRE ATT&CK T1566.002"],
    tags: ["open-redirect"],
  },
  {
    id: "QRY-003",
    category: "query",
    name: "Plaintext Password Exposed in Query String",
    description: "URL passes authentication passwords in the clear query string.",
    severity: "critical",
    weight: 35,
    confidence: 0.98,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      for (const key of Object.keys(ctx.queryParams)) {
        if (SENSITIVE_CRED_KEYS.has(key.toLowerCase())) {
          return {
            ruleId: "QRY-003",
            ruleCode: "QRY-PASSWORD-EXPOSED",
            category: "query",
            name: "Plaintext Password Exposed in Query String",
            description: `Credential parameter '${key}' exposed in cleartext query string.`,
            severity: "critical",
            weight: 35,
            confidence: 0.98,
            evidence: `Exposed parameter: ${key}`,
            matchedString: key,
            whyItMatters: "Query strings are saved in browser history, web server access logs, proxy logs, and sent in HTTP Referer headers. Exposing passwords in query strings guarantees credential leakage.",
            realWorldTechnique: "CWE-598: Use of GET Request Method with Sensitive Query Strings.",
            recommendedAction: "Never submit credentials via GET query parameters.",
            references: ["CWE-598", "OWASP Top 10 A02: Cryptographic Failures"],
            tags: ["credentials", "password-leak", "cwe598"],
          };
        }
      }
      return null;
    },
    whyItMatters: "Query parameters are logged across all proxy and browser logs, leaking passwords.",
    realWorldTechnique: "CWE-598 Sensitive Data in GET Query.",
    recommendedAction: "Never pass secrets via URL query.",
    references: ["CWE-598"],
    tags: ["credentials", "password"],
  },
  {
    id: "QRY-004",
    category: "query",
    name: "API Secret Key or Access Token in Query",
    description: "URL transmits API secret tokens or bearer keys in clear query parameters.",
    severity: "high",
    weight: 25,
    confidence: 0.92,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      for (const key of Object.keys(ctx.queryParams)) {
        if (TOKEN_PARAM_KEYS.has(key.toLowerCase())) {
          return {
            ruleId: "QRY-004",
            ruleCode: "QRY-API-TOKEN-EXPOSED",
            category: "query",
            name: "API Secret Key or Access Token in Query",
            description: `Secret token parameter '${key}' exposed in URL.`,
            severity: "high",
            weight: 25,
            confidence: 0.92,
            evidence: `Parameter: ${key}`,
            matchedString: key,
            whyItMatters: "Leaked tokens allow attackers to authenticate as legitimate users or access administrative APIs without needing passwords.",
            realWorldTechnique: "Token harvesting from web server access logs.",
            recommendedAction: "Transmit authentication tokens exclusively in HTTP Authorization headers.",
            references: ["RFC 6750 (OAuth Bearer)", "CWE-598"],
            tags: ["token", "api-key", "leakage"],
          };
        }
      }
      return null;
    },
    whyItMatters: "Exposes API secrets to log files and proxy intercepts.",
    realWorldTechnique: "Token harvesting from server logs.",
    recommendedAction: "Use Authorization headers.",
    references: ["RFC 6750"],
    tags: ["token", "api-key"],
  },
  {
    id: "QRY-005",
    category: "query",
    name: "Victim Email Pre-fill Parameter",
    description: "Query contains victim email addresses designed to populate phishing forms.",
    severity: "high",
    weight: 25,
    confidence: 0.94,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      for (const [key, val] of Object.entries(ctx.queryParams)) {
        if (["email", "user", "mail", "recipient", "account"].includes(key.toLowerCase())) {
          if (val.includes("@") || /^[a-zA-Z0-9._%+-]+%40[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/i.test(val)) {
            return {
              ruleId: "QRY-005",
              ruleCode: "QRY-VICTIM-EMAIL",
              category: "query",
              name: "Victim Email Pre-fill Parameter",
              description: `Victim email parameter '${key}' pre-populated in link.`,
              severity: "high",
              weight: 25,
              confidence: 0.94,
              evidence: `Parameter ${key} contains email format`,
              matchedString: key,
              whyItMatters: "Targeted spear-phishing campaigns pre-fill the victim's email address in the fake login form to make the site appear customized and legitimate.",
              realWorldTechnique: "Targeted spear-phishing personalization (MITRE ATT&CK T1566.002).",
              recommendedAction: "Recognize that this link was customized specifically for you by an external sender.",
              references: ["MITRE ATT&CK T1566.002", "APWG Spear Phishing Trends"],
              tags: ["spear-phishing", "victim-email", "personalization"],
            };
          }
        }
      }
      return null;
    },
    whyItMatters: "Pre-filled emails are standard spear-phishing tactics to increase victim trust.",
    realWorldTechnique: "Targeted spear-phishing personalization.",
    recommendedAction: "Exercise high caution on pre-filled links.",
    references: ["MITRE ATT&CK T1566.002"],
    tags: ["spear-phishing", "email"],
  },
  {
    id: "QRY-006",
    category: "query",
    name: "Excessive Query String Length (> 100 characters)",
    description: "The query string exceeds 100 characters in length.",
    severity: "low",
    weight: 8,
    confidence: 0.75,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.query.length > 100 && !ctx.isAllowlisted) {
        return {
          ruleId: "QRY-006",
          ruleCode: "QRY-LEN-100",
          category: "query",
          name: "Excessive Query String Length (> 100 characters)",
          description: `Query length is ${ctx.query.length} characters.`,
          severity: "low",
          weight: 8,
          confidence: 0.75,
          evidence: `Query length: ${ctx.query.length}`,
          matchedString: ctx.query.substring(0, 30) + "...",
          whyItMatters: "Long query strings are often used to pass serialized state or tracking telemetry.",
          realWorldTechnique: "State stuffing and tracking token transmission.",
          recommendedAction: "Inspect embedded parameters.",
          references: ["RFC 3986"],
          tags: ["query-length", "tracking"],
        };
      }
      return null;
    },
    whyItMatters: "Excessive query lengths carry heavy tracking or obfuscated payloads.",
    realWorldTechnique: "Serialized payload transport.",
    recommendedAction: "Review query keys.",
    references: ["RFC 3986"],
    tags: ["query-length"],
  },
  {
    id: "QRY-007",
    category: "query",
    name: "Base64 or Encoded Data Blob in Query Parameter",
    description: "Query parameter value contains a long base64 or hex encoded data block.",
    severity: "medium",
    weight: 18,
    confidence: 0.88,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      for (const [key, val] of Object.entries(ctx.queryParams)) {
        if (val.length >= 32 && /^[a-zA-Z0-9+/=_-]{32,}$/.test(val) && !ctx.isAllowlisted) {
          return {
            ruleId: "QRY-007",
            ruleCode: "QRY-BASE64-BLOB",
            category: "query",
            name: "Base64 or Encoded Data Blob in Query Parameter",
            description: `Parameter '${key}' carries encoded data blob (${val.length} chars).`,
            severity: "medium",
            weight: 18,
            confidence: 0.88,
            evidence: `${key}=${val.substring(0, 24)}...`,
            matchedString: val,
            whyItMatters: "Base64 payloads in query parameters often conceal secondary redirect URLs or encoded victim identifiers.",
            realWorldTechnique: "Payload obfuscation in URL query.",
            recommendedAction: "Decode the parameter value to reveal transmitted contents.",
            references: ["APWG Obfuscation Taxonomy"],
            tags: ["base64", "query", "obfuscation"],
          };
        }
      }
      return null;
    },
    whyItMatters: "Base64 query values conceal target URLs or victim telemetry.",
    realWorldTechnique: "Payload obfuscation in query parameters.",
    recommendedAction: "Decode parameter string.",
    references: ["APWG"],
    tags: ["base64", "query"],
  },
  {
    id: "QRY-008",
    category: "query",
    name: "Script Protocol or Data URI in Query (javascript:, data:)",
    description: "Query parameter contains 'javascript:' or 'data:' URI schemes.",
    severity: "critical",
    weight: 40,
    confidence: 0.98,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (/javascript:|data:text\/html/i.test(ctx.query)) {
        return {
          ruleId: "QRY-008",
          ruleCode: "QRY-XSS-SCHEME",
          category: "query",
          name: "Script Protocol or Data URI in Query (javascript:, data:)",
          description: "Executable script scheme (javascript:/data:) embedded in query string.",
          severity: "critical",
          weight: 40,
          confidence: 0.98,
          evidence: "Script scheme present in query string",
          matchedString: "javascript:",
          whyItMatters: "Indicates an active Cross-Site Scripting (XSS) or DOM-based execution exploit designed to execute arbitrary JavaScript in the victim's session.",
          realWorldTechnique: "CWE-79: Cross-site Scripting via JavaScript URI injection.",
          recommendedAction: "Block immediately. Active exploit vector.",
          references: ["OWASP XSS Prevention Cheat Sheet", "CWE-79"],
          tags: ["xss", "javascript", "exploit", "cwe79"],
        };
      }
      return null;
    },
    whyItMatters: "Script schemes execute arbitrary JavaScript in victim browsers.",
    realWorldTechnique: "CWE-79 Cross-Site Scripting via URI injection.",
    recommendedAction: "Block URL.",
    references: ["OWASP XSS"],
    tags: ["xss", "exploit"],
  },
  {
    id: "QRY-009",
    category: "query",
    name: "High Query Parameter Count (>= 8 parameters)",
    description: "The URL carries 8 or more distinct query parameters.",
    severity: "low",
    weight: 8,
    confidence: 0.70,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      const keys = Object.keys(ctx.queryParams);
      if (keys.length >= 8 && !ctx.isAllowlisted) {
        return {
          ruleId: "QRY-009",
          ruleCode: "QRY-PARAM-COUNT-HIGH",
          category: "query",
          name: "High Query Parameter Count (>= 8 parameters)",
          description: `URL contains ${keys.length} query parameters.`,
          severity: "low",
          weight: 8,
          confidence: 0.70,
          evidence: `Parameter count: ${keys.length}`,
          matchedString: keys.join(", "),
          whyItMatters: "High parameter counts are often used for invasive multi-touch telemetry or fingerprinting.",
          realWorldTechnique: "Ad-tracker telemetry and fingerprinting.",
          recommendedAction: "Review parameters before navigating.",
          references: ["RFC 3986"],
          tags: ["parameters", "tracking"],
        };
      }
      return null;
    },
    whyItMatters: "High parameter density correlates with fingerprinting and tracking chains.",
    realWorldTechnique: "Device fingerprinting via query.",
    recommendedAction: "Inspect query contents.",
    references: ["RFC 3986"],
    tags: ["tracking"],
  },
  {
    id: "QRY-010",
    category: "query",
    name: "SQL Injection Probe Syntax in Query",
    description: "Query parameter includes SQL meta-characters or keywords (UNION SELECT, OR '1'='1').",
    severity: "critical",
    weight: 35,
    confidence: 0.95,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (/('|\%27)\s*(or|and)\s*('|\%27|1=1)|union\s+select|select\s+.*\s+from/i.test(ctx.query)) {
        return {
          ruleId: "QRY-010",
          ruleCode: "QRY-SQLI-PROBE",
          category: "query",
          name: "SQL Injection Probe Syntax in Query",
          description: "SQL injection syntax detected in query parameter.",
          severity: "critical",
          weight: 35,
          confidence: 0.95,
          evidence: "SQL meta-characters in query string",
          matchedString: "union select",
          whyItMatters: "Indicates an active SQL injection attack targeting backend databases to extract user records.",
          realWorldTechnique: "CWE-89: SQL Injection.",
          recommendedAction: "Block request at WAF level and alert application security team.",
          references: ["OWASP SQL Injection Prevention", "CWE-89"],
          tags: ["sqli", "exploit", "cwe89"],
        };
      }
      return null;
    },
    whyItMatters: "SQL syntax in query strings indicates database exploitation attempts.",
    realWorldTechnique: "CWE-89 SQL Injection.",
    recommendedAction: "Block request.",
    references: ["OWASP SQLi"],
    tags: ["sqli", "exploit"],
  },
  {
    id: "QRY-011",
    category: "query",
    name: "HTML / XSS Tag Injection in Query (<script>, <img>)",
    description: "Query contains HTML opening tags or event handlers.",
    severity: "critical",
    weight: 40,
    confidence: 0.98,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (/<script|<img|onerror=|onload=|alert\(/i.test(ctx.query)) {
        return {
          ruleId: "QRY-011",
          ruleCode: "QRY-HTML-XSS",
          category: "query",
          name: "HTML / XSS Tag Injection in Query (<script>, <img>)",
          description: "Raw HTML tag or JavaScript event handler detected in query.",
          severity: "critical",
          weight: 40,
          confidence: 0.98,
          evidence: "HTML tag / handler in query",
          matchedString: "<script",
          whyItMatters: "Reflected XSS attacks inject malicious script tags into query parameters to steal session tokens when clicked.",
          realWorldTechnique: "CWE-79: Reflected Cross-Site Scripting.",
          recommendedAction: "Never click links containing HTML tags or event handlers in query strings.",
          references: ["OWASP Top 10 A03: Injection", "CWE-79"],
          tags: ["xss", "injection", "cwe79"],
        };
      }
      return null;
    },
    whyItMatters: "HTML tags in URLs reflect into web pages to steal authentication cookies.",
    realWorldTechnique: "Reflected Cross-Site Scripting.",
    recommendedAction: "Block link.",
    references: ["OWASP XSS"],
    tags: ["xss", "injection"],
  },
  {
    id: "QRY-012",
    category: "query",
    name: "Chat Bot / Webhook Exfiltration Parameter in Query",
    description: "Query points to Discord webhooks or Telegram bot APIs for data exfiltration.",
    severity: "critical",
    weight: 40,
    confidence: 0.98,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (/discord(app)?\.com\/api\/webhooks|api\.telegram\.org\/bot/i.test(ctx.query)) {
        return {
          ruleId: "QRY-012",
          ruleCode: "QRY-WEBHOOK-EXFIL",
          category: "query",
          name: "Chat Bot / Webhook Exfiltration Parameter in Query",
          description: "Webhook exfiltration channel (Telegram/Discord) present in URL.",
          severity: "critical",
          weight: 40,
          confidence: 0.98,
          evidence: "Exfiltration webhook in query parameter",
          matchedString: "webhook",
          whyItMatters: "Phishing kits frequently exfiltrate harvested credentials directly to private Telegram bots or Discord webhook channels in real-time.",
          realWorldTechnique: "MITRE ATT&CK T1567.002: Exfiltration to Cloud Storage / Webhook.",
          recommendedAction: "Block webhook endpoint and report to platform abuse team.",
          references: ["MITRE ATT&CK T1567.002", "APWG Phishing Kit Analysis"],
          tags: ["webhook", "telegram", "discord", "exfiltration"],
        };
      }
      return null;
    },
    whyItMatters: "Phishing kits exfiltrate stolen credentials to chat bots.",
    realWorldTechnique: "MITRE ATT&CK T1567.002 Exfiltration to Webhook.",
    recommendedAction: "Report webhook to Discord/Telegram abuse.",
    references: ["MITRE ATT&CK T1567.002"],
    tags: ["exfiltration", "webhook"],
  },
];
