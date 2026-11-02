import type { Rule, RuleFinding, ParsedUrlContext } from "./types.ts";

export const lexicalRules: Rule[] = [
  {
    id: "LEX-001",
    category: "lexical",
    name: "Credential Harvesting Keyword (login, signin, password)",
    description: "URL contains discrete authentication tokens designed to harvest credentials.",
    severity: "high",
    weight: 25,
    confidence: 0.92,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const targets = ["login", "signin", "sign-in", "log-in", "password", "passcode", "credential"];
      const matched = ctx.allTokens.find((t) => targets.includes(t));
      if (matched) {
        return {
          ruleId: "LEX-001",
          ruleCode: "H7-KEYWORD-LOGIN",
          category: "lexical",
          name: "Credential Harvesting Keyword (login, signin, password)",
          description: `Authentication lure keyword '${matched}' detected.`,
          severity: "high",
          weight: 25,
          confidence: 0.92,
          evidence: `Keyword matched: '${matched}'`,
          matchedString: matched,
          whyItMatters: "Phishing links overwhelmingly simulate authentication portals. When coupled with an unknown host, login tokens indicate deceptive credential collection.",
          realWorldTechnique: "MITRE ATT&CK T1566.002: Lures directing users to credential-harvesting landing pages.",
          recommendedAction: "Do not provide usernames or passwords. Navigate to the service directly via bookmark or official app.",
          references: ["MITRE ATT&CK T1566.002", "OWASP Phishing Defense"],
          tags: ["lexical", "credential", "login", "harvesting"],
        };
      }
      return null;
    },
    whyItMatters: "Login keywords on unverified domains are primary indicators of credential harvesting.",
    realWorldTechnique: "Captures user passwords through fake sign-in portals.",
    recommendedAction: "Never type credentials on links from emails or messages.",
    references: ["MITRE ATT&CK T1566"],
    tags: ["login", "credentials"],
  },
  {
    id: "LEX-002",
    category: "lexical",
    name: "Account & Verification Keyword (verify, account, secure)",
    description: "URL contains tokens that mimic security verification or account validation.",
    severity: "medium",
    weight: 20,
    confidence: 0.88,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const targets = ["verify", "verification", "account", "authenticate", "portal", "secure", "validate"];
      const matched = ctx.allTokens.find((t) => targets.includes(t));
      if (matched) {
        return {
          ruleId: "LEX-002",
          ruleCode: "H7-KEYWORD-VERIFY",
          category: "lexical",
          name: "Account & Verification Keyword (verify, account, secure)",
          description: `Security verification keyword '${matched}' detected.`,
          severity: "medium",
          weight: 20,
          confidence: 0.88,
          evidence: `Keyword matched: '${matched}'`,
          matchedString: matched,
          whyItMatters: "Attackers manufacture false urgency claiming the victim's account is suspended and requires immediate 'verification' or 'security validation'.",
          realWorldTechnique: "Social engineering appeal to security authority.",
          recommendedAction: "Check account status directly within the official mobile app or desktop website.",
          references: ["FBI IC3 Annual Report", "CISA Social Engineering"],
          tags: ["lexical", "verify", "account", "social-engineering"],
        };
      }
      return null;
    },
    whyItMatters: "Verification tokens trick victims into believing security validation is required.",
    realWorldTechnique: "False security alerts.",
    recommendedAction: "Check official portal directly.",
    references: ["CISA Social Engineering"],
    tags: ["verification", "account"],
  },
  {
    id: "LEX-003",
    category: "lexical",
    name: "Financial & Banking Keyword (banking, invoice, payment)",
    description: "URL contains discrete financial and monetary keywords.",
    severity: "high",
    weight: 25,
    confidence: 0.90,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const targets = ["banking", "bank", "invoice", "billing", "payment", "payout", "payroll", "transfer", "refund", "wire"];
      const searchTokens = [...ctx.hostTokens, ...ctx.pathTokens, ...Object.keys(ctx.queryParams)];
      const matched = searchTokens.find((t) => targets.includes(t));
      if (matched) {
        return {
          ruleId: "LEX-003",
          ruleCode: "H7-KEYWORD-BANKING",
          category: "lexical",
          name: "Financial & Banking Keyword (banking, invoice, payment)",
          description: `Financial keyword '${matched}' detected in unverified link.`,
          severity: "high",
          weight: 25,
          confidence: 0.90,
          evidence: `Financial token: '${matched}'`,
          matchedString: matched,
          whyItMatters: "Financial lures exploit curiosity or fear regarding invoices, pending payments, or bank account issues to coerce immediate user action.",
          realWorldTechnique: "Business Email Compromise (BEC) and fake invoice scams.",
          recommendedAction: "Verify with accounts payable or bank directly through established out-of-band channels.",
          references: ["FBI IC3 BEC Advisory", "MITRE ATT&CK T1566.001"],
          tags: ["financial", "banking", "bec", "invoice"],
        };
      }
      return null;
    },
    whyItMatters: "Financial lures coerce victims into revealing bank or payment details.",
    realWorldTechnique: "Fake invoice and banking phishing.",
    recommendedAction: "Verify invoices out-of-band.",
    references: ["FBI IC3 BEC"],
    tags: ["financial", "banking"],
  },
  {
    id: "LEX-004",
    category: "lexical",
    name: "False Urgency & Coercion Keyword (urgent, suspend, alert)",
    description: "URL employs coercive urgency keywords designed to bypass critical thinking.",
    severity: "medium",
    weight: 18,
    confidence: 0.88,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const targets = ["urgent", "suspend", "suspended", "action-required", "alert", "notice", "immediate", "unauthorized"];
      const matched = ctx.allTokens.find((t) => targets.includes(t));
      if (matched) {
        return {
          ruleId: "LEX-004",
          ruleCode: "LEX-URGENCY",
          category: "lexical",
          name: "False Urgency & Coercion Keyword (urgent, suspend, alert)",
          description: `High-urgency coercion token '${matched}' detected.`,
          severity: "medium",
          weight: 18,
          confidence: 0.88,
          evidence: `Urgency keyword: '${matched}'`,
          matchedString: matched,
          whyItMatters: "Psychological manipulation through artificial urgency is the hallmark of social engineering, causing victims to react quickly without inspecting URL authenticity.",
          realWorldTechnique: "Urgency-driven emotional triggers (e.g. 'account-suspended-immediate-action.com').",
          recommendedAction: "Slow down. Authentic services rarely require clicking urgent external links.",
          references: ["NIST Special Publication 800-63-3", "SANS Social Engineering"],
          tags: ["urgency", "psychology", "social-engineering"],
        };
      }
      return null;
    },
    whyItMatters: "Artificial urgency induces panic to bypass cognitive suspicion.",
    realWorldTechnique: "Psychological coercion in phishing lures.",
    recommendedAction: "Pause and verify independently.",
    references: ["NIST SP 800-63"],
    tags: ["urgency"],
  },
  {
    id: "LEX-005",
    category: "lexical",
    name: "Lure / Incentive Keyword (reward, free, bonus, prize)",
    description: "URL promises unearned rewards, bonuses, or gifts to entice victims.",
    severity: "medium",
    weight: 18,
    confidence: 0.85,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const targets = ["reward", "free", "bonus", "prize", "winner", "giveaway", "airdrop", "gift", "claim"];
      const matched = ctx.allTokens.find((t) => targets.includes(t));
      if (matched) {
        return {
          ruleId: "LEX-005",
          ruleCode: "H7-KEYWORD-REWARD",
          category: "lexical",
          name: "Lure / Incentive Keyword (reward, free, bonus, prize)",
          description: `Reward incentive token '${matched}' detected.`,
          severity: "medium",
          weight: 18,
          confidence: 0.85,
          evidence: `Incentive keyword: '${matched}'`,
          matchedString: matched,
          whyItMatters: "Greed and reward incentives lure victims into completing surveys, downloading info-stealers, or connecting crypto wallets.",
          realWorldTechnique: "Fake giveaway scams and lottery phishing.",
          recommendedAction: "Ignore unsolicited offers of prizes, bonuses, or free rewards.",
          references: ["FTC Consumer Alert: Prize Scams"],
          tags: ["lure", "reward", "scam"],
        };
      }
      return null;
    },
    whyItMatters: "Unsolicited reward claims are standard bait for malicious downloads and credential capture.",
    realWorldTechnique: "Prize scam and crypto giveaway lures.",
    recommendedAction: "Disregard unsolicited offers.",
    references: ["FTC Prize Scams"],
    tags: ["reward", "lure"],
  },
  {
    id: "LEX-006",
    category: "lexical",
    name: "Tech Support & Update Keyword (support, update, helpdesk)",
    description: "URL simulates software updates or IT technical support desks.",
    severity: "low",
    weight: 12,
    confidence: 0.80,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      // Token-boundary aware: will NOT match 'updated-news' or 'biosecure'
      const targets = ["support", "helpdesk", "antivirus", "sysadmin", "update", "upgrade"];
      const matched = ctx.allTokens.find((t) => targets.includes(t));
      if (matched) {
        return {
          ruleId: "LEX-006",
          ruleCode: "H7-KEYWORD-UPDATE",
          category: "lexical",
          name: "Tech Support & Update Keyword (support, update, helpdesk)",
          description: `Tech support token '${matched}' detected in link.`,
          severity: "low",
          weight: 12,
          confidence: 0.80,
          evidence: `Token: '${matched}'`,
          matchedString: matched,
          whyItMatters: "Fake update alerts deceive users into downloading remote access trojans (RATs) or granting helpdesk access.",
          realWorldTechnique: "Fake browser update / tech support scareware.",
          recommendedAction: "Only update software through built-in OS or application settings.",
          references: ["CISA Tech Support Scams"],
          tags: ["support", "update", "scareware"],
        };
      }
      return null;
    },
    whyItMatters: "Fake IT update links distribute remote administration trojans.",
    realWorldTechnique: "Fake browser update prompts.",
    recommendedAction: "Update software directly through OS settings.",
    references: ["CISA Tech Support"],
    tags: ["update", "support"],
  },
  {
    id: "LEX-007",
    category: "lexical",
    name: "Government & Tax Authority Scam Token (irs, hmrc, tax, aadhaar)",
    description: "URL references revenue services or national identity credentials.",
    severity: "high",
    weight: 30,
    confidence: 0.95,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const targets = ["irs", "hmrc", "tax-refund", "challan", "aadhaar", "pan-card", "gov-verify"];
      const matched = ctx.allTokens.find((t) => targets.includes(t));
      if (matched) {
        return {
          ruleId: "LEX-007",
          ruleCode: "LEX-GOV-TAX",
          category: "lexical",
          name: "Government & Tax Authority Scam Token (irs, hmrc, tax, aadhaar)",
          description: `Government / tax identity token '${matched}' detected on non-governmental domain.`,
          severity: "high",
          weight: 30,
          confidence: 0.95,
          evidence: `Government token: '${matched}' on domain '${ctx.rootDomain}'`,
          matchedString: matched,
          whyItMatters: "Government impersonation scams intimidate victims into disclosing Social Security, PAN, or Aadhaar numbers to avoid legal penalties or claim non-existent tax rebates.",
          realWorldTechnique: "Tax refund phishing and e-challan traffic fine fraud.",
          recommendedAction: "Real government portals strictly use '.gov', '.gov.in', or '.gov.uk' domains. Never input identity proofs elsewhere.",
          references: ["IRS Tax Scam Alerts", "Cert-In Advisory on E-Challan Phishing"],
          tags: ["government", "tax", "identity-theft"],
        };
      }
      return null;
    },
    whyItMatters: "Tax and national ID lures harvest sensitive government identifiers.",
    realWorldTechnique: "Fake tax refund portals and challan payment scams.",
    recommendedAction: "Verify '.gov' or official government portal domain.",
    references: ["Cert-In Advisory"],
    tags: ["government", "tax"],
  },
  {
    id: "LEX-008",
    category: "lexical",
    name: "Crypto Seed Phrase / Wallet Drainer Token",
    description: "URL references cryptocurrency seed phrases, private keys, or wallet authorization.",
    severity: "critical",
    weight: 35,
    confidence: 0.96,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const targets = ["seed-phrase", "private-key", "recovery-phrase", "keystore", "secret-recovery", "walletconnect"];
      const matched = ctx.allTokens.find((t) => targets.includes(t));
      if (matched) {
        return {
          ruleId: "LEX-008",
          ruleCode: "LEX-CRYPTO-SEED",
          category: "lexical",
          name: "Crypto Seed Phrase / Wallet Drainer Token",
          description: `Crypto recovery phrase token '${matched}' detected.`,
          severity: "critical",
          weight: 35,
          confidence: 0.96,
          evidence: `Crypto token: '${matched}'`,
          matchedString: matched,
          whyItMatters: "No legitimate cryptocurrency application or support desk will EVER ask for your seed phrase or private key via a web form. Web forms requesting seed phrases are 100% wallet drainers.",
          realWorldTechnique: "Web3 wallet drainer and secret recovery phrase theft.",
          recommendedAction: "NEVER enter your 12- or 24-word seed phrase into any website under any circumstance.",
          references: ["Consensys Security Best Practices", "FBI Web3 Scam Advisory"],
          tags: ["crypto", "seed-phrase", "wallet-drainer"],
        };
      }
      return null;
    },
    whyItMatters: "Web forms soliciting seed phrases are guaranteed wallet-draining exploits.",
    realWorldTechnique: "Theft of cryptocurrency wallet master keys.",
    recommendedAction: "Never type seed phrases into websites.",
    references: ["Consensys Security"],
    tags: ["crypto", "seed-phrase"],
  },
  {
    id: "LEX-009",
    category: "lexical",
    name: "Multilingual Credential Lure (French/Spanish/German)",
    description: "URL contains non-English authentication tokens used in regional campaigns.",
    severity: "medium",
    weight: 20,
    confidence: 0.88,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const targets = ["connexion", "verifier", "iniciar", "sesion", "cuenta", "clave", "anmelden", "sicherheit"];
      const matched = ctx.allTokens.find((t) => targets.includes(t));
      if (matched) {
        return {
          ruleId: "LEX-009",
          ruleCode: "LEX-MULTILINGUAL",
          category: "lexical",
          name: "Multilingual Credential Lure (French/Spanish/German)",
          description: `Regional language authentication token '${matched}' detected.`,
          severity: "medium",
          weight: 20,
          confidence: 0.88,
          evidence: `Multilingual token: '${matched}'`,
          matchedString: matched,
          whyItMatters: "International phishing groups target specific language demographics using regional banking keywords.",
          realWorldTechnique: "Targeted regional phishing operations.",
          recommendedAction: "Verify site directly with your local banking provider.",
          references: ["ENISA Threat Landscape"],
          tags: ["multilingual", "regional", "credentials"],
        };
      }
      return null;
    },
    whyItMatters: "Regional campaigns target non-English speaking demographics.",
    realWorldTechnique: "Localized phishing campaigns.",
    recommendedAction: "Inspect domain with regional institution.",
    references: ["ENISA Threat Landscape"],
    tags: ["multilingual"],
  },
  {
    id: "LEX-010",
    category: "lexical",
    name: "OTP / Two-Factor Authentication Intercept Token",
    description: "URL explicitly targets One-Time Passwords (OTP) or Multi-Factor Authentication codes.",
    severity: "high",
    weight: 25,
    confidence: 0.94,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const targets = ["otp", "mfa", "2fa", "token-verify", "auth-code", "sms-code"];
      const matched = ctx.allTokens.find((t) => targets.includes(t));
      if (matched) {
        return {
          ruleId: "LEX-010",
          ruleCode: "LEX-OTP-INTERCEPT",
          category: "lexical",
          name: "OTP / Two-Factor Authentication Intercept Token",
          description: `MFA interception token '${matched}' detected in path/query.`,
          severity: "high",
          weight: 25,
          confidence: 0.94,
          evidence: `OTP token: '${matched}'`,
          matchedString: matched,
          whyItMatters: "Reverse-proxy phishing kits (e.g. Evilginx) capture 2FA tokens and session cookies in real-time to bypass multi-factor authentication.",
          realWorldTechnique: "Adversary-in-the-Middle (AiTM) multi-factor authentication bypass.",
          recommendedAction: "Use FIDO2 / WebAuthn hardware keys resistant to phishing interception.",
          references: ["CISA AiTM Phishing Fact Sheet", "MITRE ATT&CK T1556: Modify Authentication Process"],
          tags: ["otp", "mfa", "aitm", "2fa"],
        };
      }
      return null;
    },
    whyItMatters: "Targets real-time capture of OTPs to bypass two-factor authentication.",
    realWorldTechnique: "AiTM phishing kits capturing SMS codes and session cookies.",
    recommendedAction: "Use phishing-resistant FIDO2 hardware security keys.",
    references: ["CISA AiTM Fact Sheet"],
    tags: ["otp", "mfa", "aitm"],
  },
  {
    id: "LEX-011",
    category: "lexical",
    name: "Fake Shipping / Parcel Delivery Lure (fedex, dhl, usps)",
    description: "URL references courier tracking and package delivery on an unrelated domain.",
    severity: "medium",
    weight: 20,
    confidence: 0.90,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const targets = ["fedex-tracking", "dhl-parcel", "ups-delivery", "usps-redelivery", "indiapost-tracking", "parcel-status"];
      const matched = ctx.allTokens.find((t) => targets.includes(t));
      if (matched) {
        return {
          ruleId: "LEX-011",
          ruleCode: "LEX-SHIPPING-LURE",
          category: "lexical",
          name: "Fake Shipping / Parcel Delivery Lure (fedex, dhl, usps)",
          description: `Parcel tracking lure '${matched}' detected.`,
          severity: "medium",
          weight: 20,
          confidence: 0.90,
          evidence: `Lure token: '${matched}'`,
          matchedString: matched,
          whyItMatters: "Fake delivery notifications request a tiny fee ($1-$2) to reschedule a missed package, capturing full credit card details and CVV numbers.",
          realWorldTechnique: "Package delivery smishing scam.",
          recommendedAction: "Track parcels directly through official courier apps using the original tracking number.",
          references: ["USPS Postal Inspection Alert", "US-CERT Smishing"],
          tags: ["shipping", "parcel", "smishing"],
        };
      }
      return null;
    },
    whyItMatters: "Missed delivery scams steal credit card details under the guise of redelivery fees.",
    realWorldTechnique: "Package delivery smishing.",
    recommendedAction: "Verify with courier directly.",
    references: ["USPS Inspection Alert"],
    tags: ["shipping", "parcel"],
  },
  {
    id: "LEX-012",
    category: "lexical",
    name: "DocuSign / e-Signature Lure in Path",
    description: "URL simulates digital document signing services on an unverified domain.",
    severity: "high",
    weight: 25,
    confidence: 0.92,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const targets = ["docusign", "adobesign", "sign-document", "review-document", "esign"];
      const matched = ctx.allTokens.find((t) => targets.includes(t));
      if (matched) {
        return {
          ruleId: "LEX-012",
          ruleCode: "LEX-DOCUSIGN-LURE",
          category: "lexical",
          name: "DocuSign / e-Signature Lure in Path",
          description: `Document signing lure '${matched}' detected.`,
          severity: "high",
          weight: 25,
          confidence: 0.92,
          evidence: `Token: '${matched}'`,
          matchedString: matched,
          whyItMatters: "DocuSign lures trick corporate employees into signing into fake corporate portal pages, compromising enterprise Microsoft 365 or Google Workspace accounts.",
          realWorldTechnique: "Corporate identity theft via fake signature workflows.",
          recommendedAction: "Access documents directly from your authentic DocuSign account dashboard.",
          references: ["DocuSign Security Advisory", "MITRE ATT&CK T1566.002"],
          tags: ["docusign", "document-lure", "corporate-phishing"],
        };
      }
      return null;
    },
    whyItMatters: "Simulates electronic signature workflows to harvest corporate employee credentials.",
    realWorldTechnique: "DocuSign lure campaigns.",
    recommendedAction: "Verify document through authentic signature portal.",
    references: ["DocuSign Advisory"],
    tags: ["docusign", "corporate"],
  },
  {
    id: "LEX-013",
    category: "lexical",
    name: "Telephony / Voice Phishing (Vishing) Callback Lure",
    description: "URL references phone call center callbacks or fake customer service numbers.",
    severity: "medium",
    weight: 15,
    confidence: 0.82,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const targets = ["call-center", "toll-free", "customer-care", "helpline", "call-now"];
      const matched = ctx.allTokens.find((t) => targets.includes(t));
      if (matched) {
        return {
          ruleId: "LEX-013",
          ruleCode: "LEX-VISHING-CALLBACK",
          category: "lexical",
          name: "Telephony / Voice Phishing (Vishing) Callback Lure",
          description: `Call center lure '${matched}' detected.`,
          severity: "medium",
          weight: 15,
          confidence: 0.82,
          evidence: `Token: '${matched}'`,
          matchedString: matched,
          whyItMatters: "Directs users to call fraudulent support numbers where human social engineers persuade them to grant remote desktop control.",
          realWorldTechnique: "Multi-channel hybrid vishing/phishing attack.",
          recommendedAction: "Never call phone numbers displayed on unexpected security warnings.",
          references: ["FBI IC3 Vishing Alerts"],
          tags: ["vishing", "call-center", "social-engineering"],
        };
      }
      return null;
    },
    whyItMatters: "Coerces victims into calling fraudulent phone support call centers.",
    realWorldTechnique: "Hybrid vishing.",
    recommendedAction: "Do not call phone numbers on alert banners.",
    references: ["FBI IC3 Vishing"],
    tags: ["vishing"],
  },
  {
    id: "LEX-014",
    category: "lexical",
    name: "High Lexical Lure Density (>= 3 Distinct Category Tokens)",
    description: "URL contains 3 or more distinct suspicious keywords simultaneously.",
    severity: "high",
    weight: 25,
    confidence: 0.94,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const keywordSet = new Set([
        "login", "verify", "secure", "account", "banking", "password", "reward", "free",
        "bonus", "update", "signin", "wallet", "invoice", "urgent", "suspend"
      ]);
      const matchedList = ctx.allTokens.filter((t) => keywordSet.has(t));
      const uniqueMatched = Array.from(new Set(matchedList));
      if (uniqueMatched.length >= 3) {
        return {
          ruleId: "LEX-014",
          ruleCode: "LEX-DENSITY-HIGH",
          category: "lexical",
          name: "High Lexical Lure Density (>= 3 Distinct Category Tokens)",
          description: `Multiple lure keywords combined: [${uniqueMatched.join(", ")}].`,
          severity: "high",
          weight: 25,
          confidence: 0.94,
          evidence: `Matched tokens: ${uniqueMatched.join(", ")}`,
          matchedString: uniqueMatched.join(", "),
          whyItMatters: "Stitching multiple security and financial words together (e.g. 'secure-login-account-update.com') is a definitive trait of artificial phishing domain synthesis.",
          realWorldTechnique: "Keyword clustering for social engineering reinforcement.",
          recommendedAction: "Strongly avoid interacting with domain.",
          references: ["APWG Survey on Phishing Nomenclature"],
          tags: ["lexical", "keyword-density", "clustering"],
        };
      }
      return null;
    },
    whyItMatters: "Multiple combined security keywords indicate artificial domain generation.",
    realWorldTechnique: "Keyword chaining in phishing domains.",
    recommendedAction: "Reject URL.",
    references: ["APWG Phishing Nomenclature"],
    tags: ["lexical", "keyword-density"],
  },
  {
    id: "LEX-015",
    category: "lexical",
    name: "File Attachment Phishing Indicator in Path",
    description: "Path explicitly references fake email attachments or secure messages.",
    severity: "medium",
    weight: 15,
    confidence: 0.85,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const targets = ["attachment", "secure-message", "encrypted-email", "view-document", "download-file"];
      const matched = ctx.allTokens.find((t) => targets.includes(t));
      if (matched) {
        return {
          ruleId: "LEX-015",
          ruleCode: "LEX-ATTACHMENT-LURE",
          category: "lexical",
          name: "File Attachment Phishing Indicator in Path",
          description: `Encrypted attachment lure token '${matched}' detected.`,
          severity: "medium",
          weight: 15,
          confidence: 0.85,
          evidence: `Token: '${matched}'`,
          matchedString: matched,
          whyItMatters: "Phishing emails claim an encrypted or protected document is waiting for review, redirecting users to fake Microsoft or Google login portals.",
          realWorldTechnique: "Fake secure message notification lure.",
          recommendedAction: "Request confirmation from sender via known phone or chat channel.",
          references: ["US-CERT Email Security"],
          tags: ["attachment", "lure", "email"],
        };
      }
      return null;
    },
    whyItMatters: "Fake attachment notifications trick victims into credential entry.",
    realWorldTechnique: "Fake encrypted document portals.",
    recommendedAction: "Verify sender out-of-band.",
    references: ["US-CERT Email"],
    tags: ["attachment"],
  },
];
