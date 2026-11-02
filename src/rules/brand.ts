import type { Rule, RuleFinding, ParsedUrlContext } from "./types.ts";

// Levenshtein distance for fuzzy brand matching
function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}

const TOP_MONITORED_BRANDS = [
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
  "wellsfargo",
  "citibank",
  "barclays",
  "binance",
  "coinbase",
  "metamask",
  "telegram",
  "discord",
  "linkedin",
  "spotify",
  "dropbox",
  "docusign",
];

const INDIAN_FINANCIAL_BRANDS = [
  "sbi",
  "onlinesbi",
  "hdfc",
  "hdfcbank",
  "icici",
  "icicibank",
  "axisbank",
  "kotak",
  "pnb",
  "paytm",
  "phonepe",
  "bhim",
  "razorpay",
  "zerodha",
  "groww",
];

export const brandRules: Rule[] = [
  {
    id: "BRD-001",
    category: "brand",
    name: "Direct Leetspeak Character Substitution",
    description: "Domain uses numbers or homoglyphs to substitute letters in brand names (e.g., '0' for 'o', '1' for 'l').",
    severity: "critical",
    weight: 35,
    confidence: 0.98,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const host = ctx.hostname.toLowerCase();
      const leetMap: Record<string, string> = {
        g00gle: "Google",
        micr0soft: "Microsoft",
        m1crosoft: "Microsoft",
        amaz0n: "Amazon",
        paypai: "PayPal (Latin 'I' for 'l')",
        app1e: "Apple",
        netf1ix: "Netflix",
        faceb00k: "Facebook",
      };

      for (const [pattern, brand] of Object.entries(leetMap)) {
        if (host.includes(pattern)) {
          return {
            ruleId: "BRD-001",
            ruleCode: "H8-LEETSPEAK",
            category: "brand",
            name: "Direct Leetspeak Character Substitution",
            description: `Leetspeak typo '${pattern}' imitating brand '${brand}'.`,
            severity: "critical",
            weight: 35,
            confidence: 0.98,
            evidence: `Host: ${ctx.hostname} contains '${pattern}'`,
            matchedString: pattern,
            whyItMatters: "Leetspeak substitution tricks human cognitive pattern recognition. Readers read 'g00gle' or 'paypaI' as authentic brands while computers connect to distinct adversary domains.",
            realWorldTechnique: "Typosquatting and character substitution (MITRE ATT&CK T1566.002).",
            recommendedAction: "Block URL immediately. Intentional deceptive impersonation.",
            references: ["MITRE ATT&CK T1566.002", "APWG Anti-Phishing Best Practices"],
            tags: ["brand", "leetspeak", "typosquatting", "t1566"],
          };
        }
      }
      return null;
    },
    whyItMatters: "Leetspeak substitutions visually deceive human readers into trusting attacker domains.",
    realWorldTechnique: "Typosquatting brand impersonation.",
    recommendedAction: "Reject URL unconditionally.",
    references: ["MITRE ATT&CK T1566.002"],
    tags: ["leetspeak", "brand"],
  },
  {
    id: "BRD-002",
    category: "brand",
    name: "Google Ecosystem Impersonation",
    description: "Domain impersonates Google Workspace, Gmail, or Google Docs on an unauthorized domain.",
    severity: "critical",
    weight: 35,
    confidence: 0.96,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const host = ctx.hostname.toLowerCase();
      if (/(?:^|\.)(google|gmail|google-drive|google-docs|google-security)[a-z0-9-]*\./i.test(host)) {
        return {
          ruleId: "BRD-002",
          ruleCode: "BRD-GOOGLE-SPOOF",
          category: "brand",
          name: "Google Ecosystem Impersonation",
          description: `Unauthorized domain imitating Google brand (${ctx.rootDomain}).`,
          severity: "critical",
          weight: 35,
          confidence: 0.96,
          evidence: `Domain: ${ctx.rootDomain}`,
          matchedString: ctx.hostname,
          whyItMatters: "Google accounts grant access to emails, cloud drives, and enterprise SSO. Stealing Google credentials compromises the victim's entire identity.",
          realWorldTechnique: "Fake Google Workspace / OAuth consent screen phishing.",
          recommendedAction: "Authentic Google services strictly reside on '*.google.com'. Never log in elsewhere.",
          references: ["Google Safe Browsing Technical Advisory"],
          tags: ["google", "brand", "workspace"],
        };
      }
      return null;
    },
    whyItMatters: "Fake Google domains steal enterprise SSO and personal email accounts.",
    realWorldTechnique: "Google Workspace credential harvesting.",
    recommendedAction: "Verify '*.google.com' domain.",
    references: ["Google Safe Browsing"],
    tags: ["google", "brand"],
  },
  {
    id: "BRD-003",
    category: "brand",
    name: "Microsoft / Office 365 Impersonation",
    description: "Domain mimics Microsoft, Outlook, Office 365, or Azure authentication on an unauthorized host.",
    severity: "critical",
    weight: 35,
    confidence: 0.96,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const host = ctx.hostname.toLowerCase();
      if (/(?:^|\.)(microsoft|office365|outlook-web|login-microsoft|azure-portal)[a-z0-9-]*\./i.test(host)) {
        return {
          ruleId: "BRD-003",
          ruleCode: "BRD-MS-SPOOF",
          category: "brand",
          name: "Microsoft / Office 365 Impersonation",
          description: `Unauthorized domain imitating Microsoft corporate services (${ctx.rootDomain}).`,
          severity: "critical",
          weight: 35,
          confidence: 0.96,
          evidence: `Domain: ${ctx.rootDomain}`,
          matchedString: ctx.hostname,
          whyItMatters: "Microsoft 365 is the #1 targeted corporate identity system globally. Stolen credentials lead to internal network pivoting and Business Email Compromise.",
          realWorldTechnique: "Corporate M365 credential harvesting portals.",
          recommendedAction: "Authentic Microsoft logins only occur on '*.microsoft.com' or 'login.microsoftonline.com'.",
          references: ["Microsoft Security Intelligence Phishing Report"],
          tags: ["microsoft", "office365", "corporate-identity"],
        };
      }
      return null;
    },
    whyItMatters: "Microsoft impersonation is the primary corporate credential theft vector.",
    realWorldTechnique: "Office 365 credential harvesting.",
    recommendedAction: "Only log in on official Microsoft domains.",
    references: ["Microsoft Threat Intelligence"],
    tags: ["microsoft", "office365"],
  },
  {
    id: "BRD-004",
    category: "brand",
    name: "Apple & iCloud Impersonation",
    description: "Domain mimics Apple ID, Find My iPhone, or iCloud verification portals.",
    severity: "critical",
    weight: 35,
    confidence: 0.96,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const host = ctx.hostname.toLowerCase();
      if (/(?:^|\.)(apple-id|icloud-find|apple-support|apple-security)[a-z0-9-]*\./i.test(host)) {
        return {
          ruleId: "BRD-004",
          ruleCode: "BRD-APPLE-SPOOF",
          category: "brand",
          name: "Apple & iCloud Impersonation",
          description: `Domain mimics Apple identity infrastructure (${ctx.rootDomain}).`,
          severity: "critical",
          weight: 35,
          confidence: 0.96,
          evidence: `Host: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "Stolen Apple IDs allow criminals to remotely disable Activation Lock on stolen iOS devices and access iCloud backups and personal photos.",
          realWorldTechnique: "Find My iPhone SMS phishing sent to victims of stolen devices.",
          recommendedAction: "Authentic Apple ID logins strictly occur on 'appleid.apple.com' or 'icloud.com'.",
          references: ["Apple Support: Recognize Phishing"],
          tags: ["apple", "icloud", "activation-lock"],
        };
      }
      return null;
    },
    whyItMatters: "Apple ID phishing unlocks stolen phones and accesses private iCloud data.",
    realWorldTechnique: "Stolen iPhone Find My bypass phishing.",
    recommendedAction: "Inspect for '*.apple.com' domain.",
    references: ["Apple Security"],
    tags: ["apple", "icloud"],
  },
  {
    id: "BRD-005",
    category: "brand",
    name: "PayPal & Payment Gateway Impersonation",
    description: "Domain mimics PayPal resolution centers or account verification.",
    severity: "critical",
    weight: 35,
    confidence: 0.98,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const host = ctx.hostname.toLowerCase();
      if (/(?:^|\.)(paypal-verify|paypal-security|paypal-account|paypal-service)[a-z0-9-]*\./i.test(host)) {
        return {
          ruleId: "BRD-005",
          ruleCode: "BRD-PAYPAL-SPOOF",
          category: "brand",
          name: "PayPal & Payment Gateway Impersonation",
          description: `Unauthorized domain simulating PayPal services (${ctx.rootDomain}).`,
          severity: "critical",
          weight: 35,
          confidence: 0.98,
          evidence: `Host: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "PayPal phishing directly compromises linked bank accounts and credit cards, enabling immediate fraudulent transfers.",
          realWorldTechnique: "Fake account limitation and payment dispute warnings.",
          recommendedAction: "Open 'paypal.com' directly in your browser. Never use email links.",
          references: ["PayPal Security Center Guidance"],
          tags: ["paypal", "payment", "fraud"],
        };
      }
      return null;
    },
    whyItMatters: "Direct financial theft through fake payment dispute and account hold forms.",
    realWorldTechnique: "PayPal account limitation phishing.",
    recommendedAction: "Navigate directly to 'paypal.com'.",
    references: ["PayPal Security"],
    tags: ["paypal", "payment"],
  },
  {
    id: "BRD-006",
    category: "brand",
    name: "Amazon Order / Account Impersonation",
    description: "Domain simulates Amazon customer service, prime rewards, or order suspensions.",
    severity: "critical",
    weight: 35,
    confidence: 0.96,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const host = ctx.hostname.toLowerCase();
      if (/(?:^|\.)(amazon-security|amazon-order|amazon-support|prime-rewards)[a-z0-9-]*\./i.test(host)) {
        return {
          ruleId: "BRD-006",
          ruleCode: "BRD-AMAZON-SPOOF",
          category: "brand",
          name: "Amazon Order / Account Impersonation",
          description: `Domain mimics Amazon customer infrastructure (${ctx.rootDomain}).`,
          severity: "critical",
          weight: 35,
          confidence: 0.96,
          evidence: `Host: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "Fake order confirmation emails induce panic about unauthorized high-value purchases (e.g. '$1,200 laptop order'), prompting victims to click.",
          realWorldTechnique: "Order cancellation and charge-reversal social engineering.",
          recommendedAction: "Check your 'Your Orders' tab directly on 'amazon.com'.",
          references: ["Amazon Customer Security Guidelines"],
          tags: ["amazon", "e-commerce", "order-scam"],
        };
      }
      return null;
    },
    whyItMatters: "Fake order emails panic victims into logging into counterfeit portals.",
    realWorldTechnique: "Order dispute and cancellation fraud.",
    recommendedAction: "Verify orders on official Amazon app.",
    references: ["Amazon Guidelines"],
    tags: ["amazon", "order-scam"],
  },
  {
    id: "BRD-007",
    category: "brand",
    name: "State Bank of India (SBI) Impersonation",
    description: "Domain mimics State Bank of India (onlinesbi) or YONO digital banking.",
    severity: "critical",
    weight: 40,
    confidence: 0.98,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const host = ctx.hostname.toLowerCase();
      if (/(?:^|\.)(sbi-kyc|onlinesbi-portal|sbi-rewards|yono-sbi|sbi-netbanking)[a-z0-9-]*\./i.test(host)) {
        return {
          ruleId: "BRD-007",
          ruleCode: "BRD-SBI-SPOOF",
          category: "brand",
          name: "State Bank of India (SBI) Impersonation",
          description: `Unauthorized domain imitating SBI / YONO net banking (${ctx.rootDomain}).`,
          severity: "critical",
          weight: 40,
          confidence: 0.98,
          evidence: `Host: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "SBI is India's largest public sector bank. Fake KYC update SMS messages steal NetBanking login profiles and OTPs for instantaneous UPI draining.",
          realWorldTechnique: "SBI PAN/Aadhaar KYC suspension smishing scams.",
          recommendedAction: "Authentic SBI portal is strictly 'onlinesbi.sbi' or 'sbi.co.in'. Never access via SMS links.",
          references: ["Cert-In Advisory on SBI KYC Phishing", "RBI Consumer Awareness"],
          tags: ["sbi", "indian-banking", "kyc-scam", "yono"],
        };
      }
      return null;
    },
    whyItMatters: "SBI phishing steals online banking credentials and intercepts OTPs via SMS lures.",
    realWorldTechnique: "PAN / KYC update SMS phishing in India.",
    recommendedAction: "Only use 'onlinesbi.sbi' or official YONO app.",
    references: ["Cert-In Advisory", "RBI"],
    tags: ["sbi", "indian-banking"],
  },
  {
    id: "BRD-008",
    category: "brand",
    name: "HDFC Bank NetBanking Impersonation",
    description: "Domain mimics HDFC Bank customer portals or reward point redemptions.",
    severity: "critical",
    weight: 40,
    confidence: 0.98,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const host = ctx.hostname.toLowerCase();
      if (/(?:^|\.)(hdfc-netbanking|hdfc-kyc|hdfcbank-rewards|hdfc-security)[a-z0-9-]*\./i.test(host)) {
        return {
          ruleId: "BRD-008",
          ruleCode: "BRD-HDFC-SPOOF",
          category: "brand",
          name: "HDFC Bank NetBanking Impersonation",
          description: `Domain mimics HDFC Bank services (${ctx.rootDomain}).`,
          severity: "critical",
          weight: 40,
          confidence: 0.98,
          evidence: `Host: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "HDFC Bank credit card reward point and KYC expiration lures trick customers into submitting internet banking passwords and OTP tokens.",
          realWorldTechnique: "Reward points expiry and debit card verification fraud.",
          recommendedAction: "Official domain is strictly 'hdfcbank.com'. Block unauthorized variations.",
          references: ["HDFC Bank Security Advisory", "Cert-In Financial Fraud Bulletin"],
          tags: ["hdfc", "indian-banking", "netbanking"],
        };
      }
      return null;
    },
    whyItMatters: "HDFC lures steal netbanking credentials under the guise of reward redemption.",
    realWorldTechnique: "Reward point expiration smishing.",
    recommendedAction: "Access solely via 'hdfcbank.com'.",
    references: ["HDFC Security"],
    tags: ["hdfc", "indian-banking"],
  },
  {
    id: "BRD-009",
    category: "brand",
    name: "ICICI Bank iMobile Impersonation",
    description: "Domain simulates ICICI Bank iMobile or corporate banking portals.",
    severity: "critical",
    weight: 40,
    confidence: 0.98,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const host = ctx.hostname.toLowerCase();
      if (/(?:^|\.)(icici-login|icicibank-security|icici-rewards|imobile-verify)[a-z0-9-]*\./i.test(host)) {
        return {
          ruleId: "BRD-009",
          ruleCode: "BRD-ICICI-SPOOF",
          category: "brand",
          name: "ICICI Bank iMobile Impersonation",
          description: `Domain simulates ICICI Bank net banking (${ctx.rootDomain}).`,
          severity: "critical",
          weight: 40,
          confidence: 0.98,
          evidence: `Host: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "Harvests user IDs, debit card PINs, and grid authentication values to siphon bank balances.",
          realWorldTechnique: "Credit card block / debit grid card number capture.",
          recommendedAction: "Only bank on 'icicibank.com' or verified iMobile app.",
          references: ["ICICI Safe Banking Best Practices"],
          tags: ["icici", "indian-banking", "grid-card"],
        };
      }
      return null;
    },
    whyItMatters: "ICICI phishing targets grid card values and netbanking passwords.",
    realWorldTechnique: "Debit card grid authentication theft.",
    recommendedAction: "Verify 'icicibank.com'.",
    references: ["ICICI Safe Banking"],
    tags: ["icici", "banking"],
  },
  {
    id: "BRD-010",
    category: "brand",
    name: "Indian UPI & Fintech Impersonation (Paytm, PhonePe, GPay)",
    description: "Domain mimics popular Indian UPI payment apps or lottery cashbacks.",
    severity: "critical",
    weight: 35,
    confidence: 0.96,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const host = ctx.hostname.toLowerCase();
      if (/(?:^|\.)(paytm-kyc|phonepe-reward|gpay-scratchcard|bhim-upi-reward)[a-z0-9-]*\./i.test(host)) {
        return {
          ruleId: "BRD-010",
          ruleCode: "BRD-FINTECH-UPI",
          category: "brand",
          name: "Indian UPI & Fintech Impersonation (Paytm, PhonePe, GPay)",
          description: `Fintech payment app impersonation detected (${ctx.rootDomain}).`,
          severity: "critical",
          weight: 35,
          confidence: 0.96,
          evidence: `Host: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "Scratch card and cashback scams instruct victims to approve a UPI collect request or enter their UPI PIN, mistakenly believing they are receiving money.",
          realWorldTechnique: "UPI PIN entry reverse collect scam.",
          recommendedAction: "Entering a UPI PIN ALWAYS transfers money OUT. You never enter a PIN to receive cashback.",
          references: ["NPCI UPI Safety Guidelines", "Cert-In Cashback Scam Bulletin"],
          tags: ["upi", "paytm", "phonepe", "cashback-scam"],
        };
      }
      return null;
    },
    whyItMatters: "Fintech scratch card scams deceive users into approving outgoing UPI transfers.",
    realWorldTechnique: "UPI collect request exploitation.",
    recommendedAction: "Never type UPI PINs on external web forms.",
    references: ["NPCI Guidelines"],
    tags: ["upi", "fintech"],
  },
  {
    id: "BRD-011",
    category: "brand",
    name: "Global Tier-1 Banking Impersonation (Chase, BofA, Wells Fargo)",
    description: "Domain mimics multinational retail banking institutions.",
    severity: "critical",
    weight: 40,
    confidence: 0.98,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const host = ctx.hostname.toLowerCase();
      if (/(?:^|\.)(chase-security|bankofamerica-login|wellsfargo-verify|citibank-online)[a-z0-9-]*\./i.test(host)) {
        return {
          ruleId: "BRD-011",
          ruleCode: "BRD-GLOBAL-BANK",
          category: "brand",
          name: "Global Tier-1 Banking Impersonation (Chase, BofA, Wells Fargo)",
          description: `Domain mimics multinational retail banking institution (${ctx.rootDomain}).`,
          severity: "critical",
          weight: 40,
          confidence: 0.98,
          evidence: `Host: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "Global banking phishing directly facilitates wire fraud and account takeover.",
          realWorldTechnique: "Fake fraud alert SMS and account suspension landing pages.",
          recommendedAction: "Block navigation immediately. Contact bank using back-of-card telephone number.",
          references: ["FS-ISAC Threat Bulletins"],
          tags: ["banking", "chase", "bofa", "wire-fraud"],
        };
      }
      return null;
    },
    whyItMatters: "Direct wire fraud and electronic funds transfer theft.",
    realWorldTechnique: "Tier-1 banking credential harvesting.",
    recommendedAction: "Navigate solely to verified financial bookmarks.",
    references: ["FS-ISAC"],
    tags: ["banking", "global-bank"],
  },
  {
    id: "BRD-012",
    category: "brand",
    name: "Social Media Platform Impersonation",
    description: "Domain mimics Facebook, Instagram, WhatsApp, Discord, or LinkedIn.",
    severity: "high",
    weight: 30,
    confidence: 0.94,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const host = ctx.hostname.toLowerCase();
      if (/(?:^|\.)(instagram-copyright|facebook-appeal|whatsapp-web-login|discord-nitro)[a-z0-9-]*\./i.test(host)) {
        return {
          ruleId: "BRD-012",
          ruleCode: "BRD-SOCIAL-MEDIA",
          category: "brand",
          name: "Social Media Platform Impersonation",
          description: `Domain impersonates major social network platform (${ctx.rootDomain}).`,
          severity: "high",
          weight: 30,
          confidence: 0.94,
          evidence: `Host: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "Copyright violation alerts and fake Discord Nitro promotions trick users into compromising accounts, which are then leveraged for peer social engineering.",
          realWorldTechnique: "Social network account takeover for secondary scam distribution.",
          recommendedAction: "Manage appeals directly within the official mobile app.",
          references: ["Meta Security Advisories", "Discord Safety Center"],
          tags: ["social-media", "instagram", "discord", "takeover"],
        };
      }
      return null;
    },
    whyItMatters: "Compromised social accounts are weaponized to scam victims' friends and family.",
    realWorldTechnique: "Copyright strike and Discord Nitro lures.",
    recommendedAction: "Verify notifications within official apps.",
    references: ["Meta Security"],
    tags: ["social-media"],
  },
  {
    id: "BRD-013",
    category: "brand",
    name: "Cryptocurrency Exchange Impersonation",
    description: "Domain mimics Binance, Coinbase, Kraken, or Bybit trading platforms.",
    severity: "critical",
    weight: 40,
    confidence: 0.98,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const host = ctx.hostname.toLowerCase();
      if (/(?:^|\.)(binance-security|coinbase-login|kraken-auth|bybit-airdrop)[a-z0-9-]*\./i.test(host)) {
        return {
          ruleId: "BRD-013",
          ruleCode: "BRD-CRYPTO-EXCHANGE",
          category: "brand",
          name: "Cryptocurrency Exchange Impersonation",
          description: `Cryptocurrency trading exchange impersonation (${ctx.rootDomain}).`,
          severity: "critical",
          weight: 40,
          confidence: 0.98,
          evidence: `Host: ${ctx.hostname}`,
          matchedString: ctx.hostname,
          whyItMatters: "Cryptocurrency transactions are irreversible. Stolen credentials allow attackers to immediately liquidate assets to untraceable external wallets.",
          realWorldTechnique: "Fake exchange withdrawal hold and airdrop phishing.",
          recommendedAction: "Always verify exchange SSL certificates and use hardware security keys.",
          references: ["Coinbase Security Bulletins", "Binance Anti-Phishing Code"],
          tags: ["crypto", "exchange", "binance", "coinbase"],
        };
      }
      return null;
    },
    whyItMatters: "Irreversible financial liquidation of cryptocurrency balances.",
    realWorldTechnique: "Exchange credential and 2FA interception.",
    recommendedAction: "Enable Anti-Phishing Codes in exchange settings.",
    references: ["Binance Security"],
    tags: ["crypto", "exchange"],
  },
  {
    id: "BRD-014",
    category: "brand",
    name: "Combosquatting Brand Chaining",
    description: "Domain chains a monitored brand with security, support, or portal action words.",
    severity: "high",
    weight: 30,
    confidence: 0.92,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const { rootDomain } = ctx;
      const label = rootDomain.split(".")[0];
      for (const brand of TOP_MONITORED_BRANDS) {
        if (label.includes(brand) && label !== brand) {
          const actionWords = ["security", "verify", "verification", "support", "login", "portal", "account", "update", "service", "center"];
          if (actionWords.some((w) => label.includes(w))) {
            return {
              ruleId: "BRD-014",
              ruleCode: "BRD-COMBOSQUATTING",
              category: "brand",
              name: "Combosquatting Brand Chaining",
              description: `Domain '${rootDomain}' links brand '${brand}' with action words.`,
              severity: "high",
              weight: 30,
              confidence: 0.92,
              evidence: `Combosquatting domain: ${rootDomain}`,
              matchedString: rootDomain,
              whyItMatters: "Combosquatting is currently the most prevalent form of brand infringement in cyber attacks, outpacing traditional typosquatting.",
              realWorldTechnique: "Chains brand names with trust-inducing keywords to deceive consumers.",
              recommendedAction: "Do not trust domain. Major brands use subdomains on their own domain, not separate hyphenated domains.",
              references: ["US-CERT Combosquatting Research", "ACM Conference on Computer and Communications Security"],
              tags: ["combosquatting", "brand", "deception"],
            };
          }
        }
      }
      return null;
    },
    whyItMatters: "Combosquatting leverages trusted brand names joined with security terms.",
    realWorldTechnique: "Chained brand-action domains.",
    recommendedAction: "Check official company domain.",
    references: ["US-CERT Combosquatting"],
    tags: ["combosquatting"],
  },
  {
    id: "BRD-015",
    category: "brand",
    name: "Low Edit Distance Typosquatting (Levenshtein <= 2)",
    description: "Domain label is 1 or 2 edits away from a major brand, indicating intentional misspelling.",
    severity: "high",
    weight: 30,
    confidence: 0.90,
    detect: (ctx: ParsedUrlContext): RuleFinding | null => {
      if (ctx.isAllowlisted) return null;
      const { rootDomain } = ctx;
      const label = rootDomain.split(".")[0].toLowerCase();

      for (const brand of TOP_MONITORED_BRANDS) {
        if (label !== brand && Math.abs(label.length - brand.length) <= 2) {
          const dist = levenshteinDistance(label, brand);
          if (dist === 1 || dist === 2) {
            return {
              ruleId: "BRD-015",
              ruleCode: "BRD-TYPOSQUATTING-FUZZY",
              category: "brand",
              name: "Low Edit Distance Typosquatting (Levenshtein <= 2)",
              description: `Domain '${label}' is ${dist} edit(s) away from monitored brand '${brand}'.`,
              severity: "high",
              weight: 30,
              confidence: 0.90,
              evidence: `Domain: ${label} (Distance ${dist} from ${brand})`,
              matchedString: label,
              whyItMatters: "Typosquatters anticipate typing mistakes (transpositions, omissions, adjacent keyboard slips) to capture traffic intended for major websites.",
              realWorldTechnique: "Fuzzy typosquatting capturing misdirected consumer traffic.",
              recommendedAction: "Carefully re-type the desired company domain in the address bar.",
              references: ["IEEE Security & Privacy on Typosquatting", "WIPO Domain Name Disputes"],
              tags: ["typosquatting", "levenshtein", "fuzzy-match"],
            };
          }
        }
      }
      return null;
    },
    whyItMatters: "Low edit distances indicate intentional misspelling domains targeting mistyped URLs.",
    realWorldTechnique: "Fat-finger and adjacent key typosquatting.",
    recommendedAction: "Re-check domain spelling.",
    references: ["IEEE Security & Privacy"],
    tags: ["typosquatting", "fuzzy"],
  },
];
