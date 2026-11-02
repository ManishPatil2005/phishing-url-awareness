export const SUSPICIOUS_KEYWORDS = [
  "login",
  "verify",
  "secure",
  "account",
  "banking",
  "update",
  "reward",
  "wallet",
  "bitcoin",
  "crypto",
  "password",
  "otp",
  "signin",
] as const;

export const KNOWN_BRAND_IMPERSONATIONS: Record<string, string> = {
  "g00gle": "Google",
  "micr0soft": "Microsoft",
  "amaz0n": "Amazon",
  "paypai": "PayPal",
  "paypa1": "PayPal",
  "appie": "Apple",
  "app1e": "Apple",
  "netfiix": "Netflix",
  "faceb00k": "Facebook",
  "biinance": "Binance",
  "c0inbase": "Coinbase",
};

// Calibrated Scoring Weights (Sum bounded to 100)
export const WEIGHTS = {
  IP_ADDRESS: 35,
  BRAND_IMPERSONATION: 30,
  AT_SYMBOL: 25,
  PUNYCODE: 20,
  HTTP_SCHEME: 15,
  KEYWORD_BASE: 25,
  KEYWORD_ADDITIONAL: 5, // up to 30 cap
  LONG_URL: 10,
  EXCESSIVE_SEGMENTS: 10,
  DOMAIN_ANOMALIES: 15,
} as const;

export const PRESET_SAMPLE_URLS = [
  {
    label: "Clean HTTPS",
    url: "https://www.example.com/",
    description: "Benchmark authentic enterprise domain",
  },
  {
    label: "IP + HTTP + Login",
    url: "http://192.0.2.10/login",
    description: "Canonical high-threat credential harvester",
  },
  {
    label: "@ Disguise",
    url: "http://example.com@sample.invalid/login",
    description: "RFC 3986 userinfo credential masking attack",
  },
  {
    label: "Punycode (xn--)",
    url: "https://xn--example.invalid/",
    description: "Internationalized Domain Name (IDN) homoglyph",
  },
  {
    label: "Brand Spoofing",
    url: "https://g00gle.com/secure-login",
    description: "Typosquatting visual replacement (00 -> oo)",
  },
  {
    label: "Crypto Lure",
    url: "https://metamask-wallet-connect-airdrop.crypto.invalid/",
    description: "Web3 wallet seed phrase drainer pattern",
  },
  {
    label: "Claude AI Chat",
    url: "https://claude.ai/chat/c6bfaa97-602e-4ba5-9087-69c654157747",
    description: "Legitimate clean control service URL",
  },
] as const;
