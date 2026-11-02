import test from "node:test";
import assert from "node:assert/strict";

const SUSPICIOUS_KEYWORDS = [
  "login", "verify", "secure", "account", "banking",
  "update", "reward", "wallet", "bitcoin", "crypto",
  "password", "otp", "signin",
];

const KNOWN_BRAND_IMPERSONATIONS = {
  "g00gle": "Google",
  "micr0soft": "Microsoft",
  "amaz0n": "Amazon",
  "paypai": "PayPal",
  "paypa1": "PayPal",
};

const WEIGHTS = {
  IP_ADDRESS: 35,
  BRAND_IMPERSONATION: 30,
  AT_SYMBOL: 25,
  PUNYCODE: 20,
  HTTP_SCHEME: 15,
  KEYWORD_BASE: 25,
  KEYWORD_ADDITIONAL: 5,
  LONG_URL: 10,
  EXCESSIVE_SEGMENTS: 10,
  DOMAIN_ANOMALIES: 15,
};

function isStrictIpv4(host) {
  const parts = host.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d{1,3}$/.test(p) && parseInt(p, 10) >= 0 && parseInt(p, 10) <= 255);
}

function analyzeUrl(rawUrl) {
  const trimmed = (rawUrl || "").trim();
  if (!trimmed) {
    return { isValid: false, errorMessage: "URL string cannot be empty.", riskScore: 0, classification: "SAFE-LOOKING" };
  }

  // Guard against unclosed IPv6 brackets
  if (trimmed.includes("[") && !trimmed.includes("]")) {
    return { isValid: false, errorMessage: "Malformed IPv6 URI syntax (unclosed bracket).", riskScore: 0, classification: "SAFE-LOOKING" };
  }

  let candidate = trimmed;
  if (!candidate.includes("://")) {
    candidate = `http://${candidate}`;
  }

  let scheme = "";
  let hostname = "";

  try {
    const parsed = new URL(candidate);
    scheme = parsed.protocol.replace(":", "").toLowerCase();
    hostname = (parsed.hostname || "").toLowerCase();
  } catch {
    // Regex fallback
    const regexMatch = candidate.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]+)(.*)$/);
    if (regexMatch) {
      scheme = regexMatch[1].toLowerCase();
      let authority = regexMatch[2];
      if (authority.includes("@")) authority = authority.split("@")[1];
      if (authority.includes(":")) authority = authority.split(":")[0];
      hostname = authority.toLowerCase();
    } else {
      return { isValid: false, errorMessage: "Malformed URL format.", riskScore: 0, classification: "SAFE-LOOKING" };
    }
  }

  if (!hostname) {
    return { isValid: false, errorMessage: "Could not identify hostname.", riskScore: 0, classification: "SAFE-LOOKING" };
  }

  const warnings = [];
  let score = 0;

  if (scheme === "http") {
    warnings.push("HTTP detected");
    score += WEIGHTS.HTTP_SCHEME;
  }

  if (isStrictIpv4(hostname)) {
    warnings.push("IP address detected");
    score += WEIGHTS.IP_ADDRESS;
  }

  if (candidate.includes("@")) {
    warnings.push("@ symbol detected");
    score += WEIGHTS.AT_SYMBOL;
  }

  const hostLabels = hostname.split(".").filter(Boolean);
  if (hostLabels.length >= 5) {
    warnings.push("Excessive hostname segments detected (5 or more parts)");
    score += WEIGHTS.EXCESSIVE_SEGMENTS;
  }

  if (hostname.includes("xn--") || candidate.includes("xn--")) {
    warnings.push("Punycode hostname detected (xn--)");
    score += WEIGHTS.PUNYCODE;
  }

  if (trimmed.length > 100) {
    warnings.push("Unusually long URL (over 100 characters)");
    score += WEIGHTS.LONG_URL;
  }

  const lower = candidate.toLowerCase();
  const matchedKw = SUSPICIOUS_KEYWORDS.filter((kw) => lower.includes(kw));
  if (matchedKw.length > 0) {
    matchedKw.forEach((kw) => warnings.push(`Suspicious keyword: ${kw}`));
    const kwScore = WEIGHTS.KEYWORD_BASE + (matchedKw.length - 1) * WEIGHTS.KEYWORD_ADDITIONAL;
    score += Math.min(kwScore, 30);
  }

  for (const [pattern] of Object.entries(KNOWN_BRAND_IMPERSONATIONS)) {
    if (hostname.includes(pattern)) {
      warnings.push(`Brand impersonation detected: ${pattern}`);
      score += WEIGHTS.BRAND_IMPERSONATION;
      break;
    }
  }

  const hyphenCount = (hostname.match(/-/g) || []).length;
  const cleanHost = hostname.replace(/^www\./, "");
  if (hyphenCount >= 3) {
    warnings.push("Excessive hyphens detected");
    score += WEIGHTS.DOMAIN_ANOMALIES;
  } else if (/\d{4,}/.test(cleanHost)) {
    warnings.push("Numeric domain sequence detected");
    score += WEIGHTS.DOMAIN_ANOMALIES;
  } else if (/([a-zA-Z])\1{2,}/.test(cleanHost)) {
    warnings.push("Repeated character patterns detected");
    score += WEIGHTS.DOMAIN_ANOMALIES;
  }

  const finalScore = Math.min(Math.max(score, 0), 100);
  let classification = "SAFE-LOOKING";
  if (finalScore > 70) classification = "HIGH RISK";
  else if (finalScore > 40) classification = "MEDIUM RISK";
  else if (finalScore > 20) classification = "LOW RISK";

  return { isValid: true, riskScore: finalScore, classification, warnings };
}

// ----------------------------------------------------------------------------
// 30 FORMAL QA TEST CASES
// ----------------------------------------------------------------------------

test("TC-01: Clean benchmark URL https://www.google.com/", () => {
  const r = analyzeUrl("https://www.google.com/");
  assert.equal(r.isValid, true);
  assert.equal(r.riskScore, 0);
  assert.equal(r.classification, "SAFE-LOOKING");
});

test("TC-02: Clean benchmark URL https://github.com/ManishPatil2005", () => {
  const r = analyzeUrl("https://github.com/ManishPatil2005");
  assert.equal(r.isValid, true);
  assert.equal(r.riskScore, 0);
  assert.equal(r.classification, "SAFE-LOOKING");
});

test("TC-03: Sensitive path https://www.example.com/login", () => {
  const r = analyzeUrl("https://www.example.com/login");
  assert.equal(r.riskScore, 25);
  assert.equal(r.classification, "LOW RISK");
});

test("TC-04: Plain HTTP protocol http://www.example.com/", () => {
  const r = analyzeUrl("http://www.example.com/");
  assert.equal(r.riskScore, 15);
  assert.equal(r.classification, "SAFE-LOOKING");
});

test("TC-05: IP host with account keyword http://192.0.2.10/account", () => {
  const r = analyzeUrl("http://192.0.2.10/account");
  assert.equal(r.riskScore, 75);
  assert.equal(r.classification, "HIGH RISK");
});

test("TC-06: Canonical prompt target http://192.0.2.10/login", () => {
  const r = analyzeUrl("http://192.0.2.10/login");
  assert.equal(r.riskScore, 75);
  assert.equal(r.classification, "HIGH RISK");
});

test("TC-07: Userinfo disguise http://example.com@sample.invalid/login", () => {
  const r = analyzeUrl("http://example.com@sample.invalid/login");
  assert.equal(r.riskScore, 65);
  assert.equal(r.classification, "MEDIUM RISK");
});

test("TC-08: Subdomain nesting https://a.b.c.d.e.example.invalid/path", () => {
  const r = analyzeUrl("https://a.b.c.d.e.example.invalid/path");
  assert.equal(r.riskScore, 10);
  assert.equal(r.classification, "SAFE-LOOKING");
});

test("TC-09: Punycode IDN https://xn--example.invalid/", () => {
  const r = analyzeUrl("https://xn--example.invalid/");
  assert.equal(r.riskScore, 20);
  assert.equal(r.classification, "SAFE-LOOKING");
});

test("TC-10: Cyrillic homoglyph http://xn--e1afmkfd.example.invalid/account", () => {
  const r = analyzeUrl("http://xn--e1afmkfd.example.invalid/account");
  assert.equal(r.riskScore, 60);
  assert.equal(r.classification, "MEDIUM RISK");
});

test("TC-11: Brand impersonation https://g00gle.com/secure-login", () => {
  const r = analyzeUrl("https://g00gle.com/secure-login");
  assert.equal(r.riskScore, 60);
  assert.equal(r.classification, "MEDIUM RISK");
});

test("TC-12: Brand impersonation http://paypaI.com/verify-account", () => {
  const r = analyzeUrl("http://paypaI.com/verify-account");
  assert.equal(r.riskScore, 75);
  assert.equal(r.classification, "HIGH RISK");
});

test("TC-13: Brand impersonation https://micr0soft.com/update", () => {
  const r = analyzeUrl("https://micr0soft.com/update");
  assert.equal(r.riskScore, 55);
  assert.equal(r.classification, "MEDIUM RISK");
});

test("TC-14: Brand impersonation https://amaz0n-security.com/signin", () => {
  const r = analyzeUrl("https://amaz0n-security.com/signin");
  assert.equal(r.riskScore, 55);
  assert.equal(r.classification, "MEDIUM RISK");
});

test("TC-15: Excessive hyphens https://apple-id-verify-secure-login-account.com", () => {
  const r = analyzeUrl("https://apple-id-verify-secure-login-account.com");
  assert.equal(r.riskScore, 45);
  assert.equal(r.classification, "MEDIUM RISK");
});

test("TC-16: Numeric domain sequence https://paypal183749274.com/login", () => {
  const r = analyzeUrl("https://paypal183749274.com/login");
  assert.equal(r.riskScore, 40);
  assert.equal(r.classification, "LOW RISK");
});

test("TC-17: Repeated characters https://goooogle.com/search", () => {
  const r = analyzeUrl("https://goooogle.com/search");
  assert.equal(r.riskScore, 15);
  assert.equal(r.classification, "SAFE-LOOKING");
});

test("TC-18: Obfuscated URL length (>100 characters)", () => {
  const r = analyzeUrl("https://example.com/" + "a".repeat(100));
  assert.equal(r.riskScore, 10);
  assert.equal(r.classification, "SAFE-LOOKING");
});

test("TC-19: Compound multi-vector attack", () => {
  const r = analyzeUrl("http://198.51.100.25@phish.invalid/verify-password?t=" + "x".repeat(90));
  assert.ok(r.riskScore >= 75);
  assert.equal(r.classification, "HIGH RISK");
});

test("TC-20: Crypto wallet lure https://metamask-wallet-connect-airdrop.crypto.invalid/", () => {
  const r = analyzeUrl("https://metamask-wallet-connect-airdrop.crypto.invalid/");
  assert.equal(r.riskScore, 45); // 2 keywords (30) + 3 hyphens (15) = 45
  assert.equal(r.classification, "MEDIUM RISK");
});

test("TC-21: Banking phishing portal http://secure-online-banking-portal.update.com/otp", () => {
  const r = analyzeUrl("http://secure-online-banking-portal.update.com/otp");
  assert.equal(r.riskScore, 60); // HTTP (15) + 4 keywords (30) + 3 hyphens (15) = 60
  assert.equal(r.classification, "MEDIUM RISK");
});

test("TC-22: Empty string input", () => {
  const r = analyzeUrl("");
  assert.equal(r.isValid, false);
});

test("TC-23: Whitespace only input", () => {
  const r = analyzeUrl("   ");
  assert.equal(r.isValid, false);
});

test("TC-24: Malformed IPv6 brackets http://[bad-ipv6", () => {
  const r = analyzeUrl("http://[bad-ipv6");
  assert.equal(r.isValid, false);
});

test("TC-25: Missing scheme auto-normalization www.paypal.com", () => {
  const r = analyzeUrl("www.paypal.com");
  assert.equal(r.isValid, true);
  assert.equal(r.riskScore, 15); // Auto-prepends http:// -> flags HTTP (15)
});

test("TC-26: Non-routable octets http://999.999.999.999/", () => {
  const r = analyzeUrl("http://999.999.999.999/");
  assert.equal(r.riskScore, 15); // HTTP only (15), IP rejected as >255
});

test("TC-27: Custom port number https://example.com:8443/login", () => {
  const r = analyzeUrl("https://example.com:8443/login");
  assert.equal(r.riskScore, 25);
});

test("TC-28: Redirect query parameter https://example.com/?redirect=http://attacker.com", () => {
  const r = analyzeUrl("https://example.com/?redirect=http://attacker.com");
  assert.equal(r.isValid, true);
});

test("TC-29: Fragment anchor https://example.com/#login-section", () => {
  const r = analyzeUrl("https://example.com/#login-section");
  assert.equal(r.riskScore, 25);
});

test("TC-30: Claude.ai chat URL https://claude.ai/chat/c6bfaa97-602e-4ba5-9087-69c654157747", () => {
  const r = analyzeUrl("https://claude.ai/chat/c6bfaa97-602e-4ba5-9087-69c654157747");
  assert.equal(r.isValid, true);
  assert.equal(r.riskScore, 0);
  assert.equal(r.classification, "SAFE-LOOKING");
});
