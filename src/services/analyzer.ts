import { z } from "zod";
import {
  AnalysisResult,
  HeuristicFinding,
  ThreatClassification,
  UrlBreakdown,
} from "@/types";
import {
  KNOWN_BRAND_IMPERSONATIONS,
  SUSPICIOUS_KEYWORDS,
  WEIGHTS,
} from "@/lib/constants";
import { decomposeUrl } from "./breakdown";
import { getThreatExplanation } from "./threatIntel";

// Input validation schema using Zod
export const urlInputSchema = z.object({
  url: z
    .string()
    .trim()
    .min(1, "URL string cannot be empty.")
    .max(4096, "URL exceeds maximum supported length (4,096 characters)."),
});

export function isStrictIpv4(host: string): boolean {
  const parts = host.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    const n = parseInt(part, 10);
    return n >= 0 && n <= 255;
  });
}

export function detectBrandImpersonation(hostname: string): string[] {
  const detected: string[] = [];
  const hostLower = hostname.toLowerCase();

  for (const [pattern, brand] of Object.entries(KNOWN_BRAND_IMPERSONATIONS)) {
    if (hostLower.includes(pattern)) {
      detected.push(`${pattern} (Impersonating ${brand})`);
    }
  }
  return detected;
}

export function detectDomainAnomalies(hostname: string): string[] {
  const anomalies: string[] = [];
  
  // Check for excessive hyphens in domain
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    anomalies.push(`Excessive hyphens detected (${hyphenCount} hyphens)`);
  }

  // Check for excessive trailing numbers in root label
  const digitsMatch = hostname.match(/\d{4,}/);
  if (digitsMatch) {
    anomalies.push(`Suspicious numeric sequence in domain (${digitsMatch[0]})`);
  }

  // Check for character triplication (e.g., goooogle.com) excluding standard 'www.'
  const cleanHost = hostname.replace(/^www\./, "");
  if (/([a-zA-Z])\1{2,}/.test(cleanHost)) {
    anomalies.push("Repeated character patterns detected");
  }

  return anomalies;
}

export function analyzeUrl(rawUrlInput: string): AnalysisResult {
  const validation = urlInputSchema.safeParse({ url: rawUrlInput });

  const fallbackBreakdown: UrlBreakdown = {
    rawUrl: rawUrlInput,
    normalizedUrl: rawUrlInput,
    scheme: "",
    subdomains: [],
    subdomainString: "",
    rootDomain: "",
    hostname: "",
    tld: "",
    port: "",
    path: "",
    query: "",
    queryParams: {},
    fragment: "",
    hasUserinfo: false,
    userinfo: "",
  };

  if (!validation.success) {
    return {
      id: `scan-${Date.now()}`,
      rawUrl: rawUrlInput,
      normalizedUrl: rawUrlInput,
      isValid: false,
      errorMessage: validation.error.errors[0]?.message || "Invalid input URL.",
      riskScore: 0,
      classification: "SAFE-LOOKING",
      breakdown: fallbackBreakdown,
      findings: [],
      recommendation: "Provide a valid non-empty URL string to initiate security analysis.",
      executiveSummary: "Analysis halted: user input validation rejected the target string.",
      securityNotes: ["Ensure candidate string follows standard web address syntax."],
      timestamp: new Date().toISOString(),
    };
  }

  const rawUrl = validation.data.url;
  const breakdown = decomposeUrl(rawUrl);

  if (!breakdown.hostname) {
    return {
      id: `scan-${Date.now()}`,
      rawUrl,
      normalizedUrl: breakdown.normalizedUrl,
      isValid: false,
      errorMessage: "Could not identify a valid destination hostname.",
      riskScore: 0,
      classification: "SAFE-LOOKING",
      breakdown,
      findings: [],
      recommendation: "Verify that the link contains a recognizable domain name or IP address.",
      executiveSummary: "Analysis halted: No authoritative hostname could be extracted from input.",
      securityNotes: ["Syntax parsing failed to isolate authority section pursuant to RFC 3986."],
      timestamp: new Date().toISOString(),
    };
  }

  const findings: HeuristicFinding[] = [];
  let score = 0;

  // -------------------------------------------------------------------------
  // Heuristic 1: Plaintext Protocol Transport
  // -------------------------------------------------------------------------
  if (breakdown.scheme === "http") {
    const intel = getThreatExplanation("HTTP_SCHEME");
    findings.push({
      id: "H1-HTTP",
      code: "HTTP_SCHEME",
      title: "Plaintext HTTP Transport Detected",
      description: "URL utilizes unencrypted HTTP protocol rather than secure HTTPS.",
      severity: "medium",
      points: WEIGHTS.HTTP_SCHEME,
      ...intel,
    });
    score += WEIGHTS.HTTP_SCHEME;
  }

  // -------------------------------------------------------------------------
  // Heuristic 2: Numeric IPv4 Hostname Detection
  // -------------------------------------------------------------------------
  if (isStrictIpv4(breakdown.hostname)) {
    const intel = getThreatExplanation("IP_HOST");
    findings.push({
      id: "H2-IP",
      code: "IP_HOST",
      title: "Direct Numeric IP Address Hostname",
      description: `Hostname is configured as a bare decimal IPv4 address (${breakdown.hostname}) rather than a registered DNS domain name.`,
      severity: "critical",
      points: WEIGHTS.IP_ADDRESS,
      ...intel,
    });
    score += WEIGHTS.IP_ADDRESS;
  }

  // -------------------------------------------------------------------------
  // Heuristic 3: Userinfo Delimiter '@' Exploitation
  // -------------------------------------------------------------------------
  if (breakdown.normalizedUrl.includes("@") || breakdown.hasUserinfo) {
    const intel = getThreatExplanation("AT_SYMBOL");
    findings.push({
      id: "H3-AT",
      code: "AT_SYMBOL",
      title: "Userinfo '@' Symbol Disguise Present",
      description: "URL contains an '@' character within authority section, commonly used to disguise actual destination server.",
      severity: "high",
      points: WEIGHTS.AT_SYMBOL,
      ...intel,
    });
    score += WEIGHTS.AT_SYMBOL;
  }

  // -------------------------------------------------------------------------
  // Heuristic 4: Excessive Hostname Segmentation
  // -------------------------------------------------------------------------
  const hostLabels = breakdown.hostname.split(".").filter(Boolean);
  if (hostLabels.length >= 5) {
    const intel = getThreatExplanation("EXCESSIVE_SEGMENTS");
    findings.push({
      id: "H4-SEGMENTS",
      code: "EXCESSIVE_SEGMENTS",
      title: "Excessive Subdomain Segmentation Depth",
      description: `Hostname is partitioned into ${hostLabels.length} dot-separated labels (>= 5), indicating potential subdomain spoofing.`,
      severity: "medium",
      points: WEIGHTS.EXCESSIVE_SEGMENTS,
      ...intel,
    });
    score += WEIGHTS.EXCESSIVE_SEGMENTS;
  }

  // -------------------------------------------------------------------------
  // Heuristic 5: Punycode IDN Marker ('xn--')
  // -------------------------------------------------------------------------
  if (breakdown.hostname.includes("xn--")) {
    const intel = getThreatExplanation("PUNYCODE");
    findings.push({
      id: "H5-PUNYCODE",
      code: "PUNYCODE",
      title: "Punycode (xn--) Homoglyph Domain Marker",
      description: "Hostname incorporates Internationalized Domain Name (IDN) Punycode encoding, often used in look-alike character substitution.",
      severity: "high",
      points: WEIGHTS.PUNYCODE,
      ...intel,
    });
    score += WEIGHTS.PUNYCODE;
  }

  // -------------------------------------------------------------------------
  // Heuristic 6: Excessive URL Length (> 100 characters)
  // -------------------------------------------------------------------------
  if (rawUrl.length > 100) {
    const intel = getThreatExplanation("LONG_URL");
    findings.push({
      id: "H6-LENGTH",
      code: "LONG_URL",
      title: "Unusually Long URL (Over 100 Characters)",
      description: `Total URL string length is ${rawUrl.length} characters, exceeding typical navigation boundaries and risking address bar truncation.`,
      severity: "low",
      points: WEIGHTS.LONG_URL,
      ...intel,
    });
    score += WEIGHTS.LONG_URL;
  }

  // -------------------------------------------------------------------------
  // Heuristic 7: Social Engineering Keyword Scanner (13 Keywords)
  // -------------------------------------------------------------------------
  const lowerUrl = breakdown.normalizedUrl.toLowerCase();
  const detectedKeywords: string[] = [];

  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (lowerUrl.includes(kw)) {
      detectedKeywords.push(kw);
    }
  }

  if (detectedKeywords.length > 0) {
    const intel = getThreatExplanation("SUSPICIOUS_KEYWORD");
    const kwScore =
      WEIGHTS.KEYWORD_BASE +
      (detectedKeywords.length - 1) * WEIGHTS.KEYWORD_ADDITIONAL;
    const boundedKwScore = Math.min(kwScore, 30);

    findings.push({
      id: "H7-KEYWORDS",
      code: "SUSPICIOUS_KEYWORD",
      title: `Social Engineering Keywords Detected (${detectedKeywords.length})`,
      description: `Identified sensitive credential/urgency tokens: [${detectedKeywords.join(", ")}].`,
      severity: detectedKeywords.length > 2 ? "high" : "medium",
      points: boundedKwScore,
      ...intel,
    });
    score += boundedKwScore;
  }

  // -------------------------------------------------------------------------
  // Heuristic 8: Brand Impersonation & Typosquatting
  // -------------------------------------------------------------------------
  const impersonatedBrands = detectBrandImpersonation(breakdown.hostname);
  if (impersonatedBrands.length > 0) {
    const intel = getThreatExplanation("BRAND_IMPERSONATION");
    findings.push({
      id: "H8-IMPERSONATION",
      code: "BRAND_IMPERSONATION",
      title: "Brand Impersonation / Typosquatting Detected",
      description: `Hostname contains visual look-alike domain patterns: ${impersonatedBrands.join("; ")}.`,
      severity: "critical",
      points: WEIGHTS.BRAND_IMPERSONATION,
      ...intel,
    });
    score += WEIGHTS.BRAND_IMPERSONATION;
  }

  // -------------------------------------------------------------------------
  // Heuristic 9: Domain Pattern Anomalies
  // -------------------------------------------------------------------------
  const domainAnomalies = detectDomainAnomalies(breakdown.hostname);
  if (domainAnomalies.length > 0) {
    const intel = getThreatExplanation("DOMAIN_ANOMALIES");
    findings.push({
      id: "H9-ANOMALIES",
      code: "DOMAIN_ANOMALIES",
      title: "Domain Syntactic Pattern Anomalies",
      description: `Observed abnormal structural signatures: ${domainAnomalies.join("; ")}.`,
      severity: "low",
      points: WEIGHTS.DOMAIN_ANOMALIES,
      ...intel,
    });
    score += WEIGHTS.DOMAIN_ANOMALIES;
  }

  // Bound score strictly to 0 - 100
  const finalScore = Math.min(Math.max(score, 0), 100);

  // Determine threat category
  let classification: ThreatClassification = "SAFE-LOOKING";
  let recommendation = "No listed warning signs found. This does NOT prove safety. Always verify.";

  if (finalScore === 0) {
    classification = "SAFE-LOOKING";
    recommendation =
      "No listed warning signs found. This does NOT prove safety. Always verify domain authenticity independently.";
  } else if (finalScore <= 20) {
    classification = "SAFE-LOOKING";
    recommendation =
      "Minimal structural anomalies detected. Exercise standard vigilance before interacting.";
  } else if (finalScore <= 40) {
    classification = "LOW RISK";
    recommendation =
      "Minor threat indicators observed. Verify authenticity before submitting credentials or downloading attachments.";
  } else if (finalScore <= 70) {
    classification = "MEDIUM RISK";
    recommendation =
      "Notable suspicious indicators detected. Exercise high caution and refrain from entering sensitive personal data.";
  } else {
    classification = "HIGH RISK";
    recommendation =
      "Review carefully before interacting. High probability of deceptive or malicious heuristic patterns.";
  }

  const executiveSummary =
    findings.length === 0
      ? "Target URL exhibits zero visible syntactic red flags under static inspection. Note that absence of evidence is not evidence of absence; sophisticated spear-phishing often employs clean domains."
      : `Static heuristic inspection flagged ${findings.length} threat indicators accumulating an aggregate risk score of ${finalScore}/100 (${classification}). Primary concern: ${findings[0]?.title}.`;

  const securityNotes: string[] = [
    "Analysis conducted purely in memory via deterministic RFC 3986 lexical decomposition.",
    "Zero network sockets, DNS requests, or threat intelligence reputation API lookups were performed.",
    "Results represent heuristic threat indicators rather than definitive sandbox detonation conclusions.",
  ];

  return {
    id: `scan-${Date.now()}`,
    rawUrl,
    normalizedUrl: breakdown.normalizedUrl,
    isValid: true,
    riskScore: finalScore,
    classification,
    breakdown,
    findings,
    recommendation,
    executiveSummary,
    securityNotes,
    timestamp: new Date().toISOString(),
  };
}
