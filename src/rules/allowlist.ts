/**
 * Bundled offline allowlist & Public Suffix List (PSL) helper.
 * Zero-network, deterministic lookup.
 */

// Two-part effective TLDs (country-code second level domains)
export const COMPOUND_TLDS = new Set([
  "co.uk",
  "org.uk",
  "me.uk",
  "ltd.uk",
  "plc.uk",
  "net.uk",
  "sch.uk",
  "ac.uk",
  "gov.uk",
  "co.in",
  "net.in",
  "org.in",
  "gen.in",
  "firm.in",
  "ind.in",
  "nic.in",
  "gov.in",
  "res.in",
  "edu.in",
  "com.au",
  "net.au",
  "org.au",
  "edu.au",
  "gov.au",
  "co.nz",
  "net.nz",
  "org.nz",
  "co.jp",
  "ne.jp",
  "or.jp",
  "go.jp",
  "ac.jp",
  "com.br",
  "net.br",
  "org.br",
  "com.sg",
  "edu.sg",
  "gov.sg",
  "com.my",
  "edu.my",
  "gov.my",
  "co.za",
  "org.za",
  "web.za",
  "com.cn",
  "net.cn",
  "org.cn",
  "gov.cn",
  "edu.cn",
  "com.de",
]);

// Verified high-reputation domains (for false positive mitigation)
export const VERIFIED_LEGITIMATE_DOMAINS = new Set([
  "google.com",
  "accounts.google.com",
  "mail.google.com",
  "docs.google.com",
  "drive.google.com",
  "microsoft.com",
  "login.microsoftonline.com",
  "live.com",
  "office.com",
  "apple.com",
  "icloud.com",
  "amazon.com",
  "aws.amazon.com",
  "github.com",
  "gitlab.com",
  "netflix.com",
  "paypal.com",
  "linkedin.com",
  "twitter.com",
  "x.com",
  "facebook.com",
  "instagram.com",
  "whatsapp.com",
  "youtube.com",
  "wikipedia.org",
  "claude.ai",
  "anthropic.com",
  "openai.com",
  "chatgpt.com",
  "sbi.co.in",
  "hdfcbank.com",
  "icicibank.com",
  "axisbank.com",
  "kotak.com",
  "paytm.com",
  "phonepe.com",
  "cloudflare.com",
  "stackoverflow.com",
  "reddit.com",
  "dropbox.com",
  "zoom.us",
  "spotify.com",
]);

/**
 * Parses hostname into root domain (eTLD+1) and subdomains.
 */
export function extractDomainParts(hostname: string): {
  rootDomain: string;
  subdomains: string[];
  tld: string;
} {
  const cleanHost = hostname.toLowerCase().replace(/\.+$/, "");
  const parts = cleanHost.split(".");

  if (parts.length <= 1) {
    return { rootDomain: cleanHost, subdomains: [], tld: "" };
  }

  // Check 2-level TLD (e.g. example.co.uk)
  if (parts.length >= 3) {
    const twoPartTld = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
    if (COMPOUND_TLDS.has(twoPartTld)) {
      const rootDomain = `${parts[parts.length - 3]}.${twoPartTld}`;
      const subdomains = parts.slice(0, parts.length - 3);
      return { rootDomain, subdomains, tld: twoPartTld };
    }
  }

  // Standard 1-level TLD (e.g. example.com)
  const tld = parts[parts.length - 1];
  const rootDomain = `${parts[parts.length - 2]}.${tld}`;
  const subdomains = parts.slice(0, parts.length - 2);

  return { rootDomain, subdomains, tld };
}

/**
 * Checks if a hostname belongs to an authentic allowlisted entity.
 */
export function isAllowlistedDomain(hostname: string): boolean {
  const clean = hostname.toLowerCase().replace(/\.+$/, "");
  if (VERIFIED_LEGITIMATE_DOMAINS.has(clean)) return true;

  const { rootDomain } = extractDomainParts(clean);
  return VERIFIED_LEGITIMATE_DOMAINS.has(rootDomain);
}
