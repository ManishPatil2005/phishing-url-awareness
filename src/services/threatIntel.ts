import { HeuristicFinding } from "@/types";

export interface ThreatExplanation {
  whyItMatters: string;
  realWorldTechnique: string;
  recommendedAction: string;
}

export const THREAT_KNOWLEDGE_BASE: Record<string, ThreatExplanation> = {
  HTTP_SCHEME: {
    whyItMatters:
      "Plaintext HTTP lacks cryptographic encryption. All exchanged passwords, credit cards, and session cookies are transmitted in the clear.",
    realWorldTechnique:
      "Adversary-in-the-Middle (MitM) packet sniffing on public Wi-Fi and lack of Certificate Authority validation.",
    recommendedAction:
      "Never enter passwords or personal data on unencrypted HTTP web pages. Verify HTTPS presence.",
  },
  IP_HOST: {
    whyItMatters:
      "Legitimate commercial organizations rely on branded domain names. Direct numeric IP addresses bypass domain reputation systems and hide true ownership.",
    realWorldTechnique:
      "Cybercriminals deploy ephemeral phishing servers on bulletproof hosting providers using bare IPv4 addresses to evade DNS blacklists.",
    recommendedAction:
      "Do not interact. Legitimate institutions (banks, cloud portals) never host authentication interfaces on bare IP addresses.",
  },
  AT_SYMBOL: {
    whyItMatters:
      "RFC 3986 specifies that text preceding an '@' symbol in the authority component represents user credentials (userinfo) and is ignored by the browser during routing.",
    realWorldTechnique:
      "Credential disguise: in 'http://paypal.com@evil.com', the victim sees 'paypal.com' and assumes safety, but the browser actually connects to 'evil.com'.",
    recommendedAction:
      "Inspect the character sequence strictly after the '@' delimiter to identify the true destination server.",
  },
  EXCESSIVE_SEGMENTS: {
    whyItMatters:
      "Concatenating multiple subdomain labels creates visual confusion, making malicious URLs appear complex and authoritative.",
    realWorldTechnique:
      "Subdomain spoofing: 'login.bank.com.security-verify.attacker.invalid' tricks users into focusing on the initial trusted brand token.",
    recommendedAction:
      "Read domains from right to left before the first single slash to identify the genuine authoritative root domain.",
  },
  PUNYCODE: {
    whyItMatters:
      "Punycode ('xn--') allows non-ASCII internationalized characters to be mapped to ASCII. Attackers use homoglyphs that visually mimic Latin letters.",
    realWorldTechnique:
      "IDN Homograph attacks: substituting the Cyrillic 'а' (U+0430) for Latin 'a' (U+0061) to produce indistinguishable fake brand domains.",
    recommendedAction:
      "Check address bar certificate details and look for 'xn--' prefixes in copy-pasted URLs.",
  },
  LONG_URL: {
    whyItMatters:
      "URLs exceeding 100 characters often attempt to push the malicious domain off the visible viewport on mobile devices and compact desktop browser bars.",
    realWorldTechnique:
      "Address bar overflow and query-string obfuscation hiding exploit payloads or redirection commands outside user sight.",
    recommendedAction:
      "Scroll through the full address bar or analyze in a dedicated security inspector before clicking.",
  },
  BRAND_IMPERSONATION: {
    whyItMatters:
      "Deliberate typographical substitution (e.g. replacing letter 'o' with zero '0', or 'l' with capital 'I') designed to trick human visual recognition.",
    realWorldTechnique:
      "Typosquatting & Combosquatting: registering 'g00gle.com' or 'paypaI.com' to intercept misdirected traffic and harvest credentials.",
    recommendedAction:
      "Look carefully at each character in the root domain. Manually type known official domain names directly into your browser bookmark bar.",
  },
  SUSPICIOUS_KEYWORD: {
    whyItMatters:
      "Phishing relies heavily on psychological urgency, fear of account suspension, or financial greed to induce hasty compliance.",
    realWorldTechnique:
      "Social engineering lures: embedding tokens like 'login', 'verify', 'update', 'banking', or 'wallet' into paths to mimic critical notifications.",
    recommendedAction:
      "Access critical accounts only through official mobile apps or previously saved browser bookmarks, never from unsolicited links.",
  },
  DOMAIN_ANOMALIES: {
    whyItMatters:
      "Excessive hyphens, unusual character repetitions, or long numeric strings within domain names are statistically correlated with throwaway phishing domains.",
    realWorldTechnique:
      "Automated domain generation algorithms (DGAs) and bulk phishing kit deployment platforms.",
    recommendedAction:
      "Exercise heightened scrutiny if a domain contains multiple hyphens or trailing numbers.",
  },
};

export function getThreatExplanation(code: string): ThreatExplanation {
  return (
    THREAT_KNOWLEDGE_BASE[code] || {
      whyItMatters: "This structural indicator deviates from standard web architecture practices.",
      realWorldTechnique: "Observed in social engineering and URL obfuscation methodologies.",
      recommendedAction: "Verify domain authenticity independently before proceeding.",
    }
  );
}
