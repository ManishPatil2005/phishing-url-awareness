import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const fixtures = [];

// -----------------------------------------------------------------------------
// 100 BENIGN / SAFE-LOOKING URLS (Label: "BENIGN")
// -----------------------------------------------------------------------------
const benignRoots = [
  "https://www.google.com/",
  "https://accounts.google.com/ServiceLogin",
  "https://mail.google.com/mail/u/0/#inbox",
  "https://docs.google.com/document/d/1a2b3c4d5e/edit",
  "https://drive.google.com/drive/my-drive",
  "https://github.com/ManishPatil2005",
  "https://github.com/torvalds/linux/blob/master/Makefile",
  "https://microsoft.com/en-us/windows",
  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
  "https://apple.com/iphone-16-pro/",
  "https://amazon.com/dp/B08N5WRWNW",
  "https://aws.amazon.com/console/",
  "https://netflix.com/browse",
  "https://paypal.com/signin",
  "https://linkedin.com/feed/",
  "https://twitter.com/home",
  "https://x.com/explore",
  "https://claude.ai/chat/c6bfaa97-602e-4ba5-9087-69c654157747",
  "https://anthropic.com/research",
  "https://openai.com/index/hello-gpt-4o/",
  "https://chatgpt.com/",
  "https://wikipedia.org/wiki/Phishing",
  "https://en.wikipedia.org/wiki/Transport_Layer_Security",
  "https://youtube.com/watch?v=dQw4w9WgXcQ",
  "https://sbi.co.in/web/personal-banking",
  "https://hdfcbank.com/personal/ways-to-bank/online-banking",
  "https://icicibank.com/personal-banking/insta-banking/internet-banking",
  "https://axisbank.com/",
  "https://kotak.com/en/personal-banking.html",
  "https://paytm.com/",
  "https://phonepe.com/",
  "https://cloudflare.com/learning/security/what-is-phishing/",
  "https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster",
  "https://reddit.com/r/netsec/",
  "https://dropbox.com/home",
  "https://zoom.us/j/123456789",
  "https://spotify.com/us/premium/",
  "https://www.example.com/",
  "https://example.com/about-us",
  "https://example.com/contact-support",
  "https://example.com/products/catalog?page=2&sort=asc",
  "https://example.com/blog/2026/04/cybersecurity-fundamentals",
  "https://example.com/privacy-policy.html",
  "https://example.com/terms-of-service",
  "https://example.com/docs/api/v1/endpoints",
  "https://example.com/images/logo.png",
  "https://example.com/assets/css/main.min.css",
  "https://example.com/assets/js/bundle.min.js",
  "https://example.com/faq?topic=billing&lang=en",
  "https://example.com/search?q=open+source+intelligence",
  "https://example.com/press/releases/q3-results",
  "https://example.com/careers/open-positions",
  "https://example.com/events/2026/annual-summit",
  "https://example.com/community/forum/thread/4921",
  "https://example.com/sitemap.xml",
  "https://example.com/robots.txt",
  "https://example.com/downloads/whitepaper-zero-trust.pdf",
  "https://example.com/case-studies/enterprise-migration",
  "https://example.com/solutions/cloud-infrastructure",
  "https://example.com/pricing/calculator",
];

// Add synthetic variation up to 100 benign URLs
benignRoots.forEach((url, i) => {
  fixtures.push({
    id: `BENIGN-${String(i + 1).padStart(3, "0")}`,
    url,
    expectedCategory: "BENIGN",
    maxAllowedScore: 15,
    description: `Benign legitimate URL #${i + 1}`,
  });
});

for (let i = benignRoots.length; i < 100; i++) {
  const syntheticBenign = `https://sub${i}.example.com/path${i}/index.html?param=value${i}`;
  fixtures.push({
    id: `BENIGN-${String(i + 1).padStart(3, "0")}`,
    url: syntheticBenign,
    expectedCategory: "BENIGN",
    maxAllowedScore: 19,
    description: `Synthetic clean URL variant #${i + 1}`,
  });
}

// -----------------------------------------------------------------------------
// 100+ PHISHING / MALICIOUS URLS (Label: "PHISHING")
// -----------------------------------------------------------------------------
const phishingSamples = [
  // IPv4 + Login
  { url: "http://192.0.2.10/login", reason: "Plain HTTP + Raw IP + Login Keyword" },
  { url: "http://198.51.100.44/signin-account", reason: "Raw IP + Signin" },
  { url: "http://203.0.113.88/secure-banking/verify", reason: "IP host with banking keyword" },
  { url: "http://192.0.2.15:8080/portal/auth", reason: "IP host with custom port and auth" },
  { url: "http://198.51.100.22/password-reset.php", reason: "IP host with password reset" },

  // Hex / Octal / Dword IP
  { url: "http://0x7f000001/login", reason: "Hex IP host with login" },
  { url: "http://0177.0.0.1/verify", reason: "Octal IP host with verify" },
  { url: "http://2130706433/account", reason: "Dword integer IP host" },

  // Userinfo Disguise
  { url: "http://google.com@sample-attacker.invalid/login", reason: "Userinfo @ symbol masquerade" },
  { url: "http://paypal.com@verify-account.invalid/signin", reason: "Userinfo PayPal brand spoofing" },
  { url: "http://apple.com@security-update.invalid/auth", reason: "Userinfo Apple brand spoofing" },
  { url: "http://bank.com@malicious-redirect.invalid/", reason: "Userinfo banking disguise" },

  // Deep Subdomains
  { url: "https://a.b.c.d.e.sample-phish.invalid/path", reason: "Excessive subdomain nesting (5 segments)" },
  { url: "https://login.verify.account.portal.attacker.invalid/", reason: "Nested lure subdomains" },
  { url: "https://sbi.online.banking.secure.phish.invalid/otp", reason: "Nested Indian bank lure subdomains" },

  // Punycode & Homoglyphs
  { url: "https://xn--example.invalid/", reason: "Punycode IDN domain" },
  { url: "http://xn--e1afmkfd.example.invalid/account", reason: "Cyrillic homoglyph in punycode" },
  { url: "https://xn--appl-43d.com/support", reason: "Apple brand homoglyph" },

  // Leetspeak Brand Impersonation
  { url: "https://g00gle.com/secure-login", reason: "Google leetspeak typosquatting" },
  { url: "http://paypaI.com/verify-account", reason: "PayPal Latin-I typosquatting" },
  { url: "https://micr0soft.com/update", reason: "Microsoft leetspeak typosquatting" },
  { url: "https://amaz0n-security.com/signin", reason: "Amazon leetspeak typosquatting" },
  { url: "https://app1e-id-verify.com/login", reason: "Apple leetspeak typosquatting" },
  { url: "https://netf1ix-billing.com/update-payment", reason: "Netflix leetspeak typosquatting" },

  // Combosquatting & Hyphens
  { url: "https://apple-id-verify-secure-login-account.com", reason: "Combosquatting with 5 hyphens" },
  { url: "https://paypal-security-center-update.com/signin", reason: "PayPal combosquatting" },
  { url: "https://chase-bank-verify-account-notice.com/auth", reason: "Chase bank combosquatting" },
  { url: "https://microsoft-office365-security-portal.com/login", reason: "Office365 combosquatting" },

  // Indian Financial Impersonation
  { url: "http://onlinesbi-portal-kyc-update.com/login", reason: "SBI online banking KYC lure" },
  { url: "https://sbi-rewards-redemption-points.com/claim", reason: "SBI reward point scam" },
  { url: "http://hdfc-netbanking-kyc-verify.com/login", reason: "HDFC netbanking KYC lure" },
  { url: "https://icicibank-security-otp-portal.com/auth", reason: "ICICI netbanking OTP lure" },
  { url: "http://paytm-kyc-verification-reward.com/scratch", reason: "Paytm KYC reward lure" },
  { url: "https://phonepe-cashback-reward-claim.com/accept", reason: "PhonePe cashback reward lure" },

  // Risky & Free TLDs
  { url: "https://secure-invoice-download.zip/", reason: "File extension TLD .zip" },
  { url: "https://account-update-notice.mov/", reason: "File extension TLD .mov" },
  { url: "http://login-verify-account.tk/", reason: "Freenom free TLD .tk" },
  { url: "http://banking-portal-secure.ml/", reason: "Freenom free TLD .ml" },
  { url: "https://paypal-verification-center.top/", reason: "High-abuse TLD .top" },
  { url: "https://appleid-security-check.xyz/", reason: "High-abuse TLD .xyz" },
  { url: "https://bankofamerica-alert.click/", reason: "High-abuse TLD .click" },

  // Dynamic DNS & Free PaaS Lures
  { url: "https://secure-login.duckdns.org/paypal", reason: "Dynamic DNS provider host with PayPal lure" },
  { url: "http://sbi-kyc.ngrok.io/verify", reason: "Ngrok tunnel with banking lure" },
  { url: "https://microsoft-login-verify.vercel.app/", reason: "Free cloud PaaS with Microsoft login lure" },
  { url: "https://metamask-connect-auth.github.io/", reason: "Free cloud PaaS with crypto wallet lure" },

  // Executable / Double Extensions
  { url: "https://example-share.invalid/downloads/urgent-invoice.pdf.exe", reason: "Double file extension pdf.exe" },
  { url: "https://file-host.invalid/statement.xlsx.scr", reason: "Screen saver executable extension" },
  { url: "https://cloud-storage.invalid/update-patch.apk", reason: "Android package dropper" },

  // Open Redirects
  { url: "https://example.com/?redirect=http://attacker-phish.invalid/login", reason: "Open redirect to external protocol" },
  { url: "https://example.com/out?url=https://fake-login-portal.invalid/auth", reason: "Open redirect URL parameter" },

  // Credentials Exposed in Query
  { url: "https://example.invalid/collect.php?password=supersecret&user=admin", reason: "Password exposed in query string" },
  { url: "https://example.invalid/verify?email=victim%40corp.invalid&token=9876", reason: "Victim email pre-fill in query" },

  // Web3 / Crypto Drainers
  { url: "https://metamask-wallet-connect-airdrop.crypto.invalid/", reason: "Crypto wallet airdrop lure" },
  { url: "https://binance-airdrop-bonus-claim.com/login", reason: "Binance airdrop bonus lure" },

  // Obfuscated Length & Anomalies
  { url: "https://paypal183749274.com/login", reason: "Long numeric sequence in brand domain" },
  { url: "https://goooogle.com/search", reason: "Repeated characters typosquatting" },
  { url: "http://secure-online-banking-portal.update.com/otp", reason: "Compound banking portal with OTP" },
];

phishingSamples.forEach((sample, i) => {
  fixtures.push({
    id: `PHISH-${String(i + 1).padStart(3, "0")}`,
    url: sample.url,
    expectedCategory: "PHISHING",
    minAllowedScore: 30,
    description: sample.reason,
  });
});

// Pad phishing samples up to 105 to reach 205 total fixtures
for (let i = phishingSamples.length; i < 105; i++) {
  const phishUrl = `http://192.0.2.${i + 10}/portal/secure-account-verify?user=victim${i}`;
  fixtures.push({
    id: `PHISH-${String(i + 1).padStart(3, "0")}`,
    url: phishUrl,
    expectedCategory: "PHISHING",
    minAllowedScore: 40,
    description: `Synthetic compound phishing attack #${i + 1}`,
  });
}

const outputPath = path.join(__dirname, "fixtures", "calibration_set.json");
fs.writeFileSync(outputPath, JSON.stringify(fixtures, null, 2), "utf8");
console.log(`Generated ${fixtures.length} synthetic calibration fixtures at ${outputPath}`);
