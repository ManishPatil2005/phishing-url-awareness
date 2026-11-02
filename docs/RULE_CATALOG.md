# Threat Engine v2.0 - Complete Rule Catalog
**Total Active Heuristic Rules**: 114  
**Architecture**: Pure, Deterministic, Zero-Network In-Memory Inspection  
**Standard Compliance**: RFC 3986, RFC 3987, OWASP Top 10, MITRE ATT&CK T1566  
**Last Updated**: 2026-11-02T18:24:41.507Z

---

## Table of Categories
- [Structure Rules (15)](#category-structure)
- [Host & Domain Rules (15)](#category-host)
- [Encoding & Obfuscation Rules (15)](#category-encoding)
- [Top-Level Domain (TLD) Rules (15)](#category-tld)
- [Lexical & Social Engineering Rules (15)](#category-lexical)
- [Brand Impersonation & Typosquatting Rules (15)](#category-brand)
- [Path & File Payload Rules (12)](#category-path)
- [Query & Redirection Rules (12)](#category-query)

---

<a id="category-structure"></a>
## Category: STRUCTURE (15 Rules)

### [STR-001] Plain HTTP Scheme (Unencrypted)
- **Severity**: `MEDIUM` | **Weight**: `+15` | **Confidence**: `95%`
- **Description**: The URL uses plaintext unencrypted HTTP instead of modern TLS/HTTPS.
- **Why It Matters**: Plaintext HTTP exposes credentials to network eavesdropping.
- **Real-World Technique**: Adversaries deploy unencrypted pages for short-lived phishing campaigns.
- **Recommended Action**: Avoid entering sensitive data on unencrypted sites.
- **References**: `RFC 2616`, `OWASP A02:2021-Cryptographic Failures`
- **Tags**: `#scheme` `#transport-security`

### [STR-002] Dotted-Decimal IPv4 Hostname
- **Severity**: `HIGH` | **Weight**: `+35` | **Confidence**: `99%`
- **Description**: Hostname is represented as a raw dotted-decimal IPv4 address instead of a domain name.
- **Why It Matters**: Direct IP addressing circumvents domain reputation and brand identification.
- **Real-World Technique**: Attackers deploy phishing portals directly on unmanaged IP VPS hosts.
- **Recommended Action**: Do not enter authentication details on raw IP addresses.
- **References**: `RFC 3986`, `MITRE ATT&CK T1566`
- **Tags**: `#host` `#ip-address`

### [STR-003] Hex-Encoded IP Address Host
- **Severity**: `CRITICAL` | **Weight**: `+40` | **Confidence**: `95%`
- **Description**: Hostname is an obfuscated hexadecimal representation of an IP address.
- **Why It Matters**: Hex encoding is an evasion tactic to disguise IP hosts.
- **Real-World Technique**: Bypasses standard dotted-decimal regex filters.
- **Recommended Action**: Block navigation and flag for security operations review.
- **References**: `RFC 3986`, `CWE-116`
- **Tags**: `#evasion` `#obfuscation`

### [STR-004] Octal-Encoded IP Address Host
- **Severity**: `CRITICAL` | **Weight**: `+40` | **Confidence**: `95%`
- **Description**: Hostname utilizes leading-zero octal numbers to disguise an IP address.
- **Why It Matters**: Octal IP formats deceive casual users and static string filters.
- **Real-World Technique**: Conceals true server destination using POSIX base-8 parsing quirks.
- **Recommended Action**: Block and investigate link origin.
- **References**: `POSIX inet_addr`, `RFC 3986`
- **Tags**: `#evasion` `#octal`

### [STR-005] Dword (Integer) IP Host
- **Severity**: `CRITICAL` | **Weight**: `+40` | **Confidence**: `98%`
- **Description**: Hostname is represented as a single large 32-bit integer (Dword).
- **Why It Matters**: Dword IP numbers are standard evasion vectors in phishing campaigns.
- **Real-World Technique**: Converts dotted-quad IP to a single 32-bit integer.
- **Recommended Action**: Treat with immediate suspicion.
- **References**: `RFC 3986 §3.2.2`
- **Tags**: `#dword` `#ip-address`

### [STR-006] Bracketed IPv6 Literal Host
- **Severity**: `HIGH` | **Weight**: `+30` | **Confidence**: `95%`
- **Description**: Hostname contains a bracketed IPv6 address literal.
- **Why It Matters**: Raw IPv6 addresses in consumer URLs usually indicate unauthorized or direct machine communications.
- **Real-World Technique**: Evades legacy IPv4 threat detection feeds.
- **Recommended Action**: Verify destination legitimacy.
- **References**: `RFC 3986`, `RFC 4291`
- **Tags**: `#ipv6`

### [STR-007] Private or Loopback IP Range
- **Severity**: `MEDIUM` | **Weight**: `+20` | **Confidence**: `90%`
- **Description**: Host targets RFC 1918 private subnets or RFC 5735 loopback/link-local space.
- **Why It Matters**: Private IP links in external communications often indicate SSRF or cross-site probing.
- **Real-World Technique**: Coerces browser into attacking local routers or developer daemons.
- **Recommended Action**: Do not open links pointing to local/private IP addresses from unknown emails.
- **References**: `RFC 1918`, `CWE-918`
- **Tags**: `#ssrf` `#rfc1918`

### [STR-008] Userinfo Authentication Delimiter (@)
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `99%`
- **Description**: The '@' symbol is embedded in the URL authority section.
- **Why It Matters**: The '@' symbol tricks victims into mistaking the username field for the destination host.
- **Real-World Technique**: Prefixes trusted brand names before the '@' sign to camouflage attacker domain.
- **Recommended Action**: Always check the domain that appears immediately AFTER the '@' symbol.
- **References**: `RFC 3986 §3.2.1`
- **Tags**: `#userinfo` `#spoofing`

### [STR-009] Multiple Userinfo (@) Delimiters
- **Severity**: `CRITICAL` | **Weight**: `+35` | **Confidence**: `99%`
- **Description**: URL contains two or more '@' symbols in the string.
- **Why It Matters**: Multiple '@' symbols cause parser discrepancies between firewalls and browsers.
- **Real-World Technique**: Parser confusion to bypass enterprise security gateways.
- **Recommended Action**: Block immediately.
- **References**: `RFC 3986`
- **Tags**: `#parser-differential`

### [STR-010] Non-Standard HTTP/HTTPS Port
- **Severity**: `MEDIUM` | **Weight**: `+15` | **Confidence**: `85%`
- **Description**: The URL specifies a custom or non-standard port number.
- **Why It Matters**: Non-standard ports often indicate ad-hoc, temporary, or compromised hosting environments.
- **Real-World Technique**: Runs phishing scripts on alternate ports to bypass shared web server configurations.
- **Recommended Action**: Exercise vigilance on non-standard ports.
- **References**: `IANA Port Registry`
- **Tags**: `#port`

### [STR-011] Default Port Explicitly Declared
- **Severity**: `INFO` | **Weight**: `+5` | **Confidence**: `75%`
- **Description**: The standard port (:80 or :443) is explicitly declared in the URL authority.
- **Why It Matters**: Explicit default ports frequently originate from automated generation scripts.
- **Real-World Technique**: Tooling artifacts in mass phishing frameworks.
- **Recommended Action**: Low severity; check other indicators.
- **References**: `RFC 3986`
- **Tags**: `#port`

### [STR-012] High Overall URL Length (> 100 characters)
- **Severity**: `LOW` | **Weight**: `+10` | **Confidence**: `80%`
- **Description**: Total character count of the URL exceeds standard benign length thresholds.
- **Why It Matters**: Excessive length conceals payload components from browser address bars.
- **Real-World Technique**: Pads URL to hide malicious host behind mobile viewport boundaries.
- **Recommended Action**: Inspect full URL string.
- **References**: `RFC 3986`
- **Tags**: `#length`

### [STR-013] Extreme Obfuscated URL Length (> 250 characters)
- **Severity**: `MEDIUM` | **Weight**: `+20` | **Confidence**: `88%`
- **Description**: Total character count of the URL exceeds 250 characters.
- **Why It Matters**: Extreme length is often used to embed serialized payloads or base64 tracking tokens.
- **Real-World Technique**: Encodes entire redirection state in URL query.
- **Recommended Action**: Examine embedded query parameters closely.
- **References**: `RFC 3986`
- **Tags**: `#length`

### [STR-014] Backslash Confusion in Authority
- **Severity**: `CRITICAL` | **Weight**: `+35` | **Confidence**: `98%`
- **Description**: The URL contains backslashes ('\') in the authority or scheme separator.
- **Why It Matters**: Backslashes induce parser differences between browsers and security filtering proxies.
- **Real-World Technique**: Exploits WHATWG browser path normalization to camouflage destination domain.
- **Recommended Action**: Reject URL unconditionally.
- **References**: `WHATWG URL Spec`, `CWE-1286`
- **Tags**: `#parser-confusion` `#backslash`

### [STR-015] High Special Character Ratio (> 20%)
- **Severity**: `MEDIUM` | **Weight**: `+15` | **Confidence**: `85%`
- **Description**: A high proportion of characters in the URL are non-alphanumeric punctuation marks.
- **Why It Matters**: High symbol density indicates encoding chains or evasion delimiter chaining.
- **Real-World Technique**: Breaks IDS signature matching with excessive symbols.
- **Recommended Action**: Sanitize and inspect query parameters.
- **References**: `OWASP`
- **Tags**: `#obfuscation`


<a id="category-host"></a>
## Category: HOST (15 Rules)

### [HST-001] Excessive Subdomain Segments (>= 5)
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `90%`
- **Description**: Hostname has 5 or more dot-separated subdomain labels.
- **Why It Matters**: Deep subdomain nesting pushes apex domain out of view.
- **Real-World Technique**: Hides true registered domain behind long prefix labels.
- **Recommended Action**: Inspect apex domain right before TLD.
- **References**: `RFC 1034`
- **Tags**: `#subdomains`

### [HST-002] Moderate Subdomain Nesting (3-4 Segments)
- **Severity**: `LOW` | **Weight**: `+8` | **Confidence**: `75%`
- **Description**: Hostname has 3 or 4 subdomain labels on non-allowlisted domain.
- **Why It Matters**: Multiple subdomains may indicate layered redirect infrastructure.
- **Real-World Technique**: Uses subdomains for ephemeral routing.
- **Recommended Action**: Check apex domain.
- **References**: `RFC 1034`
- **Tags**: `#subdomains`

### [HST-003] Brand Keyword in Foreign Subdomain
- **Severity**: `CRITICAL` | **Weight**: `+35` | **Confidence**: `96%`
- **Description**: A major brand name is embedded as a subdomain on an unrelated domain.
- **Why It Matters**: Trusted brand names in foreign subdomains are classic impersonation vectors.
- **Real-World Technique**: Pretends to be legitimate brand via subdomain while apex domain belongs to attacker.
- **Recommended Action**: Inspect the registered apex domain.
- **References**: `MITRE ATT&CK T1566.002`
- **Tags**: `#brand` `#spoofing`

### [HST-004] Excessive Hyphens in Hostname (>= 3)
- **Severity**: `MEDIUM` | **Weight**: `+15` | **Confidence**: `88%`
- **Description**: The hostname contains 3 or more hyphens.
- **Why It Matters**: Multiple hyphens indicate combosquatting or keyword stitching.
- **Real-World Technique**: Chains brand and security words using hyphens.
- **Recommended Action**: Verify against authentic company domain.
- **References**: `US-CERT Combosquatting Alert`
- **Tags**: `#hyphens` `#combosquatting`

### [HST-005] Suspicious Numeric Sequence in Hostname (>= 4 digits)
- **Severity**: `MEDIUM` | **Weight**: `+15` | **Confidence**: `85%`
- **Description**: Hostname contains 4 or more numbers, common in automated phishing domain generation.
- **Why It Matters**: Long numbers in domain names correlate strongly with disposable campaign domains.
- **Real-World Technique**: Appends numbers to brand names for mass registration.
- **Recommended Action**: Confirm domain on company website.
- **References**: `APWG Survey`
- **Tags**: `#numeric` `#automation`

### [HST-006] Excessive Character Repetition (> 2 identical characters)
- **Severity**: `MEDIUM` | **Weight**: `+15` | **Confidence**: `88%`
- **Description**: Hostname repeats the same character 3 or more times (excluding 'www').
- **Why It Matters**: Duplicated characters are designed to exploit user typing mistakes.
- **Real-World Technique**: Registers domains with doubled or tripled letters.
- **Recommended Action**: Check domain spelling closely.
- **References**: `Typosquatting Standards`
- **Tags**: `#typosquatting`

### [HST-007] Trailing Dot Fully Qualified Domain (FQDN)
- **Severity**: `LOW` | **Weight**: `+10` | **Confidence**: `90%`
- **Description**: The hostname ends with a trailing dot (DNS root notation).
- **Why It Matters**: Trailing dot can bypass strict regex string matching while resolving in DNS.
- **Real-World Technique**: Evades string matching in firewalls.
- **Recommended Action**: Strip trailing dot and evaluate normalized host.
- **References**: `RFC 1034`
- **Tags**: `#fqdn` `#dns`

### [HST-008] Long Domain Label (> 40 characters)
- **Severity**: `MEDIUM` | **Weight**: `+15` | **Confidence**: `85%`
- **Description**: A single DNS label between dots exceeds 40 characters.
- **Why It Matters**: Excessively long labels are characteristic of DGA or obfuscation.
- **Real-World Technique**: DGA domain generation.
- **Recommended Action**: Inspect domain structure.
- **References**: `RFC 1035`
- **Tags**: `#label-length`

### [HST-009] Long Overall Hostname (> 60 characters)
- **Severity**: `MEDIUM` | **Weight**: `+15` | **Confidence**: `85%`
- **Description**: Total length of the hostname exceeds 60 characters.
- **Why It Matters**: Excessively long hostnames truncate address bar viewports.
- **Real-World Technique**: Conceals apex domain behind mobile browser limits.
- **Recommended Action**: Inspect full hostname.
- **References**: `RFC 1035`
- **Tags**: `#length`

### [HST-010] Malformed Hyphen at Label Boundary
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `95%`
- **Description**: Hostname label begins or ends with a hyphen, violating DNS specifications.
- **Why It Matters**: Hyphens at boundaries violate RFC 1035 DNS specifications.
- **Real-World Technique**: Parser fuzzing and exception generation.
- **Recommended Action**: Reject URL.
- **References**: `RFC 1035`
- **Tags**: `#rfc-violation`

### [HST-011] Dynamic DNS (DDNS) Service Host
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `90%`
- **Description**: Hostname resolves via a free dynamic DNS provider frequently abused in cyber attacks.
- **Why It Matters**: Dynamic DNS is heavily leveraged for ephemeral, unverified phishing campaigns.
- **Real-World Technique**: Bypasses domain registration costs and KYC checks.
- **Recommended Action**: Do not authenticate on DDNS sites.
- **References**: `MITRE ATT&CK T1568.002`
- **Tags**: `#ddns`

### [HST-012] Free Cloud PaaS with Credential / Brand Context
- **Severity**: `HIGH` | **Weight**: `+30` | **Confidence**: `92%`
- **Description**: Hosted on a free developer platform while containing brand or credential lures.
- **Why It Matters**: Major brands never authenticate users on free developer subdomains.
- **Real-World Technique**: Leverages cloud trust and free SSL to host phishing forms.
- **Recommended Action**: Never submit credentials on free PaaS subdomains.
- **References**: `APWG Cloud Abuse`
- **Tags**: `#paas` `#cloud-abuse`

### [HST-013] High Consonant-to-Vowel Ratio (DGA Indicator)
- **Severity**: `MEDIUM` | **Weight**: `+20` | **Confidence**: `85%`
- **Description**: Domain label contains an unnatural consonant-vowel ratio characteristic of automated generation.
- **Why It Matters**: Unbalanced consonant-to-vowel ratios indicate algorithmic generation.
- **Real-World Technique**: DGA domain generation.
- **Recommended Action**: Check DNS records.
- **References**: `SANS DGA`
- **Tags**: `#dga`

### [HST-014] Port Number Mimicry in Domain String
- **Severity**: `LOW` | **Weight**: `+10` | **Confidence**: `80%`
- **Description**: Domain incorporates hyphenated port strings (e.g. '-80', '-443', '-8080') to mimic network authorities.
- **Why It Matters**: Simulating port numbers in domain strings is an evasion camouflage technique.
- **Real-World Technique**: Social engineering camouflage.
- **Recommended Action**: Verify registered domain.
- **References**: `APWG`
- **Tags**: `#mimicry`

### [HST-015] TLD Extension Masquerade in Subdomain
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `94%`
- **Description**: A top-level domain suffix (like '.com', '.org', '.net') is embedded inside a subdomain or hyphenated string.
- **Why It Matters**: Simulating TLDs inside subdomains tricks users into thinking they are on the official site.
- **Real-World Technique**: Visual spoofing using fake '.com' prefixes.
- **Recommended Action**: Identify the authentic apex TLD at the end of the hostname.
- **References**: `MITRE ATT&CK T1566.002`
- **Tags**: `#tld-spoofing`


<a id="category-encoding"></a>
## Category: ENCODING (15 Rules)

### [ENC-001] Punycode (xn--) Internationalized Domain
- **Severity**: `HIGH` | **Weight**: `+20` | **Confidence**: `92%`
- **Description**: The domain uses the 'xn--' Punycode prefix to render Unicode characters.
- **Why It Matters**: Punycode is frequently abused for visual homograph spoofing of major brands.
- **Real-World Technique**: IDN homoglyph impersonation.
- **Recommended Action**: Inspect the raw Punycode string.
- **References**: `RFC 3492`
- **Tags**: `#punycode`

### [ENC-002] Cyrillic Character in Hostname (Homoglyph)
- **Severity**: `CRITICAL` | **Weight**: `+35` | **Confidence**: `98%`
- **Description**: Host contains Cyrillic characters that visually mimic Latin letters.
- **Why It Matters**: Cyrillic homoglyphs look visually identical to Latin letters.
- **Real-World Technique**: Homograph brand spoofing.
- **Recommended Action**: Block navigation.
- **References**: `Unicode TR #39`
- **Tags**: `#cyrillic` `#homoglyph`

### [ENC-003] Greek Character in Hostname
- **Severity**: `CRITICAL` | **Weight**: `+35` | **Confidence**: `96%`
- **Description**: Host contains Greek alphabet characters that mimic Latin characters.
- **Why It Matters**: Greek characters visually imitate Latin counterparts.
- **Real-World Technique**: Homograph spoofing.
- **Recommended Action**: Reject URL.
- **References**: `Unicode TR #36`
- **Tags**: `#greek`

### [ENC-004] Zero-Width or Invisible Character
- **Severity**: `CRITICAL` | **Weight**: `+40` | **Confidence**: `99%`
- **Description**: The URL contains invisible or zero-width unicode characters.
- **Why It Matters**: Invisible characters bypass text filters while remaining unseen by humans.
- **Real-World Technique**: Zero-width evasion.
- **Recommended Action**: Block URL.
- **References**: `Unicode Annex #9`
- **Tags**: `#zero-width`

### [ENC-005] Right-to-Left Override (RLO) Inversion
- **Severity**: `CRITICAL` | **Weight**: `+40` | **Confidence**: `99%`
- **Description**: The URL contains the Unicode Right-to-Left Override control character (U+202E).
- **Why It Matters**: RLO flips visual text direction to disguise file extensions and hostnames.
- **Real-World Technique**: MITRE ATT&CK T1036.002 Right-to-Left Override.
- **Recommended Action**: Block immediately.
- **References**: `MITRE ATT&CK T1036.002`
- **Tags**: `#rlo`

### [ENC-006] High Shannon Entropy in Hostname (> 3.8 bits)
- **Severity**: `MEDIUM` | **Weight**: `+20` | **Confidence**: `88%`
- **Description**: Hostname displays unusually high information entropy, indicative of algorithmic generation.
- **Why It Matters**: High entropy reveals pseudo-random machine generated strings.
- **Real-World Technique**: DGA domain generation.
- **Recommended Action**: Flag for threat analysis.
- **References**: `Shannon Entropy Standards`
- **Tags**: `#entropy`

### [ENC-007] Excessive Percent-Encoding (> 3 Sequences)
- **Severity**: `MEDIUM` | **Weight**: `+15` | **Confidence**: `85%`
- **Description**: URL contains multiple percent-encoded character sequences.
- **Why It Matters**: Excess percent-encoding obfuscates keywords from detection rules.
- **Real-World Technique**: Hides malicious words via hex escaping.
- **Recommended Action**: Decode URL before inspection.
- **References**: `RFC 3986 §2.1`
- **Tags**: `#percent-encoding`

### [ENC-008] Double Percent-Encoding (%25)
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `95%`
- **Description**: URL contains '%25' sequence, indicating double-layer percent-encoding.
- **Why It Matters**: Double-encoding exploits parser discrepancies to bypass security filters.
- **Real-World Technique**: WAF and filter evasion.
- **Recommended Action**: Block URL.
- **References**: `OWASP Double Encoding`
- **Tags**: `#double-encoding`

### [ENC-009] Percent-Encoded Forward Slash (%2F)
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `92%`
- **Description**: The path delimiter forward slash is obfuscated as '%2F'.
- **Why It Matters**: Encoded slashes bypass URL routing and firewall path rules.
- **Real-World Technique**: Smuggles prohibited paths past perimeter filters.
- **Recommended Action**: Decode and inspect normalized path.
- **References**: `RFC 3986`
- **Tags**: `#slash`

### [ENC-010] Percent-Encoded Userinfo Delimiter (%40)
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `95%`
- **Description**: The authentication delimiter '@' is encoded as '%40'.
- **Why It Matters**: Hides userinfo '@' symbol from security parsers.
- **Real-World Technique**: Concealed authority spoofing.
- **Recommended Action**: Decode before identifying destination host.
- **References**: `RFC 3986`
- **Tags**: `#userinfo`

### [ENC-011] Percent-Encoded Fragment Hash (%23)
- **Severity**: `MEDIUM` | **Weight**: `+15` | **Confidence**: `88%`
- **Description**: The fragment delimiter '#' is encoded as '%23' to alter path parsing.
- **Why It Matters**: Manipulates fragment vs query parsing boundaries.
- **Real-World Technique**: Smuggles client-side parameters.
- **Recommended Action**: Inspect query components.
- **References**: `RFC 3986`
- **Tags**: `#fragment`

### [ENC-012] Base64 or Hex Encoded Blob in Path (> 24 chars)
- **Severity**: `MEDIUM` | **Weight**: `+15` | **Confidence**: `85%`
- **Description**: URL contains a long base64 or hexadecimal data blob in the path component.
- **Why It Matters**: Base64 blobs typically encode victim identities or dynamic redirect targets.
- **Real-World Technique**: Carries victim metadata in URL paths.
- **Recommended Action**: Decode blob to identify victim data.
- **References**: `APWG Techniques`
- **Tags**: `#base64`

### [ENC-013] Mixed-Script Hostname Anomaly
- **Severity**: `CRITICAL` | **Weight**: `+35` | **Confidence**: `98%`
- **Description**: The hostname mixes Latin characters with non-Latin characters in the same label.
- **Why It Matters**: Mixing alphabets in a single domain label is a primary homoglyph spoofing signal.
- **Real-World Technique**: Replaces single characters with foreign lookalikes.
- **Recommended Action**: Block URL.
- **References**: `ICANN Guidelines §4`
- **Tags**: `#mixed-script`

### [ENC-014] Null Byte Injection (%00)
- **Severity**: `CRITICAL` | **Weight**: `+40` | **Confidence**: `99%`
- **Description**: URL contains a null byte (%00 or \0) in the string.
- **Why It Matters**: Null bytes truncate strings in C/C++ backends, bypassing file extension filters.
- **Real-World Technique**: Bypasses extension checks on uploaded shells.
- **Recommended Action**: Reject immediately.
- **References**: `OWASP Null Byte`
- **Tags**: `#null-byte`

### [ENC-015] Non-ASCII Control Character in URL
- **Severity**: `HIGH` | **Weight**: `+30` | **Confidence**: `95%`
- **Description**: URL contains non-printable ASCII control characters (bytes 0-31 or 127).
- **Why It Matters**: Control characters are illegal in standard RFC 3986 URLs.
- **Real-World Technique**: CRLF injection and terminal log poisoning.
- **Recommended Action**: Reject URL.
- **References**: `RFC 3986 §2`
- **Tags**: `#control-char`


<a id="category-tld"></a>
## Category: TLD (15 Rules)

### [TLD-001] File Extension Top-Level Domain (.zip, .mov)
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `94%`
- **Description**: The domain uses a TLD that overlaps with dangerous archive or media file extensions.
- **Why It Matters**: .zip and .mov TLDs conflate file attachments with web links.
- **Real-World Technique**: Tricks users into navigating to attacker sites thinking they are opening a document.
- **Recommended Action**: Verify if link was intended as a file or website.
- **References**: `US-CERT .zip Alert`
- **Tags**: `#tld` `#file-extension`

### [TLD-002] Free High-Abuse Freenom TLD (.tk, .ml, .ga, etc.)
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `92%`
- **Description**: Domain utilizes a free registration country-code TLD with historically high abuse rates.
- **Why It Matters**: Free TLDs are heavily abused for anonymous throwaway phishing.
- **Real-World Technique**: Zero-cost mass domain registration.
- **Recommended Action**: Do not enter credentials.
- **References**: `Spamhaus Most Abused TLDs`
- **Tags**: `#tld` `#freenom`

### [TLD-003] High-Abuse Generic TLD (.top, .xyz, .click, etc.)
- **Severity**: `MEDIUM` | **Weight**: `+15` | **Confidence**: `85%`
- **Description**: Domain is registered under a generic top-level domain frequently cited on threat feeds.
- **Why It Matters**: Inexpensive TLDs are statistical hotspots for disposable spam and phishing.
- **Real-World Technique**: Cycles cheap domains to evade domain reputation filters.
- **Recommended Action**: Exercise vigilance on high-abuse TLDs.
- **References**: `Spamhaus`
- **Tags**: `#tld` `#abuse`

### [TLD-004] Decentralized / Web3 Non-ICANN TLD (.crypto, .eth)
- **Severity**: `MEDIUM` | **Weight**: `+20` | **Confidence**: `88%`
- **Description**: Domain uses a blockchain or decentralized TLD not recognized by standard ICANN root servers.
- **Why It Matters**: Decentralized TLDs lack standard abuse reporting and trademark takedowns.
- **Real-World Technique**: Immune to traditional domain takedown requests.
- **Recommended Action**: Scrutinize wallet connection requests.
- **References**: `ICANN Root Zone`
- **Tags**: `#web3` `#crypto`

### [TLD-005] Low Governance ccTLD (.pw, .cc, .ws, .su)
- **Severity**: `MEDIUM` | **Weight**: `+15` | **Confidence**: `82%`
- **Description**: Domain uses a country-code TLD known for minimal registrar abuse enforcement.
- **Why It Matters**: Permissive registries delay or resist phishing takedown requests.
- **Real-World Technique**: Bulletproof infrastructure.
- **Recommended Action**: Verify official company domain.
- **References**: `APWG`
- **Tags**: `#tld`

### [TLD-006] Commercial Brand on Foreign ccTLD
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `90%`
- **Description**: An international or Indian financial entity name hosted on an unexpected foreign ccTLD.
- **Why It Matters**: Banks do not operate retail customer portals on foreign adversary ccTLDs.
- **Real-World Technique**: Jurisdiction hopping to resist domestic court orders.
- **Recommended Action**: Block navigation.
- **References**: `FS-ISAC Guidance`
- **Tags**: `#brand` `#cctld`

### [TLD-007] Missing or Unqualified TLD
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `95%`
- **Description**: The hostname does not possess a valid top-level domain extension.
- **Why It Matters**: Single-label hostnames trigger local name resolution vulnerabilities.
- **Real-World Technique**: MITRE ATT&CK T1557.001 LLMNR/NBT-NS Poisoning.
- **Recommended Action**: Use fully qualified domain names.
- **References**: `MITRE ATT&CK T1557.001`
- **Tags**: `#llmnr` `#tld`

### [TLD-008] Exceptionally Long TLD (> 10 characters)
- **Severity**: `LOW` | **Weight**: `+10` | **Confidence**: `75%`
- **Description**: TLD extension exceeds 10 characters, which can visually camouflage path separators.
- **Why It Matters**: Long TLDs blur the visual separation between domain and path.
- **Real-World Technique**: Visual ambiguity in URL formatting.
- **Recommended Action**: Inspect full URL.
- **References**: `ICANN gTLD`
- **Tags**: `#tld`

### [TLD-009] New Low-Cost Generic TLD with Lure (.site, .online, .live, .shop)
- **Severity**: `MEDIUM` | **Weight**: `+18` | **Confidence**: `88%`
- **Description**: Registered under a heavily discounted gTLD while advertising financial/account keywords.
- **Why It Matters**: Discount TLDs combined with lures represent high statistical likelihood of phishing.
- **Real-World Technique**: Low-cost mass phishing.
- **Recommended Action**: Verify site with official provider.
- **References**: `APWG`
- **Tags**: `#tld` `#lure`

### [TLD-010] Hyphenated Compound TLD Spoofing
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `92%`
- **Description**: Domain embeds fake TLD structures like '.com-account' in the hostname.
- **Why It Matters**: Hyphenated fake TLDs trick human visual scanning.
- **Real-World Technique**: Visual spoofing of domain boundaries.
- **Recommended Action**: Check real apex domain.
- **References**: `US-CERT`
- **Tags**: `#tld-spoof`

### [TLD-011] Reserved / Test TLD Inappropriate Exposure (.test, .invalid)
- **Severity**: `INFO` | **Weight**: `+5` | **Confidence**: `99%`
- **Description**: Domain uses an RFC 2606 reserved documentation or testing TLD.
- **Why It Matters**: Reserved TLDs are guaranteed non-routable on public DNS.
- **Real-World Technique**: Educational and QA simulation.
- **Recommended Action**: Safe for offline testing.
- **References**: `RFC 2606`
- **Tags**: `#rfc2606`

### [TLD-012] Multi-Part ccTLD Misinterpretation
- **Severity**: `LOW` | **Weight**: `+10` | **Confidence**: `80%`
- **Description**: Domain structures deep subdomains imitating multi-part country codes.
- **Why It Matters**: Sub-leases mimic genuine ccTLDs.
- **Real-World Technique**: Domain camouflage.
- **Recommended Action**: Check PSL status.
- **References**: `Public Suffix List`
- **Tags**: `#tld`

### [TLD-013] Dark Web / Onion Service Link (.onion)
- **Severity**: `HIGH` | **Weight**: `+30` | **Confidence**: `98%`
- **Description**: The URL targets a Tor hidden service (.onion).
- **Why It Matters**: Onion domains operate outside ICANN governance on anonymous overlay networks.
- **Real-World Technique**: Ransomware extortion and black market forums.
- **Recommended Action**: Do not navigate without dedicated isolation.
- **References**: `RFC 7686`
- **Tags**: `#tor` `#onion`

### [TLD-014] Suspicious Dynamic Redirection TLD (.link, .click)
- **Severity**: `MEDIUM` | **Weight**: `+15` | **Confidence**: `85%`
- **Description**: Domain uses a redirect-themed TLD often used in SMS phishing (smishing).
- **Why It Matters**: Short TLDs are common in SMS phishing.
- **Real-World Technique**: Smishing payload delivery.
- **Recommended Action**: Avoid clicking in text messages.
- **References**: `CISA Smishing`
- **Tags**: `#smishing` `#tld`

### [TLD-015] Non-Standard Numeric TLD Format
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `95%`
- **Description**: TLD component contains digits, which is prohibited under ICANN root zone guidelines.
- **Why It Matters**: ICANN prohibits numeric TLDs.
- **Real-World Technique**: Parser confusion / IP misinterpretation.
- **Recommended Action**: Reject URL.
- **References**: `ICANN Root Rules`
- **Tags**: `#icann` `#tld`


<a id="category-lexical"></a>
## Category: LEXICAL (15 Rules)

### [LEX-001] Credential Harvesting Keyword (login, signin, password)
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `92%`
- **Description**: URL contains discrete authentication tokens designed to harvest credentials.
- **Why It Matters**: Login keywords on unverified domains are primary indicators of credential harvesting.
- **Real-World Technique**: Captures user passwords through fake sign-in portals.
- **Recommended Action**: Never type credentials on links from emails or messages.
- **References**: `MITRE ATT&CK T1566`
- **Tags**: `#login` `#credentials`

### [LEX-002] Account & Verification Keyword (verify, account, secure)
- **Severity**: `MEDIUM` | **Weight**: `+20` | **Confidence**: `88%`
- **Description**: URL contains tokens that mimic security verification or account validation.
- **Why It Matters**: Verification tokens trick victims into believing security validation is required.
- **Real-World Technique**: False security alerts.
- **Recommended Action**: Check official portal directly.
- **References**: `CISA Social Engineering`
- **Tags**: `#verification` `#account`

### [LEX-003] Financial & Banking Keyword (banking, invoice, payment)
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `90%`
- **Description**: URL contains discrete financial and monetary keywords.
- **Why It Matters**: Financial lures coerce victims into revealing bank or payment details.
- **Real-World Technique**: Fake invoice and banking phishing.
- **Recommended Action**: Verify invoices out-of-band.
- **References**: `FBI IC3 BEC`
- **Tags**: `#financial` `#banking`

### [LEX-004] False Urgency & Coercion Keyword (urgent, suspend, alert)
- **Severity**: `MEDIUM` | **Weight**: `+18` | **Confidence**: `88%`
- **Description**: URL employs coercive urgency keywords designed to bypass critical thinking.
- **Why It Matters**: Artificial urgency induces panic to bypass cognitive suspicion.
- **Real-World Technique**: Psychological coercion in phishing lures.
- **Recommended Action**: Pause and verify independently.
- **References**: `NIST SP 800-63`
- **Tags**: `#urgency`

### [LEX-005] Lure / Incentive Keyword (reward, free, bonus, prize)
- **Severity**: `MEDIUM` | **Weight**: `+18` | **Confidence**: `85%`
- **Description**: URL promises unearned rewards, bonuses, or gifts to entice victims.
- **Why It Matters**: Unsolicited reward claims are standard bait for malicious downloads and credential capture.
- **Real-World Technique**: Prize scam and crypto giveaway lures.
- **Recommended Action**: Disregard unsolicited offers.
- **References**: `FTC Prize Scams`
- **Tags**: `#reward` `#lure`

### [LEX-006] Tech Support & Update Keyword (support, update, helpdesk)
- **Severity**: `LOW` | **Weight**: `+12` | **Confidence**: `80%`
- **Description**: URL simulates software updates or IT technical support desks.
- **Why It Matters**: Fake IT update links distribute remote administration trojans.
- **Real-World Technique**: Fake browser update prompts.
- **Recommended Action**: Update software directly through OS settings.
- **References**: `CISA Tech Support`
- **Tags**: `#update` `#support`

### [LEX-007] Government & Tax Authority Scam Token (irs, hmrc, tax, aadhaar)
- **Severity**: `HIGH` | **Weight**: `+30` | **Confidence**: `95%`
- **Description**: URL references revenue services or national identity credentials.
- **Why It Matters**: Tax and national ID lures harvest sensitive government identifiers.
- **Real-World Technique**: Fake tax refund portals and challan payment scams.
- **Recommended Action**: Verify '.gov' or official government portal domain.
- **References**: `Cert-In Advisory`
- **Tags**: `#government` `#tax`

### [LEX-008] Crypto Seed Phrase / Wallet Drainer Token
- **Severity**: `CRITICAL` | **Weight**: `+35` | **Confidence**: `96%`
- **Description**: URL references cryptocurrency seed phrases, private keys, or wallet authorization.
- **Why It Matters**: Web forms soliciting seed phrases are guaranteed wallet-draining exploits.
- **Real-World Technique**: Theft of cryptocurrency wallet master keys.
- **Recommended Action**: Never type seed phrases into websites.
- **References**: `Consensys Security`
- **Tags**: `#crypto` `#seed-phrase`

### [LEX-009] Multilingual Credential Lure (French/Spanish/German)
- **Severity**: `MEDIUM` | **Weight**: `+20` | **Confidence**: `88%`
- **Description**: URL contains non-English authentication tokens used in regional campaigns.
- **Why It Matters**: Regional campaigns target non-English speaking demographics.
- **Real-World Technique**: Localized phishing campaigns.
- **Recommended Action**: Inspect domain with regional institution.
- **References**: `ENISA Threat Landscape`
- **Tags**: `#multilingual`

### [LEX-010] OTP / Two-Factor Authentication Intercept Token
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `94%`
- **Description**: URL explicitly targets One-Time Passwords (OTP) or Multi-Factor Authentication codes.
- **Why It Matters**: Targets real-time capture of OTPs to bypass two-factor authentication.
- **Real-World Technique**: AiTM phishing kits capturing SMS codes and session cookies.
- **Recommended Action**: Use phishing-resistant FIDO2 hardware security keys.
- **References**: `CISA AiTM Fact Sheet`
- **Tags**: `#otp` `#mfa` `#aitm`

### [LEX-011] Fake Shipping / Parcel Delivery Lure (fedex, dhl, usps)
- **Severity**: `MEDIUM` | **Weight**: `+20` | **Confidence**: `90%`
- **Description**: URL references courier tracking and package delivery on an unrelated domain.
- **Why It Matters**: Missed delivery scams steal credit card details under the guise of redelivery fees.
- **Real-World Technique**: Package delivery smishing.
- **Recommended Action**: Verify with courier directly.
- **References**: `USPS Inspection Alert`
- **Tags**: `#shipping` `#parcel`

### [LEX-012] DocuSign / e-Signature Lure in Path
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `92%`
- **Description**: URL simulates digital document signing services on an unverified domain.
- **Why It Matters**: Simulates electronic signature workflows to harvest corporate employee credentials.
- **Real-World Technique**: DocuSign lure campaigns.
- **Recommended Action**: Verify document through authentic signature portal.
- **References**: `DocuSign Advisory`
- **Tags**: `#docusign` `#corporate`

### [LEX-013] Telephony / Voice Phishing (Vishing) Callback Lure
- **Severity**: `MEDIUM` | **Weight**: `+15` | **Confidence**: `82%`
- **Description**: URL references phone call center callbacks or fake customer service numbers.
- **Why It Matters**: Coerces victims into calling fraudulent phone support call centers.
- **Real-World Technique**: Hybrid vishing.
- **Recommended Action**: Do not call phone numbers on alert banners.
- **References**: `FBI IC3 Vishing`
- **Tags**: `#vishing`

### [LEX-014] High Lexical Lure Density (>= 3 Distinct Category Tokens)
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `94%`
- **Description**: URL contains 3 or more distinct suspicious keywords simultaneously.
- **Why It Matters**: Multiple combined security keywords indicate artificial domain generation.
- **Real-World Technique**: Keyword chaining in phishing domains.
- **Recommended Action**: Reject URL.
- **References**: `APWG Phishing Nomenclature`
- **Tags**: `#lexical` `#keyword-density`

### [LEX-015] File Attachment Phishing Indicator in Path
- **Severity**: `MEDIUM` | **Weight**: `+15` | **Confidence**: `85%`
- **Description**: Path explicitly references fake email attachments or secure messages.
- **Why It Matters**: Fake attachment notifications trick victims into credential entry.
- **Real-World Technique**: Fake encrypted document portals.
- **Recommended Action**: Verify sender out-of-band.
- **References**: `US-CERT Email`
- **Tags**: `#attachment`


<a id="category-brand"></a>
## Category: BRAND (15 Rules)

### [BRD-001] Direct Leetspeak Character Substitution
- **Severity**: `CRITICAL` | **Weight**: `+35` | **Confidence**: `98%`
- **Description**: Domain uses numbers or homoglyphs to substitute letters in brand names (e.g., '0' for 'o', '1' for 'l').
- **Why It Matters**: Leetspeak substitutions visually deceive human readers into trusting attacker domains.
- **Real-World Technique**: Typosquatting brand impersonation.
- **Recommended Action**: Reject URL unconditionally.
- **References**: `MITRE ATT&CK T1566.002`
- **Tags**: `#leetspeak` `#brand`

### [BRD-002] Google Ecosystem Impersonation
- **Severity**: `CRITICAL` | **Weight**: `+35` | **Confidence**: `96%`
- **Description**: Domain impersonates Google Workspace, Gmail, or Google Docs on an unauthorized domain.
- **Why It Matters**: Fake Google domains steal enterprise SSO and personal email accounts.
- **Real-World Technique**: Google Workspace credential harvesting.
- **Recommended Action**: Verify '*.google.com' domain.
- **References**: `Google Safe Browsing`
- **Tags**: `#google` `#brand`

### [BRD-003] Microsoft / Office 365 Impersonation
- **Severity**: `CRITICAL` | **Weight**: `+35` | **Confidence**: `96%`
- **Description**: Domain mimics Microsoft, Outlook, Office 365, or Azure authentication on an unauthorized host.
- **Why It Matters**: Microsoft impersonation is the primary corporate credential theft vector.
- **Real-World Technique**: Office 365 credential harvesting.
- **Recommended Action**: Only log in on official Microsoft domains.
- **References**: `Microsoft Threat Intelligence`
- **Tags**: `#microsoft` `#office365`

### [BRD-004] Apple & iCloud Impersonation
- **Severity**: `CRITICAL` | **Weight**: `+35` | **Confidence**: `96%`
- **Description**: Domain mimics Apple ID, Find My iPhone, or iCloud verification portals.
- **Why It Matters**: Apple ID phishing unlocks stolen phones and accesses private iCloud data.
- **Real-World Technique**: Stolen iPhone Find My bypass phishing.
- **Recommended Action**: Inspect for '*.apple.com' domain.
- **References**: `Apple Security`
- **Tags**: `#apple` `#icloud`

### [BRD-005] PayPal & Payment Gateway Impersonation
- **Severity**: `CRITICAL` | **Weight**: `+35` | **Confidence**: `98%`
- **Description**: Domain mimics PayPal resolution centers or account verification.
- **Why It Matters**: Direct financial theft through fake payment dispute and account hold forms.
- **Real-World Technique**: PayPal account limitation phishing.
- **Recommended Action**: Navigate directly to 'paypal.com'.
- **References**: `PayPal Security`
- **Tags**: `#paypal` `#payment`

### [BRD-006] Amazon Order / Account Impersonation
- **Severity**: `CRITICAL` | **Weight**: `+35` | **Confidence**: `96%`
- **Description**: Domain simulates Amazon customer service, prime rewards, or order suspensions.
- **Why It Matters**: Fake order emails panic victims into logging into counterfeit portals.
- **Real-World Technique**: Order dispute and cancellation fraud.
- **Recommended Action**: Verify orders on official Amazon app.
- **References**: `Amazon Guidelines`
- **Tags**: `#amazon` `#order-scam`

### [BRD-007] State Bank of India (SBI) Impersonation
- **Severity**: `CRITICAL` | **Weight**: `+40` | **Confidence**: `98%`
- **Description**: Domain mimics State Bank of India (onlinesbi) or YONO digital banking.
- **Why It Matters**: SBI phishing steals online banking credentials and intercepts OTPs via SMS lures.
- **Real-World Technique**: PAN / KYC update SMS phishing in India.
- **Recommended Action**: Only use 'onlinesbi.sbi' or official YONO app.
- **References**: `Cert-In Advisory`, `RBI`
- **Tags**: `#sbi` `#indian-banking`

### [BRD-008] HDFC Bank NetBanking Impersonation
- **Severity**: `CRITICAL` | **Weight**: `+40` | **Confidence**: `98%`
- **Description**: Domain mimics HDFC Bank customer portals or reward point redemptions.
- **Why It Matters**: HDFC lures steal netbanking credentials under the guise of reward redemption.
- **Real-World Technique**: Reward point expiration smishing.
- **Recommended Action**: Access solely via 'hdfcbank.com'.
- **References**: `HDFC Security`
- **Tags**: `#hdfc` `#indian-banking`

### [BRD-009] ICICI Bank iMobile Impersonation
- **Severity**: `CRITICAL` | **Weight**: `+40` | **Confidence**: `98%`
- **Description**: Domain simulates ICICI Bank iMobile or corporate banking portals.
- **Why It Matters**: ICICI phishing targets grid card values and netbanking passwords.
- **Real-World Technique**: Debit card grid authentication theft.
- **Recommended Action**: Verify 'icicibank.com'.
- **References**: `ICICI Safe Banking`
- **Tags**: `#icici` `#banking`

### [BRD-010] Indian UPI & Fintech Impersonation (Paytm, PhonePe, GPay)
- **Severity**: `CRITICAL` | **Weight**: `+35` | **Confidence**: `96%`
- **Description**: Domain mimics popular Indian UPI payment apps or lottery cashbacks.
- **Why It Matters**: Fintech scratch card scams deceive users into approving outgoing UPI transfers.
- **Real-World Technique**: UPI collect request exploitation.
- **Recommended Action**: Never type UPI PINs on external web forms.
- **References**: `NPCI Guidelines`
- **Tags**: `#upi` `#fintech`

### [BRD-011] Global Tier-1 Banking Impersonation (Chase, BofA, Wells Fargo)
- **Severity**: `CRITICAL` | **Weight**: `+40` | **Confidence**: `98%`
- **Description**: Domain mimics multinational retail banking institutions.
- **Why It Matters**: Direct wire fraud and electronic funds transfer theft.
- **Real-World Technique**: Tier-1 banking credential harvesting.
- **Recommended Action**: Navigate solely to verified financial bookmarks.
- **References**: `FS-ISAC`
- **Tags**: `#banking` `#global-bank`

### [BRD-012] Social Media Platform Impersonation
- **Severity**: `HIGH` | **Weight**: `+30` | **Confidence**: `94%`
- **Description**: Domain mimics Facebook, Instagram, WhatsApp, Discord, or LinkedIn.
- **Why It Matters**: Compromised social accounts are weaponized to scam victims' friends and family.
- **Real-World Technique**: Copyright strike and Discord Nitro lures.
- **Recommended Action**: Verify notifications within official apps.
- **References**: `Meta Security`
- **Tags**: `#social-media`

### [BRD-013] Cryptocurrency Exchange Impersonation
- **Severity**: `CRITICAL` | **Weight**: `+40` | **Confidence**: `98%`
- **Description**: Domain mimics Binance, Coinbase, Kraken, or Bybit trading platforms.
- **Why It Matters**: Irreversible financial liquidation of cryptocurrency balances.
- **Real-World Technique**: Exchange credential and 2FA interception.
- **Recommended Action**: Enable Anti-Phishing Codes in exchange settings.
- **References**: `Binance Security`
- **Tags**: `#crypto` `#exchange`

### [BRD-014] Combosquatting Brand Chaining
- **Severity**: `HIGH` | **Weight**: `+30` | **Confidence**: `92%`
- **Description**: Domain chains a monitored brand with security, support, or portal action words.
- **Why It Matters**: Combosquatting leverages trusted brand names joined with security terms.
- **Real-World Technique**: Chained brand-action domains.
- **Recommended Action**: Check official company domain.
- **References**: `US-CERT Combosquatting`
- **Tags**: `#combosquatting`

### [BRD-015] Low Edit Distance Typosquatting (Levenshtein <= 2)
- **Severity**: `HIGH` | **Weight**: `+30` | **Confidence**: `90%`
- **Description**: Domain label is 1 or 2 edits away from a major brand, indicating intentional misspelling.
- **Why It Matters**: Low edit distances indicate intentional misspelling domains targeting mistyped URLs.
- **Real-World Technique**: Fat-finger and adjacent key typosquatting.
- **Recommended Action**: Re-check domain spelling.
- **References**: `IEEE Security & Privacy`
- **Tags**: `#typosquatting` `#fuzzy`


<a id="category-path"></a>
## Category: PATH (12 Rules)

### [PTH-001] Dangerous Executable File Extension
- **Severity**: `CRITICAL` | **Weight**: `+40` | **Confidence**: `98%`
- **Description**: The path ends with an executable or scripting file extension.
- **Why It Matters**: Direct links to executables deliver drive-by downloads or droppers.
- **Real-World Technique**: Delivers malware payloads via unsolicited web links.
- **Recommended Action**: Block download immediately.
- **References**: `MITRE ATT&CK T1204.001`
- **Tags**: `#executable` `#malware`

### [PTH-002] Double File Extension Deception (e.g. invoice.pdf.exe)
- **Severity**: `CRITICAL` | **Weight**: `+45` | **Confidence**: `99%`
- **Description**: Path utilizes a double extension to disguise an executable as a document.
- **Why It Matters**: Double extensions exploit default Windows shell settings to trick victims into executing malware.
- **Real-World Technique**: MITRE ATT&CK T1036.007 Double Extension.
- **Recommended Action**: Block immediately.
- **References**: `MITRE ATT&CK T1036.007`
- **Tags**: `#double-extension` `#malware`

### [PTH-003] Administrative CMS Login Path (/wp-admin, /cpanel)
- **Severity**: `MEDIUM` | **Weight**: `+15` | **Confidence**: `85%`
- **Description**: Path targets web content management or server control panels.
- **Why It Matters**: Compromised WordPress sites host phishing kits in administrative subdirectories.
- **Real-World Technique**: Abuses compromised third-party websites to bypass domain reputation.
- **Recommended Action**: Verify site owner.
- **References**: `OWASP A01`
- **Tags**: `#cms` `#wordpress`

### [PTH-004] Sensitive Configuration File Exposure Target (/.env, /.git)
- **Severity**: `CRITICAL` | **Weight**: `+35` | **Confidence**: `95%`
- **Description**: Path requests sensitive credentials, secrets, or source control metadata.
- **Why It Matters**: Requests for .env or .git repositories attempt to harvest database credentials and API keys.
- **Real-World Technique**: Automated secret harvesting.
- **Recommended Action**: Block scanning client.
- **References**: `MITRE ATT&CK T1552.001`
- **Tags**: `#secrets` `#reconnaissance`

### [PTH-005] SSL Validation Abuse Path (/.well-known/pki-validation/)
- **Severity**: `MEDIUM` | **Weight**: `+20` | **Confidence**: `88%`
- **Description**: Path targets automated ACME or PKI certificate challenge paths inappropriately.
- **Why It Matters**: Phishers hide kits inside '.well-known' folders to evade webmaster detection.
- **Real-World Technique**: Stealth directory residency.
- **Recommended Action**: Audit server files.
- **References**: `RFC 8555`
- **Tags**: `#ssl-abuse` `#hidden-path`

### [PTH-006] Directory Traversal Sequence (../ or ..\)
- **Severity**: `CRITICAL` | **Weight**: `+35` | **Confidence**: `98%`
- **Description**: The path contains directory traversal sequences attempting to break out of web roots.
- **Why It Matters**: Directory traversal attempts to read unauthorized system files from the web server.
- **Real-World Technique**: Path traversal exploit.
- **Recommended Action**: Reject request.
- **References**: `OWASP Path Traversal`
- **Tags**: `#traversal` `#exploit`

### [PTH-007] Excessive Path Depth (> 5 Segments)
- **Severity**: `LOW` | **Weight**: `+10` | **Confidence**: `78%`
- **Description**: The URL path contains 6 or more nested directory levels.
- **Why It Matters**: Deep paths hide phishing scripts inside complex directory structures.
- **Real-World Technique**: Obscured directory hosting.
- **Recommended Action**: Check apex domain.
- **References**: `APWG`
- **Tags**: `#path-depth`

### [PTH-008] Excessive Path Length (> 80 characters)
- **Severity**: `LOW` | **Weight**: `+8` | **Confidence**: `75%`
- **Description**: The path string alone exceeds 80 characters in length.
- **Why It Matters**: Long paths push suspicious parameters out of mobile browser views.
- **Real-World Technique**: Mobile address bar truncation.
- **Recommended Action**: Inspect full URL string.
- **References**: `RFC 3986`
- **Tags**: `#path-length`

### [PTH-009] Consecutive Path Slashes (///)
- **Severity**: `MEDIUM` | **Weight**: `+15` | **Confidence**: `88%`
- **Description**: URL path contains 3 or more consecutive forward slashes.
- **Why It Matters**: Consecutive slashes bypass naive proxy authorization rules.
- **Real-World Technique**: Reverse proxy authorization bypass.
- **Recommended Action**: Normalize paths in middleware.
- **References**: `OWASP Normalization`
- **Tags**: `#slashes`

### [PTH-010] Trailing Dot in File Extension
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `95%`
- **Description**: The path ends with a dot following the file extension (e.g. 'doc.exe.').
- **Why It Matters**: Trailing dots exploit Windows NTFS filename normalization to bypass extension blocks.
- **Real-World Technique**: NTFS filename filter bypass.
- **Recommended Action**: Block download.
- **References**: `CWE-20`
- **Tags**: `#trailing-dot`

### [PTH-011] Compressed Archive with Invoice / Financial Name
- **Severity**: `HIGH` | **Weight**: `+30` | **Confidence**: `94%`
- **Description**: Path links to a zip, rar, or 7z archive combined with financial keywords.
- **Why It Matters**: Archives containing financial names are primary vehicles for ransomware droppers.
- **Real-World Technique**: Archive payload delivery in BEC scams.
- **Recommended Action**: Sandboxed inspection only.
- **References**: `CISA Ransomware Guide`
- **Tags**: `#archive` `#ransomware`

### [PTH-012] Visual Space Padding in Path
- **Severity**: `MEDIUM` | **Weight**: `+20` | **Confidence**: `88%`
- **Description**: Path contains repeated spaces or percent-encoded %20 sequences.
- **Why It Matters**: Spaces push malicious extensions out of address bar viewports.
- **Real-World Technique**: Visual truncation in mobile browsers.
- **Recommended Action**: Inspect full URL string.
- **References**: `APWG`
- **Tags**: `#padding` `#truncation`


<a id="category-query"></a>
## Category: QUERY (12 Rules)

### [QRY-001] Open Redirect Parameter Present
- **Severity**: `MEDIUM` | **Weight**: `+20` | **Confidence**: `88%`
- **Description**: Query contains parameter keys known to facilitate open redirects.
- **Why It Matters**: Open redirects leverage trusted domains to bounce users to attacker-controlled phishing pages.
- **Real-World Technique**: CWE-601 Open Redirect.
- **Recommended Action**: Check target destination inside query parameter.
- **References**: `OWASP Open Redirect`
- **Tags**: `#open-redirect` `#query`

### [QRY-002] Open Redirect Target with External Protocol (http:// or https://)
- **Severity**: `HIGH` | **Weight**: `+30` | **Confidence**: `95%`
- **Description**: Query parameter value contains an explicit secondary web protocol scheme.
- **Why It Matters**: An absolute URL inside a redirect parameter will forward user traffic to a foreign site.
- **Real-World Technique**: Active Open Redirect exploitation.
- **Recommended Action**: Do not navigate.
- **References**: `MITRE ATT&CK T1566.002`
- **Tags**: `#open-redirect`

### [QRY-003] Plaintext Password Exposed in Query String
- **Severity**: `CRITICAL` | **Weight**: `+35` | **Confidence**: `98%`
- **Description**: URL passes authentication passwords in the clear query string.
- **Why It Matters**: Query parameters are logged across all proxy and browser logs, leaking passwords.
- **Real-World Technique**: CWE-598 Sensitive Data in GET Query.
- **Recommended Action**: Never pass secrets via URL query.
- **References**: `CWE-598`
- **Tags**: `#credentials` `#password`

### [QRY-004] API Secret Key or Access Token in Query
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `92%`
- **Description**: URL transmits API secret tokens or bearer keys in clear query parameters.
- **Why It Matters**: Exposes API secrets to log files and proxy intercepts.
- **Real-World Technique**: Token harvesting from server logs.
- **Recommended Action**: Use Authorization headers.
- **References**: `RFC 6750`
- **Tags**: `#token` `#api-key`

### [QRY-005] Victim Email Pre-fill Parameter
- **Severity**: `HIGH` | **Weight**: `+25` | **Confidence**: `94%`
- **Description**: Query contains victim email addresses designed to populate phishing forms.
- **Why It Matters**: Pre-filled emails are standard spear-phishing tactics to increase victim trust.
- **Real-World Technique**: Targeted spear-phishing personalization.
- **Recommended Action**: Exercise high caution on pre-filled links.
- **References**: `MITRE ATT&CK T1566.002`
- **Tags**: `#spear-phishing` `#email`

### [QRY-006] Excessive Query String Length (> 100 characters)
- **Severity**: `LOW` | **Weight**: `+8` | **Confidence**: `75%`
- **Description**: The query string exceeds 100 characters in length.
- **Why It Matters**: Excessive query lengths carry heavy tracking or obfuscated payloads.
- **Real-World Technique**: Serialized payload transport.
- **Recommended Action**: Review query keys.
- **References**: `RFC 3986`
- **Tags**: `#query-length`

### [QRY-007] Base64 or Encoded Data Blob in Query Parameter
- **Severity**: `MEDIUM` | **Weight**: `+18` | **Confidence**: `88%`
- **Description**: Query parameter value contains a long base64 or hex encoded data block.
- **Why It Matters**: Base64 query values conceal target URLs or victim telemetry.
- **Real-World Technique**: Payload obfuscation in query parameters.
- **Recommended Action**: Decode parameter string.
- **References**: `APWG`
- **Tags**: `#base64` `#query`

### [QRY-008] Script Protocol or Data URI in Query (javascript:, data:)
- **Severity**: `CRITICAL` | **Weight**: `+40` | **Confidence**: `98%`
- **Description**: Query parameter contains 'javascript:' or 'data:' URI schemes.
- **Why It Matters**: Script schemes execute arbitrary JavaScript in victim browsers.
- **Real-World Technique**: CWE-79 Cross-Site Scripting via URI injection.
- **Recommended Action**: Block URL.
- **References**: `OWASP XSS`
- **Tags**: `#xss` `#exploit`

### [QRY-009] High Query Parameter Count (>= 8 parameters)
- **Severity**: `LOW` | **Weight**: `+8` | **Confidence**: `70%`
- **Description**: The URL carries 8 or more distinct query parameters.
- **Why It Matters**: High parameter density correlates with fingerprinting and tracking chains.
- **Real-World Technique**: Device fingerprinting via query.
- **Recommended Action**: Inspect query contents.
- **References**: `RFC 3986`
- **Tags**: `#tracking`

### [QRY-010] SQL Injection Probe Syntax in Query
- **Severity**: `CRITICAL` | **Weight**: `+35` | **Confidence**: `95%`
- **Description**: Query parameter includes SQL meta-characters or keywords (UNION SELECT, OR '1'='1').
- **Why It Matters**: SQL syntax in query strings indicates database exploitation attempts.
- **Real-World Technique**: CWE-89 SQL Injection.
- **Recommended Action**: Block request.
- **References**: `OWASP SQLi`
- **Tags**: `#sqli` `#exploit`

### [QRY-011] HTML / XSS Tag Injection in Query (<script>, <img>)
- **Severity**: `CRITICAL` | **Weight**: `+40` | **Confidence**: `98%`
- **Description**: Query contains HTML opening tags or event handlers.
- **Why It Matters**: HTML tags in URLs reflect into web pages to steal authentication cookies.
- **Real-World Technique**: Reflected Cross-Site Scripting.
- **Recommended Action**: Block link.
- **References**: `OWASP XSS`
- **Tags**: `#xss` `#injection`

### [QRY-012] Chat Bot / Webhook Exfiltration Parameter in Query
- **Severity**: `CRITICAL` | **Weight**: `+40` | **Confidence**: `98%`
- **Description**: Query points to Discord webhooks or Telegram bot APIs for data exfiltration.
- **Why It Matters**: Phishing kits exfiltrate stolen credentials to chat bots.
- **Real-World Technique**: MITRE ATT&CK T1567.002 Exfiltration to Webhook.
- **Recommended Action**: Report webhook to Discord/Telegram abuse.
- **References**: `MITRE ATT&CK T1567.002`
- **Tags**: `#exfiltration` `#webhook`

