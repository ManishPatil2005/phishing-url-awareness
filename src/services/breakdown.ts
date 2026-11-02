import { UrlBreakdown } from "@/types";

export function decomposeUrl(rawUrl: string): UrlBreakdown {
  const trimmed = rawUrl.trim();
  let candidate = trimmed;

  // Auto-prepend http:// if scheme delimiter is missing for RFC 3986 normalization
  if (!candidate.includes("://")) {
    candidate = `http://${candidate}`;
  }

  // Guard against unclosed bracket syntax errors (e.g. malformed IPv6)
  if (trimmed.includes("[") && !trimmed.includes("]")) {
    return {
      rawUrl: trimmed,
      normalizedUrl: candidate,
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
  }

  let scheme = "";
  let hostname = "";
  let port = "";
  let path = "/";
  let query = "";
  const queryParams: Record<string, string> = {};
  let fragment = "";
  let hasUserinfo = false;
  let userinfo = "";

  try {
    const parsed = new URL(candidate);
    scheme = parsed.protocol.replace(":", "").toLowerCase();
    hostname = (parsed.hostname || "").toLowerCase();
    port = parsed.port || (scheme === "https" ? "443" : "80");
    path = parsed.pathname || "/";
    query = parsed.search || "";
    parsed.searchParams.forEach((val, key) => {
      queryParams[key] = val;
    });
    fragment = parsed.hash ? parsed.hash.replace("#", "") : "";
    hasUserinfo = Boolean(parsed.username || parsed.password);
    userinfo = parsed.username
      ? `${parsed.username}${parsed.password ? `:${parsed.password}` : ""}`
      : "";
  } catch {
    // Regex-based fallback for URLs rejected by strict WHATWG parser (e.g. invalid Punycode labels)
    const regexMatch = candidate.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]+)(.*)$/);
    if (regexMatch) {
      scheme = regexMatch[1].toLowerCase();
      let authority = regexMatch[2];
      const rest = regexMatch[3] || "";

      if (authority.includes("@")) {
        const parts = authority.split("@");
        userinfo = parts[0];
        hasUserinfo = true;
        authority = parts[1];
      }

      if (authority.includes(":")) {
        const parts = authority.split(":");
        hostname = parts[0].toLowerCase();
        port = parts[1];
      } else {
        hostname = authority.toLowerCase();
        port = scheme === "https" ? "443" : "80";
      }

      // Parse path, query, fragment
      const hashSplit = rest.split("#");
      fragment = hashSplit.length > 1 ? hashSplit[1] : "";
      const querySplit = hashSplit[0].split("?");
      path = querySplit[0] || "/";
      query = querySplit.length > 1 ? `?${querySplit[1]}` : "";
    } else {
      return {
        rawUrl: trimmed,
        normalizedUrl: candidate,
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
    }
  }

  const hostLabels = hostname.split(".").filter(Boolean);
  let tld = "";
  let rootDomain = "";
  const subdomains: string[] = [];

  if (hostLabels.length === 1) {
    rootDomain = hostname;
  } else if (hostLabels.length === 2) {
    tld = hostLabels[1];
    rootDomain = hostname;
  } else if (hostLabels.length > 2) {
    const lastTwo = `${hostLabels[hostLabels.length - 2]}.${hostLabels[hostLabels.length - 1]}`;
    const twoPartTlds = ["co.uk", "com.au", "org.in", "co.in", "gov.in", "ac.uk", "edu.au", "com.br"];

    if (twoPartTlds.includes(lastTwo) && hostLabels.length > 3) {
      tld = lastTwo;
      rootDomain = `${hostLabels[hostLabels.length - 3]}.${lastTwo}`;
      subdomains.push(...hostLabels.slice(0, hostLabels.length - 3));
    } else {
      tld = hostLabels[hostLabels.length - 1];
      rootDomain = `${hostLabels[hostLabels.length - 2]}.${tld}`;
      subdomains.push(...hostLabels.slice(0, hostLabels.length - 2));
    }
  }

  return {
    rawUrl: trimmed,
    normalizedUrl: candidate,
    scheme,
    subdomains,
    subdomainString: subdomains.join("."),
    rootDomain,
    hostname,
    tld,
    port,
    path,
    query,
    queryParams,
    fragment,
    hasUserinfo,
    userinfo,
  };
}
