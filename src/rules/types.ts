/**
 * PhishIntel.ai Threat Engine v2.0 - Rule System Types
 * Pure, deterministic, zero-network rule interface.
 */

export const RULE_TYPES_VERSION = "2.0.0";

export type RuleCategory =
  | "structure"
  | "host"
  | "lexical"
  | "brand"
  | "encoding"
  | "redirect"
  | "tld"
  | "path"
  | "query";

export type RuleSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface ParsedUrlContext {
  rawUrl: string;
  normalizedUrl: string;
  scheme: string;
  username?: string;
  password?: string;
  hasUserinfo: boolean;
  hostname: string;
  rootDomain: string; // eTLD+1
  subdomains: string[];
  subdomainString: string;
  tld: string;
  port: string;
  path: string;
  pathSegments: string[];
  query: string;
  queryParams: Record<string, string>;
  fragment: string;
  isAllowlisted: boolean;
  allTokens: string[];
  hostTokens: string[];
  pathTokens: string[];
}

export interface RuleFinding {
  ruleId: string;
  ruleCode: string;
  category: RuleCategory;
  name: string;
  description: string;
  severity: RuleSeverity;
  weight: number;
  confidence: number;
  evidence: string;
  matchedString?: string;
  whyItMatters: string;
  realWorldTechnique: string;
  recommendedAction: string;
  references: string[];
  tags: string[];
}

export interface Rule {
  id: string; // e.g. "STR-001", "HST-005"
  category: RuleCategory;
  name: string;
  description: string;
  severity: RuleSeverity;
  weight: number;
  confidence: number;
  detect: (ctx: ParsedUrlContext) => RuleFinding | null;
  whyItMatters: string;
  realWorldTechnique: string;
  recommendedAction: string;
  references: string[];
  tags: string[];
}
