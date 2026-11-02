/**
 * Threat Engine v2.0 - Central Rule Registry
 * Aggregates all modular, pure, zero-network detection rules.
 */

import type { Rule, RuleCategory } from "./types.ts";
import { structureRules } from "./structure.ts";
import { hostRules } from "./host.ts";
import { encodingRules } from "./encoding.ts";
import { tldRules } from "./tld.ts";
import { lexicalRules } from "./lexical.ts";
import { brandRules } from "./brand.ts";
import { pathRules } from "./path.ts";
import { queryRules } from "./query.ts";

export * from "./types.ts";
export * from "./allowlist.ts";

export const ALL_RULES: Rule[] = [
  ...structureRules,
  ...hostRules,
  ...encodingRules,
  ...tldRules,
  ...lexicalRules,
  ...brandRules,
  ...pathRules,
  ...queryRules,
];

export const RULE_REGISTRY = new Map<string, Rule>();
for (const rule of ALL_RULES) {
  RULE_REGISTRY.set(rule.id, rule);
}

export function getRuleById(id: string): Rule | undefined {
  return RULE_REGISTRY.get(id);
}

export function getRulesByCategory(category: RuleCategory): Rule[] {
  return ALL_RULES.filter((r) => r.category === category);
}

export function getTotalRuleCount(): number {
  return ALL_RULES.length;
}
