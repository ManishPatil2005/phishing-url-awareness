import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { ALL_RULES } from "../src/rules/index.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let md = `# Threat Engine v2.0 - Complete Rule Catalog
**Total Active Heuristic Rules**: ${ALL_RULES.length}  
**Architecture**: Pure, Deterministic, Zero-Network In-Memory Inspection  
**Standard Compliance**: RFC 3986, RFC 3987, OWASP Top 10, MITRE ATT&CK T1566  
**Last Updated**: ${new Date().toISOString()}

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
`;

const categories = ["structure", "host", "encoding", "tld", "lexical", "brand", "path", "query"];

for (const cat of categories) {
  const catRules = ALL_RULES.filter((r) => r.category === cat);
  md += `\n<a id="category-${cat}"></a>\n## Category: ${cat.toUpperCase()} (${catRules.length} Rules)\n\n`;

  for (const rule of catRules) {
    md += `### [${rule.id}] ${rule.name}\n`;
    md += `- **Severity**: \`${rule.severity.toUpperCase()}\` | **Weight**: \`+${rule.weight}\` | **Confidence**: \`${Math.round(rule.confidence * 100)}%\`\n`;
    md += `- **Description**: ${rule.description}\n`;
    md += `- **Why It Matters**: ${rule.whyItMatters}\n`;
    md += `- **Real-World Technique**: ${rule.realWorldTechnique}\n`;
    md += `- **Recommended Action**: ${rule.recommendedAction}\n`;
    md += `- **References**: ${rule.references.map((r) => `\`${r}\``).join(", ")}\n`;
    md += `- **Tags**: ${rule.tags.map((t) => `\`#${t}\``).join(" ")}\n\n`;
  }
}

const outputPath = path.join(__dirname, "..", "docs", "RULE_CATALOG.md");
fs.writeFileSync(outputPath, md, "utf8");
console.log(`Generated RULE_CATALOG.md with ${ALL_RULES.length} rules at ${outputPath}`);
