export type ThreatClassification =
  | "SAFE-LOOKING"
  | "LOW RISK"
  | "MEDIUM RISK"
  | "HIGH RISK";

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface HeuristicFinding {
  id: string;
  code: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  points: number;
  whyItMatters: string;
  realWorldTechnique: string;
  recommendedAction: string;
}

export interface UrlBreakdown {
  rawUrl: string;
  normalizedUrl: string;
  scheme: string;
  subdomains: string[];
  subdomainString: string;
  rootDomain: string;
  hostname: string;
  tld: string;
  port: string;
  path: string;
  query: string;
  queryParams: Record<string, string>;
  fragment: string;
  hasUserinfo: boolean;
  userinfo: string;
}

export interface AnalysisResult {
  id: string;
  rawUrl: string;
  normalizedUrl: string;
  isValid: boolean;
  errorMessage?: string;
  riskScore: number;
  classification: ThreatClassification;
  breakdown: UrlBreakdown;
  findings: HeuristicFinding[];
  recommendation: string;
  executiveSummary: string;
  securityNotes: string[];
  timestamp: string;
}

export interface ScanHistoryItem {
  id: string;
  timestamp: string;
  url: string;
  riskScore: number;
  classification: ThreatClassification;
  findingCount: number;
  findingsSummary: string[];
}

export interface DashboardMetrics {
  totalScans: number;
  highRiskCount: number;
  mediumRiskCount: number;
  lowRiskCount: number;
  safeCount: number;
  averageScore: number;
}
