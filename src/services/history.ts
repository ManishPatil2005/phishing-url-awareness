import { AnalysisResult, DashboardMetrics, ScanHistoryItem } from "@/types";

const STORAGE_KEY = "phishing_intel_scan_history_v2";
const MAX_HISTORY_ITEMS = 50;

export function getScanHistory(): ScanHistoryItem[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch (err) {
    console.error("Failed to read scan history from localStorage", err);
    return [];
  }
}

export function saveScanResult(result: AnalysisResult): ScanHistoryItem[] {
  if (typeof window === "undefined" || !result.isValid) return [];
  try {
    const current = getScanHistory();
    const newItem: ScanHistoryItem = {
      id: result.id,
      timestamp: result.timestamp,
      url: result.rawUrl,
      riskScore: result.riskScore,
      classification: result.classification,
      findingCount: result.findings.length,
      findingsSummary: result.findings.map((f) => f.title),
    };

    // Prepend and truncate to max
    const updated = [newItem, ...current.filter((item) => item.url !== result.rawUrl)].slice(
      0,
      MAX_HISTORY_ITEMS
    );

    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    return updated;
  } catch (err) {
    console.error("Failed to save scan to localStorage", err);
    return [];
  }
}

export function deleteScanItem(id: string): ScanHistoryItem[] {
  if (typeof window === "undefined") return [];
  try {
    const current = getScanHistory();
    const updated = current.filter((item) => item.id !== id);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    return updated;
  } catch (err) {
    console.error("Failed to delete scan item", err);
    return [];
  }
}

export function clearScanHistory(): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch (err) {
    console.error("Failed to clear scan history", err);
  }
}

export function calculateMetrics(history: ScanHistoryItem[]): DashboardMetrics {
  if (history.length === 0) {
    return {
      totalScans: 0,
      highRiskCount: 0,
      mediumRiskCount: 0,
      lowRiskCount: 0,
      safeCount: 0,
      averageScore: 0,
    };
  }

  let totalScore = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  let safe = 0;

  for (const item of history) {
    totalScore += item.riskScore;
    if (item.classification === "HIGH RISK") high++;
    else if (item.classification === "MEDIUM RISK") medium++;
    else if (item.classification === "LOW RISK") low++;
    else safe++;
  }

  return {
    totalScans: history.length,
    highRiskCount: high,
    mediumRiskCount: medium,
    lowRiskCount: low,
    safeCount: safe,
    averageScore: Math.round(totalScore / history.length),
  };
}

export function exportHistoryAsJson(history: ScanHistoryItem[]): void {
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(history, null, 2));
  const downloadAnchor = document.createElement("a");
  downloadAnchor.setAttribute("href", dataStr);
  downloadAnchor.setAttribute("download", `phishing_intel_history_${new Date().toISOString().slice(0, 10)}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
}
