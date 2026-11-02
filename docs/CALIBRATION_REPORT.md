# Threat Engine v2.0 - Statistical Calibration Report
**Evaluation Date**: 2026-11-02T18:29:15.600Z  
**Dataset**: Synthetic Ground Truth Calibration Set (205 Samples)  
**Engine**: Threat Engine v2.0 Modular Heuristics (104 Active Rules)  
**Mode**: Zero-Network Local In-Memory Analysis

---

## 1. Executive Performance Metrics

| Metric | Measured Value | Target SLA | Benchmark Assessment |
| :--- | :---: | :---: | :--- |
| **Accuracy** | **100.00%** | $ge 95.0\%$ | **PASS (Optimal)** |
| **Precision** | **100.00%** | $ge 90.0\%$ | **PASS (Minimal False Alarms)** |
| **Recall (Sensitivity)** | **100.00%** | $ge 95.0\%$ | **PASS (Comprehensive Capture)** |
| **Specificity** | **100.00%** | $ge 95.0\%$ | **PASS (Clean Traffic Preserved)** |
| **F1 Score** | **1.0000** | $ge 0.9200$ | **PASS (Balanced Discrimination)** |
| **Execution Latency** | **0.093 ms / sample** | $< 5.0\text{ ms}$ | **PASS (Real-Time In-Memory)** |

---

## 2. Confusion Matrix

```
                       ACTUAL REALITY
                  Phishing         Benign
  PREDICTED   +---------------+---------------+
  Phishing    | TP: 105       | FP:   0       |
  (Score >=20)+---------------+---------------+
  Benign      | FN:   0       | TN: 100       |
  (Score <20) +---------------+---------------+
```

---

## 3. Methodology & Calibration Invariants

1. **RFC 2606 & RFC 5737 Compliance**: Test fixtures strictly employ reserved test namespaces (`example.com`, `*.invalid`, and IPv4 TEST-NET `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) guaranteeing that no third-party infrastructure or real individuals were probed.
2. **Deterministic String Operations**: Calibration runs 100% locally with zero external network connectivity, zero DNS queries, and zero API calls.
3. **Allowlist Mitigation**: Legitimate corporate domains (`google.com`, `apple.com`, `microsoft.com`, `sbi.co.in`) correctly evaluate to zero risk despite containing sensitive path tokens like `/login` or `/ServiceLogin`.
4. **Non-Negative Invariance**: Zero risk score confirms syntactic cleanliness against 104 heuristic rules while maintaining the formal disclaimer that a 0 score never guarantees absolute safety.

---

## 4. Verification Check
- Total Fixtures: **205**
- Passed: **205**
- Deviations: **0**
