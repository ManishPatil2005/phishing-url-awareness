"""
Automated Test Suite for Phishing URL Awareness Checker
Executes 20 formal QA test cases and validates pass/fail criteria.
"""

import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from phishing_checker import inspect_url, format_report

test_cases = [
    (1, "https://www.example.com/", "Legitimate benchmark URL", "SAFE-LOOKING", 0),
    (2, "https://www.example.com/login", "Legitimate HTTPS with keyword 'login'", "LOW RISK", 25),
    (3, "http://192.0.2.10/account", "Workbook Test 2: IP + HTTP + account keyword", "HIGH RISK", 75),
    (4, "http://example.com@sample.invalid/login", "Workbook Test 3: @ symbol + HTTP + keyword 'login'", "MEDIUM RISK", 65),
    (5, "https://a.b.c.d.e.example.invalid/path", "Workbook Test 4: >= 5 hostname segments", "SAFE-LOOKING", 10),
    (6, "https://xn--example.invalid/", "Workbook Test 5: Punycode domain", "SAFE-LOOKING", 20),
    (7, "http://192.0.2.10/login", "Prompt example: HTTP + IP + keyword 'login'", "HIGH RISK", 75),
    (8, "", "Empty input string boundary check", "Notice: No URL entered.", None),
    (9, "   ", "Whitespace-only input string", "Notice: No URL entered.", None),
    (10, "http://[bad", "Malformed bracket IPv6 URI syntax error", "Notice: Malformed URL format", None),
    (11, "www.example.com", "Missing scheme auto-normalization to HTTP", "SAFE-LOOKING", 15),
    (12, "https://banking-portal-verification-system.secure.user-credential-check.example.invalid/update", "Excessive segments + multiple keywords", "LOW RISK", 40),
    (13, "http://198.51.100.25@phish-domain.invalid/free-reward-bonus/verify-password.html?session_token=abcdef12345678901234567890", "Compound attack: HTTP + @ + keywords + length", "HIGH RISK", 80),
    (14, "https://example.com/" + "a" * 90, "Excessive URL length (>100 characters)", "SAFE-LOOKING", 10),
    (15, "http://xn--e1afmkfd.example.invalid/account", "Punycode + HTTP + keyword 'account'", "MEDIUM RISK", 60),
    (16, "https://192.168.1.1/", "HTTPS with raw IPv4 address", "LOW RISK", 35),
    (17, "http://company.com/secure-login", "HTTP + keywords 'secure' and 'login'", "MEDIUM RISK", 45),
    (18, "https://secure-login.example.invalid", "Keywords present in subdomain", "LOW RISK", 30),
    (19, "http://999.999.999.999/test", "Invalid IPv4 octets (>255) boundary check", "SAFE-LOOKING", 15),
    (20, "https://my-legit-bank.example.org/dashboard", "Clean domain with zero flagged tokens", "SAFE-LOOKING", 0)
]

print("=" * 80)
print("RUNNING 20 FORMAL QA TEST CASES")
print("=" * 80)

passed = 0
for test_id, url, desc, exp_class, exp_score in test_cases:
    res = inspect_url(url)
    if exp_score is None:
        # Error handling test
        actual = res.get("error_message") or ""
        status = "PASS" if exp_class.lower() in f"notice: {actual}".lower() else "FAIL"
    else:
        status = "PASS" if res["classification"] == exp_class else "FAIL"
    
    if status == "PASS":
        passed += 1

    warn_summary = ", ".join(res["warnings"]) if res["warnings"] else (res.get("error_message") or "None")
    print(f"Test #{test_id:02d} | Status: {status} | Score: {res['risk_score']:3d}/100 | Class: {res['classification']:12s} | URL: {url[:45]}")

print("=" * 80)
print(f"SUMMARY: {passed}/{len(test_cases)} Test Cases Passed Successfully.")
print("=" * 80)
