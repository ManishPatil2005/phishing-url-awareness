"""
==============================================================================
Project Name : Phishing URL Awareness Checker
Module       : phishing_checker.py
Author       : Manish Pundlik Patil
Role         : Cyber Security Intern (ID: EWB-OL-2026-CYB-0195)
Organization : EWB Edutech Private Limited
Course       : EWB Courses - Cybersecurity Mini Project
Python Ver   : 3.10+ (Standard Library Only)
Description  : Static text-based heuristic analyzer for identifying common
               syntactic red flags in suspicious URLs without network activity.
==============================================================================
"""

import re
import sys
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple


# ============================================================================
# CONSTANTS & CONFIGURATION
# ============================================================================

BANNER = r"""
==============================================================================
                 PHISHING URL AWARENESS CHECKER
       Defensive Text-Only Security Analysis | EWB Cybersecurity
==============================================================================
"""

SUSPICIOUS_KEYWORDS: Tuple[str, ...] = (
    "login",
    "verify",
    "secure",
    "account",
    "banking",
    "password",
    "reward",
    "free",
    "bonus",
    "update",
)

# Calibrated heuristic weights (Total max bounded to 100)
WEIGHT_IP_ADDRESS = 35
WEIGHT_KEYWORD_BASE = 25
WEIGHT_AT_SYMBOL = 25
WEIGHT_PUNYCODE = 20
WEIGHT_HTTP = 15
WEIGHT_LONG_URL = 10
WEIGHT_MANY_SEGMENTS = 10
WEIGHT_KEYWORD_ADDITIONAL = 5  # per additional keyword, up to cap (30)


# ============================================================================
# CORE ANALYSIS MODULES
# ============================================================================

def clean_and_normalize_url(raw_url: str) -> str:
    """
    Strips extraneous whitespace and ensures an HTTP/HTTPS scheme prefix
    exists so standard parsing functions can reliably identify the host.
    """
    cleaned = raw_url.strip()
    if not cleaned:
        return ""
    # If no protocol scheme is present, prepend 'http://' for syntactic parsing
    if "://" not in cleaned:
        cleaned = "http://" + cleaned
    return cleaned


def is_valid_ipv4(host: str) -> bool:
    """
    Checks if the hostname strictly follows an IPv4 address structure.
    Validates 4 octets where each octet is an integer between 0 and 255.
    """
    pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    match = re.fullmatch(pattern, host)
    if not match:
        return False
    # Validate each octet does not exceed 255
    return all(0 <= int(octet) <= 255 for octet in match.groups())


def scan_suspicious_keywords(url_string: str) -> List[str]:
    """
    Scans the URL for high-risk phishing keywords frequently used in
    social engineering lures (e.g., login, account, banking).
    """
    found_keywords = []
    url_lower = url_string.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        # Search for keyword bounded by common URL delimiters or sub-tokens
        if kw in url_lower:
            found_keywords.append(kw)
    return found_keywords


def inspect_url(raw_url: str) -> Dict[str, Any]:
    """
    Performs comprehensive, purely static heuristic checks on the provided URL.
    
    Checks executed:
    1. @ symbol detection (Userinfo deception)
    2. Length analysis (> 100 characters)
    3. Hostname format (Dotted IPv4 address detection)
    4. Domain segmentation (>= 5 dot-separated labels)
    5. Punycode detection (IDN homograph attack indicator 'xn--')
    6. Scheme analysis (Plaintext HTTP vs Encrypted HTTPS)
    7. High-risk social engineering keyword scan
    
    Returns a structured dictionary with analysis details, warnings, score,
    classification, and actionable recommendation.
    """
    raw_cleaned = raw_url.strip()
    result: Dict[str, Any] = {
        "raw_url": raw_cleaned,
        "is_valid": False,
        "warnings": [],
        "risk_score": 0,
        "classification": "SAFE-LOOKING",
        "recommendation": "No listed warning signs found. This does NOT prove safety.",
        "error_message": None,
    }

    if not raw_cleaned:
        result["error_message"] = "No URL entered."
        return result

    # Normalize candidate URL for safe parsing
    candidate = clean_and_normalize_url(raw_cleaned)

    # Defensive parsing: catch syntax/IPv6 bracket format errors
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
    except ValueError:
        result["error_message"] = "Malformed URL format (invalid structure)."
        return result

    if not host:
        result["error_message"] = "Could not identify a valid hostname."
        return result

    result["is_valid"] = True
    warnings: List[str] = []
    score = 0

    # ------------------------------------------------------------------------
    # Check 1: Plain HTTP Scheme Detection
    # ------------------------------------------------------------------------
    if parsed.scheme.lower() == "http":
        warnings.append("HTTP detected")
        score += WEIGHT_HTTP

    # ------------------------------------------------------------------------
    # Check 2: IP Address as Hostname
    # ------------------------------------------------------------------------
    if is_valid_ipv4(host):
        warnings.append("IP address detected")
        score += WEIGHT_IP_ADDRESS

    # ------------------------------------------------------------------------
    # Check 3: Userinfo '@' Symbol Detection
    # ------------------------------------------------------------------------
    if "@" in candidate:
        warnings.append("@ symbol detected")
        score += WEIGHT_AT_SYMBOL

    # ------------------------------------------------------------------------
    # Check 4: Hostname Subdomain Segmentation (>= 5 labels)
    # ------------------------------------------------------------------------
    labels = [part for part in host.split(".") if part]
    if len(labels) >= 5:
        warnings.append("Excessive hostname segments detected (5 or more parts)")
        score += WEIGHT_MANY_SEGMENTS

    # ------------------------------------------------------------------------
    # Check 5: Punycode Marker ('xn--') Detection
    # ------------------------------------------------------------------------
    if "xn--" in host:
        warnings.append("Punycode hostname detected (xn--)")
        score += WEIGHT_PUNYCODE

    # ------------------------------------------------------------------------
    # Check 6: Excessive URL Length (> 100 characters)
    # ------------------------------------------------------------------------
    if len(raw_cleaned) > 100:
        warnings.append("Unusually long URL (over 100 characters)")
        score += WEIGHT_LONG_URL

    # ------------------------------------------------------------------------
    # Additional Check 7: Suspicious Keyword Detection
    # ------------------------------------------------------------------------
    detected_keywords = scan_suspicious_keywords(candidate)
    if detected_keywords:
        for kw in detected_keywords:
            warnings.append(f"Suspicious keyword: {kw}")
        kw_score = WEIGHT_KEYWORD_BASE + (len(detected_keywords) - 1) * WEIGHT_KEYWORD_ADDITIONAL
        score += min(kw_score, 30)

    # ------------------------------------------------------------------------
    # Final Risk Scoring & Categorization (Clamped 0 to 100)
    # ------------------------------------------------------------------------
    score = min(max(score, 0), 100)
    result["warnings"] = warnings
    result["risk_score"] = score

    if score == 0:
        result["classification"] = "SAFE-LOOKING"
        result["recommendation"] = (
            "No listed warning signs found. This does NOT prove safety. Always verify."
        )
    elif 1 <= score <= 20:
        result["classification"] = "SAFE-LOOKING"
        result["recommendation"] = (
            "Minimal structural anomalies detected. Exercise standard vigilance."
        )
    elif 21 <= score <= 40:
        result["classification"] = "LOW RISK"
        result["recommendation"] = (
            "Minor indicators observed. Verify authenticity before submitting credentials."
        )
    elif 41 <= score <= 70:
        result["classification"] = "MEDIUM RISK"
        result["recommendation"] = (
            "Notable suspicious indicators detected. Exercise high caution."
        )
    else:
        result["classification"] = "HIGH RISK"
        result["recommendation"] = (
            "Review carefully before interacting."
        )

    return result


def format_report(result: Dict[str, Any]) -> str:
    """
    Generates a clean, terminal-formatted security assessment report.
    Matches industry output standards and assignment presentation specifications.
    """
    lines = []
    lines.append("================================")
    lines.append("PHISHING URL AWARENESS CHECKER")
    lines.append("================================")

    if result.get("error_message"):
        lines.append(f"\nNotice: {result['error_message']}")
        lines.append("\nRecommendation:")
        lines.append("Provide a valid URL string for structural text analysis.")
        lines.append("\n================================")
        return "\n".join(lines)

    warnings = result["warnings"]
    lines.append("\nWarnings Found:")
    if not warnings:
        lines.append("[0] No listed warning signs found.")
    else:
        for idx, w in enumerate(warnings, start=1):
            lines.append(f"[{idx}] {w}")

    lines.append(f"\nRisk Score: {result['risk_score']}/100")
    lines.append(f"\nClassification:\n{result['classification']}")
    lines.append(f"\nRecommendation:\n{result['recommendation']}")
    lines.append("\n================================")
    return "\n".join(lines)


# ============================================================================
# INTERACTIVE EXECUTION LOOP
# ============================================================================

def main() -> None:
    """
    Main interactive driver function featuring continuous scanning loop,
    graceful exit handlers, and defensive input sanitization.
    """
    print(BANNER)
    print("Static text-only heuristic analyzer.")
    print("Zero network traffic generated | Strictly local and defensive.\n")
    print("Enter 'q', 'quit', or 'exit' to terminate the program.\n")

    while True:
        try:
            raw_url = input("Enter a sample URL to inspect: ")
        except (KeyboardInterrupt, EOFError):
            print("\n\nSession terminated by user. Stay alert online!")
            sys.exit(0)

        cleaned_input = raw_url.strip().lower()
        if cleaned_input in ("q", "quit", "exit"):
            print("\nExiting Phishing URL Awareness Checker. Stay secure!")
            break

        analysis = inspect_url(raw_url)
        formatted_output = format_report(analysis)
        print(f"\n{formatted_output}\n")


if __name__ == "__main__":
    main()
