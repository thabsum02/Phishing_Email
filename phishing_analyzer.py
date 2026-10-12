"""
Phishing Email Analyzer
A beginner-friendly, rule-based email analyzer for cybersecurity learning.

This tool flags suspicious indicators. It cannot prove that an email is safe or malicious.
It analyzes text supplied by the user and does not send email data anywhere.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List
import json
from datetime import datetime


URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+", re.IGNORECASE)

SUSPICIOUS_KEYWORDS = {
    "urgent language": [
        "urgent", "immediately", "act now", "final warning", "account will be blocked",
        "suspended", "within 24 hours", "verify immediately",
    ],
    "credential or personal-information request": [
        "password", "verify your account", "login details", "bank details",
        "credit card", "social security", "one-time password", "otp",
    ],
    "prize or money lure": [
        "you have won", "winner", "claim your prize", "free gift", "cash reward",
        "refund is waiting",
    ],
    "suspicious attachment language": [
        "enable macros", "open the attachment", "invoice attached", "payment overdue",
    ],
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"
}


@dataclass
class AnalysisResult:
    risk_level: str
    risk_score: int
    indicators: List[str]
    urls_found: List[str]
    recommendation: str


def extract_urls(text: str) -> List[str]:
    """Extract URL-like strings from email text."""
    return URL_PATTERN.findall(text)


def analyze_email(email_text: str) -> AnalysisResult:
    """Analyze an email using simple, transparent rules."""
    indicators: List[str] = []
    score = 0
    lowered = email_text.lower()

    for category, phrases in SUSPICIOUS_KEYWORDS.items():
        matches = [phrase for phrase in phrases if phrase in lowered]
        if matches:
            indicators.append(f"{category.title()}: {', '.join(matches)}")
            score += min(2 + len(matches), 4)

    urls = extract_urls(email_text)
    if urls:
        indicators.append(f"Contains {len(urls)} URL(s). Review each link before opening.")
        score += min(len(urls), 2)

    for url in urls:
        cleaned = url.lower().rstrip(".,);!?")
        domain_match = re.search(r"^(?:https?://)?([^/]+)", cleaned)
        domain = domain_match.group(1).split("@")[-1].split(":")[0] if domain_match else ""
        if domain in URL_SHORTENERS:
            indicators.append(f"Uses a URL-shortening service: {url}")
            score += 2
        if re.match(r"^(?:https?://)?\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/|$)", cleaned):
            indicators.append(f"URL uses an IP address instead of a typical domain: {url}")
            score += 3
        if "@" in domain:
            indicators.append(f"URL contains an @ symbol in its authority section: {url}")
            score += 2

    if not indicators:
        indicators.append("No obvious indicators matched the built-in rules.")
        recommendation = (
            "No obvious warning signs were detected by this basic tool. "
            "This does not guarantee the email is safe; verify the sender through a trusted channel."
        )
    else:
        recommendation = (
            "Do not click links, open attachments, or share passwords/OTPs until you verify "
            "the message independently. Report suspicious messages to your email/security team."
        )

    if score >= 7:
        risk_level = "HIGH"
    elif score >= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return AnalysisResult(
        risk_level=risk_level,
        risk_score=score,
        indicators=indicators,
        urls_found=urls,
        recommendation=recommendation,
    )


def read_email_interactively() -> str:
    print("\nPaste the email text below. When finished, enter a line containing only END.")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip().upper() == "END":
            break
        lines.append(line)
    return "\n".join(lines).strip()


def print_result(result: AnalysisResult) -> None:
    print("\n" + "=" * 54)
    print("             PHISHING EMAIL ANALYSIS")
    print("=" * 54)
    print(f"Risk level : {result.risk_level}")
    print(f"Risk score : {result.risk_score}")
    print("\nIndicators:")
    for number, indicator in enumerate(result.indicators, start=1):
        print(f"  {number}. {indicator}")
    if result.urls_found:
        print("\nURLs found (do not open them just to test):")
        for url in result.urls_found:
            print(f"  - {url}")
    print("\nRecommendation:")
    print(f"  {result.recommendation}")
    print("=" * 54)


def main() -> None:
    print("Phishing Email Analyzer | Educational rule-based prototype")
    print("Choose: 1) Paste email text  2) Analyze a text file")
    choice = input("Enter 1 or 2: ").strip()

    if choice == "1":
        email_text = read_email_interactively()
    elif choice == "2":
        file_path = input("Enter the email text file path: ").strip().strip('"')
        try:
            email_text = Path(file_path).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            print(f"Could not read file: {exc}")
            return
    else:
        print("Invalid choice. Please run the program again and enter 1 or 2.")
        return

    if not email_text:
        print("No email text was provided.")
        return

    result = analyze_email(email_text)
    print_result(result)

    save = input("\nSave this result as a JSON report? (y/n): ").strip().lower()
    if save == "y":
        report = {
            "analyzed_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "note": "Rule-based educational result; not a guarantee of maliciousness or safety.",
            "result": asdict(result),
        }
        output_path = Path("analysis_report.json")
        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Report saved to: {output_path.resolve()}")


if __name__ == "__main__":
    main()
