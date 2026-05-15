#!/usr/bin/env python3
"""Security review utility for Chrome, WhatsApp, and Aalto-style mobile apps.

Modes:
1) interactive review questionnaire with weighted controls
2) patch-check scan to flag suspicious/non-original code patterns
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from urllib.parse import parse_qsl, urlparse
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Question:
    text: str
    weight: int = 1


REVIEW_QUESTIONS: dict[str, list[Question]] = {
    "chrome": [
        Question("Does the extension request minimum permissions only?", 3),
        Question("Is remote code execution prevented (no eval, no remote scripts)?", 3),
        Question("Are content scripts scoped to explicit domains, not <all_urls>?", 2),
        Question("Is CSP strict and aligned with Manifest V3 best practices?", 2),
        Question("Are credentials/tokens excluded from local storage?", 2),
        Question("Are third-party dependencies pinned and frequently updated?", 2),
    ],
    "whatsapp": [
        Question("Are group admin privileges granted only to trusted identities?", 3),
        Question("Are suspicious contacts (spoof-like names/unknown numbers) blocked quickly?", 3),
        Question("Are invite links/QR links rotated after membership changes?", 2),
        Question("Is two-step verification enabled on the account?", 2),
        Question("Are chat backups encrypted and restricted to trusted storage?", 2),
        Question("Is media auto-download disabled for unknown contacts/groups?", 2),
    ],
    "aalto": [
        Question("Is authentication protected with MFA and device binding?", 3),
        Question("Are app secrets excluded from client binaries/logs?", 3),
        Question("Are API endpoints enforcing least-privilege authorization?", 2),
        Question("Are input validation and anti-injection controls tested?", 2),
        Question("Is PII encrypted both at rest and in transit?", 2),
        Question("Are audit trails immutable and monitored?", 2),
    ],
    "manus": [
        Question("Are you logged into ChatGPT and Manus with the same email identity?", 3),
        Question("Is the Manus app allowed in your workspace/account policy?", 3),
        Question("Are third-party cookies enabled for chatgpt.com and manus.im domains?", 2),
        Question("Is pop-up blocking disabled for OAuth redirect windows?", 2),
        Question("Have you cleared old Manus OAuth grants and retried linking?", 2),
        Question("Are browser extensions (ad/privacy blockers) disabled for the connect flow?", 2),
    ],
}

MANUS_ERROR_HINTS: dict[str, str] = {
    "invalid_state": "OAuth state mismatch: disable strict tracking prevention, retry in an incognito window.",
    "redirect_uri_mismatch": "Manus redirect URI is outdated: reconnect from the latest ChatGPT Apps page and avoid old bookmarks.",
    "access_denied": "Authorization denied by workspace policy or user: check org app policy and grant access again.",
    "forbidden": "Your account/workspace does not currently allow the Manus app.",
    "timeout": "Network or popup timeout during OAuth callback: allow popups and retry.",
    "network": "Connection blocked by firewall/VPN/proxy: retry on a different network or disable VPN temporarily.",
}

SUSPICIOUS_PATTERNS: dict[str, str] = {
    r"\beval\s*\(": "dynamic code execution via eval",
    r"exec\s*\(": "dynamic code execution via exec",
    r"AKIA[0-9A-Z]{16}": "possible AWS access key",
    r"-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----": "private key material",
    r"(?i)password\s*=\s*['\"][^'\"]+['\"]": "hard-coded password",
    r"(?i)token\s*=\s*['\"][^'\"]+['\"]": "hard-coded token",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Security review and patch-check utility")
    sub = parser.add_subparsers(dest="command", required=True)

    review = sub.add_parser("review", help="Run interactive security questionnaire")
    review.add_argument("target", choices=sorted(REVIEW_QUESTIONS.keys()), help="Review template target")
    review.add_argument("--json", action="store_true", help="Emit machine-readable JSON report")

    patch = sub.add_parser("patch-check", help="Scan code for suspicious/non-original patterns")
    patch.add_argument("path", type=Path, help="File or directory to scan")
    patch.add_argument("--json", action="store_true", help="Emit machine-readable JSON report")

    manus = sub.add_parser("manus-diagnose", help="Diagnose ChatGPT Apps -> Manus connection errors")
    manus.add_argument("error", help="Raw error message shown while connecting Manus")
    manus.add_argument("--url", help="Optional Manus link used during connection")
    manus.add_argument("--json", action="store_true", help="Emit machine-readable JSON report")

    return parser.parse_args()


def ask_boolean(prompt: str) -> bool:
    while True:
        answer = input(f"{prompt} [y/n]: ").strip().lower()
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("Please enter y or n.")


def grade(score: int, max_score: int) -> str:
    ratio = score / max_score if max_score else 0
    if ratio >= 0.85:
        return "LOW RISK"
    if ratio >= 0.60:
        return "MODERATE RISK"
    return "HIGH RISK"


def run_review(target: str, as_json: bool) -> int:
    questions = REVIEW_QUESTIONS[target]
    passed: list[str] = []
    failed: list[str] = []
    score = 0
    max_score = sum(q.weight for q in questions)

    print(f"Security Review: {target.title()}\n")
    for index, question in enumerate(questions, start=1):
        ok = ask_boolean(f"{index}. {question.text}")
        if ok:
            score += question.weight
            passed.append(question.text)
        else:
            failed.append(question.text)

    result = {
        "target": target,
        "score": score,
        "max_score": max_score,
        "risk": grade(score, max_score),
        "passed": passed,
        "failed": failed,
    }

    if as_json:
        print(json.dumps(result, indent=2))
    else:
        print("\n=== Review Summary ===")
        print(f"Score: {score}/{max_score}")
        print(f"Overall: {result['risk']}")
        print("Passed controls:")
        for item in passed:
            print(f"  - {item}")
        print("Failed controls:")
        for item in failed:
            print(f"  - {item}")
    return 0


def files_to_scan(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return [p for p in path.rglob("*") if p.is_file() and p.suffix in {".py", ".js", ".ts", ".json", ".yaml", ".yml"}]


def sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()


def run_patch_check(path: Path, as_json: bool) -> int:
    if not path.exists():
        print(f"ERROR: path not found: {path}")
        return 2

    findings: list[dict[str, str | int]] = []
    scanned = 0

    for file_path in files_to_scan(path):
        scanned += 1
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        for pattern, description in SUSPICIOUS_PATTERNS.items():
            for match in re.finditer(pattern, content):
                line_no = content.count("\n", 0, match.start()) + 1
                findings.append(
                    {
                        "file": str(file_path),
                        "line": line_no,
                        "issue": description,
                        "pattern": pattern,
                    }
                )

        if "security_review_app.py" in str(file_path):
            findings.append(
                {
                    "file": str(file_path),
                    "line": 1,
                    "issue": f"file fingerprint sha256={sha256_text(content)[:16]}... (use for original-code tracking)",
                    "pattern": "fingerprint",
                }
            )

    result = {"scanned_files": scanned, "findings": findings, "risk": "HIGH" if findings else "LOW"}

    if as_json:
        print(json.dumps(result, indent=2))
    else:
        print("=== Patch Check Report ===")
        print(f"Scanned files: {scanned}")
        print(f"Risk: {result['risk']}")
        if findings:
            for finding in findings:
                print(f"- {finding['file']}:{finding['line']} -> {finding['issue']}")
        else:
            print("No suspicious patterns found.")
    return 0


def analyze_manus_url(link: str) -> list[str]:
    warnings: list[str] = []
    parsed = urlparse(link.strip())
    if parsed.scheme not in {"http", "https"}:
        warnings.append("URL scheme is not HTTP/HTTPS.")

    domain = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    is_manus = domain.endswith("manus.im")
    is_chatgpt = domain.endswith("chatgpt.com")
    valid_chatgpt_path = path.startswith("/apps/manus")

    if not (is_manus or is_chatgpt):
        warnings.append("Domain is neither manus.im nor chatgpt.com; use official app URLs only.")
    if is_manus and path != "/app":
        warnings.append("For manus.im links, path should be /app.")
    if is_chatgpt and not valid_chatgpt_path:
        warnings.append("For chatgpt.com links, path should start with /apps/manus.")

    params = parse_qsl(parsed.query, keep_blank_values=True)
    seen: set[str] = set()
    for key, _ in params:
        if key in seen:
            warnings.append(f"Duplicate query parameter detected: {key}.")
        seen.add(key)

    noisy = {"gclid", "gbraid", "wbraid", "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term", "cid"}
    if any(key in noisy for key, _ in params):
        warnings.append("Marketing tracking parameters present; they can break/complicate OAuth flows.")

    if parsed.fragment and "referrer=" in parsed.fragment:
        warnings.append("Fragment contains referrer metadata; remove it before retrying the OAuth flow.")
    return warnings


def run_manus_diagnose(raw_error: str, as_json: bool, url: str | None = None) -> int:
    normalized = raw_error.strip().lower()
    checks = [
        "Verify ChatGPT and Manus accounts use the same email/login method.",
        "From ChatGPT > More > Apps, disconnect Manus and reconnect from scratch.",
        "Disable ad/privacy extensions for chatgpt.com and manus.im.",
        "Allow third-party cookies and popups during the connect flow.",
        "If this is a work account, confirm the workspace allows Manus.",
    ]

    matches = [hint for key, hint in MANUS_ERROR_HINTS.items() if key in normalized]
    if not matches and "oauth" in normalized:
        matches.append("Generic OAuth failure: clear stale grants and reconnect using a fresh browser session.")
    if not matches:
        matches.append("Unknown error signature: capture network/OAuth callback details and retry in incognito.")

    url_warnings = analyze_manus_url(url) if url else []
    if url_warnings:
        matches.append("Use a clean URL: https://chatgpt.com/apps/manus or https://manus.im/app without extra tracking/referrer metadata.")

    result = {
        "input_error": raw_error,
        "probable_causes": matches,
        "next_checks": checks,
        "url_warnings": url_warnings,
    }

    if as_json:
        print(json.dumps(result, indent=2))
    else:
        print("=== Manus Connection Diagnosis ===")
        print(f"Error: {raw_error}")
        print("Likely causes:")
        for item in matches:
            print(f"  - {item}")
        if url_warnings:
            print("URL warnings:")
            for item in url_warnings:
                print(f"  - {item}")
        print("Next checks:")
        for item in checks:
            print(f"  - {item}")
    return 0


def main() -> int:
    args = parse_args()
    if args.command == "review":
        return run_review(args.target, args.json)
    if args.command == "patch-check":
        return run_patch_check(args.path, args.json)
    if args.command == "manus-diagnose":
        return run_manus_diagnose(args.error, args.json, args.url)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
