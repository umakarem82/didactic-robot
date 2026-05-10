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


def main() -> int:
    args = parse_args()
    if args.command == "review":
        return run_review(args.target, args.json)
    if args.command == "patch-check":
        return run_patch_check(args.path, args.json)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
