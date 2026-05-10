#!/usr/bin/env python3
"""Interactive security review application for Chrome extensions and WhatsApp integrations."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Question:
    text: str
    weight: int = 1


REVIEW_QUESTIONS: dict[str, list[Question]] = {
    "chrome": [
        Question("Does the extension request only minimum permissions (least privilege)?", 3),
        Question("Is remote code execution prevented (no eval, no remote scripts)?", 3),
        Question("Are content scripts scoped to specific domains instead of <all_urls>?", 2),
        Question("Is user data encrypted in transit (HTTPS/TLS everywhere)?", 2),
        Question("Is sensitive data (tokens, credentials) avoided in local storage?", 2),
        Question("Are third-party libraries pinned and regularly updated?", 2),
        Question("Is CSP strict and aligned with Manifest V3 best practices?", 2),
        Question("Are telemetry/analytics disclosures clear and opt-in where required?", 1),
    ],
    "whatsapp": [
        Question("Are webhook endpoints authenticated and signature-verified?", 3),
        Question("Is message data retention minimized and time-bounded?", 2),
        Question("Are access tokens stored securely and rotated periodically?", 3),
        Question("Is role-based access enforced for agents handling chats?", 2),
        Question("Are PII and media attachments encrypted at rest?", 2),
        Question("Are abuse controls in place (rate limits, spam/fraud detection)?", 2),
        Question("Is incident response defined for account compromise or data leakage?", 2),
        Question("Are user-consent and privacy notices available and explicit?", 1),
    ],
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a lightweight security review questionnaire")
    parser.add_argument("target", choices=sorted(REVIEW_QUESTIONS.keys()), help="Review template target")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON report")
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


def main() -> int:
    args = parse_args()
    questions = REVIEW_QUESTIONS[args.target]

    passed: list[str] = []
    failed: list[str] = []
    score = 0
    max_score = sum(q.weight for q in questions)

    print(f"Security Review: {args.target.title()}\n")
    for index, question in enumerate(questions, start=1):
        ok = ask_boolean(f"{index}. {question.text}")
        if ok:
            score += question.weight
            passed.append(question.text)
        else:
            failed.append(question.text)

    risk = grade(score, max_score)
    result = {
        "target": args.target,
        "score": score,
        "max_score": max_score,
        "risk": risk,
        "passed": passed,
        "failed": failed,
    }

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    print("\n=== Review Summary ===")
    print(f"Score: {score}/{max_score}")
    print(f"Overall: {risk}")
    print("Passed controls:")
    for item in passed:
        print(f"  - {item}")
    print("Failed controls:")
    for item in failed:
        print(f"  - {item}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
