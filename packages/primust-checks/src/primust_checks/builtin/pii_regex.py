"""PII regex check -- mathematical proof ceiling.

Detects SSNs, credit cards (with Luhn validation), emails, and US phone numbers.
"""

from __future__ import annotations

import re
from typing import Any

from ..result import CheckResult

SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
PHONE_PATTERN = re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b")
CREDIT_CARD_PATTERN = re.compile(r"\b(\d[ \-]?){13,19}\b")


def _luhn_check(number: str) -> bool:
    """Validate a number string using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def check_pii_regex(
    *,
    input: Any,
    output: Any = None,
    context: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
) -> CheckResult:
    """Scan input (and optionally output) for PII patterns.

    Config options:
        disable_patterns: list of pattern names to skip.
            Valid names: ssn, email, phone, credit_card
    """
    config = config or {}
    disabled = set(config.get("disable_patterns", []))

    text = str(input)
    if output is not None:
        text += "\n" + str(output)

    matched_types: list[str] = []

    if "ssn" not in disabled and SSN_PATTERN.search(text):
        matched_types.append("ssn")

    if "email" not in disabled and EMAIL_PATTERN.search(text):
        matched_types.append("email")

    if "phone" not in disabled and PHONE_PATTERN.search(text):
        matched_types.append("phone")

    if "credit_card" not in disabled:
        for match in CREDIT_CARD_PATTERN.finditer(text):
            raw = match.group(0)
            digits_only = re.sub(r"[^\d]", "", raw)
            if _luhn_check(digits_only):
                matched_types.append("credit_card")
                break

    return CheckResult(
        passed=len(matched_types) == 0,
        check_id="pii_regex",
        evidence=f"pii_types_found={matched_types}" if matched_types else "no PII detected",
        details={"pattern_types_matched": matched_types},
        proof_ceiling="mathematical",
    )
