"""Secrets scanner check -- mathematical proof ceiling.

Detects AWS keys, GitHub tokens, GCP keys, and generic API keys
using configurable regex patterns.
"""

from __future__ import annotations

import re
from typing import Any

from ..result import CheckResult

DEFAULT_PATTERNS: dict[str, str] = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "github_token": r"gh[ps]_[A-Za-z0-9_]{36,}",
    "gcp_api_key": r"AIza[0-9A-Za-z_\-]{35}",
    "generic_api_key": r"(?<![A-Za-z0-9])[a-zA-Z0-9]{32,}(?![A-Za-z0-9])",
}


def check_secrets_scanner(
    *,
    input: Any,
    output: Any = None,
    context: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
) -> CheckResult:
    """Scan input (and optionally output) for secret patterns.

    Config options:
        patterns: dict mapping pattern name to regex string.
                  Overrides defaults when provided.
        skip_generic: bool, if True skips the generic_api_key pattern.
    """
    config = config or {}
    patterns = dict(DEFAULT_PATTERNS)

    if "patterns" in config:
        patterns = config["patterns"]
    elif config.get("skip_generic"):
        patterns.pop("generic_api_key", None)

    text = str(input)
    if output is not None:
        text += "\n" + str(output)

    matched: list[str] = []
    for name, pattern in patterns.items():
        if re.search(pattern, text):
            matched.append(name)

    return CheckResult(
        passed=len(matched) == 0,
        check_id="secrets_scanner",
        evidence=f"matched_patterns={len(matched)}" if matched else "no secrets detected",
        details={"matched_patterns": matched},
        proof_ceiling="mathematical",
    )
