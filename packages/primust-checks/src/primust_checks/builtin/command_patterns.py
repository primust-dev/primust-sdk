"""Command patterns check -- mathematical proof ceiling.

Blocks dangerous shell commands and SQL patterns via denylist.
Supports optional allowlist overrides.
"""

from __future__ import annotations

import re
from typing import Any

from ..result import CheckResult

DEFAULT_DENYLIST: list[str] = [
    r"rm\s+-rf\b",
    r"DROP\s+TABLE\b",
    r"chmod\s+777\b",
    r"curl\s.*\|\s*bash",
    r"wget\s.*\|\s*sh",
    r"sudo\s+rm\b",
]


def check_command_patterns(
    *,
    input: Any,
    output: Any = None,
    context: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
) -> CheckResult:
    """Scan input for dangerous command patterns.

    Config options:
        denylist: list of regex strings to block (overrides defaults).
        allowlist: list of exact strings that are permitted even if they
                   match a deny pattern.
    """
    config = config or {}
    denylist = config.get("denylist", DEFAULT_DENYLIST)
    allowlist = set(config.get("allowlist", []))

    text = str(input)
    if output is not None:
        text += "\n" + str(output)

    # If the entire text is in the allowlist, skip scanning
    if text.strip() in allowlist:
        return CheckResult(
            passed=True,
            check_id="command_patterns",
            evidence="allowlisted",
            proof_ceiling="mathematical",
        )

    matched: list[str] = []
    for pattern in denylist:
        if re.search(pattern, text, re.IGNORECASE):
            matched.append(pattern)

    return CheckResult(
        passed=len(matched) == 0,
        check_id="command_patterns",
        evidence=f"blocked_patterns={matched}" if matched else "no dangerous patterns",
        details={"matched_patterns": matched},
        proof_ceiling="mathematical",
    )
