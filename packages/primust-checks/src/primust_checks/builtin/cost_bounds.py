"""Cost bounds check -- mathematical proof ceiling.

Enforces token count and cost USD limits.
"""

from __future__ import annotations

from typing import Any

from ..result import CheckResult

DEFAULT_MAX_TOKENS = 100_000
DEFAULT_MAX_COST_USD = 1.00


def check_cost_bounds(
    *,
    input: Any,
    output: Any = None,
    context: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
) -> CheckResult:
    """Check that token_count and cost_usd are within bounds.

    Reads limits from config (falls back to defaults).
    Input should be a dict containing 'token_count' and/or 'cost_usd'.
    Context dict is also checked for these keys.
    """
    config = config or {}
    max_tokens = config.get("max_tokens_per_run", DEFAULT_MAX_TOKENS)
    max_cost = config.get("max_cost_usd", DEFAULT_MAX_COST_USD)

    # Gather values from input (if dict) and context
    values: dict[str, Any] = {}
    if isinstance(input, dict):
        values.update(input)
    if context and isinstance(context, dict):
        values.update(context)

    token_count = values.get("token_count")
    cost_usd = values.get("cost_usd")

    violations: list[str] = []
    evidence_parts: list[str] = []

    if token_count is not None:
        evidence_parts.append(f"tokens={token_count}/{max_tokens}")
        if token_count > max_tokens:
            violations.append(f"token_count {token_count} exceeds max {max_tokens}")

    if cost_usd is not None:
        evidence_parts.append(f"cost=${cost_usd}/{max_cost}")
        if cost_usd > max_cost:
            violations.append(f"cost_usd {cost_usd} exceeds max {max_cost}")

    if token_count is None and cost_usd is None:
        evidence_parts.append("no cost/token data provided")

    passed = len(violations) == 0
    evidence = "; ".join(evidence_parts) if evidence_parts else "no data"

    return CheckResult(
        passed=passed,
        check_id="cost_bounds",
        evidence=evidence,
        details={"violations": violations, "token_count": token_count, "cost_usd": cost_usd},
        proof_ceiling="mathematical",
    )
