"""Reconciliation check -- mathematical proof ceiling.

Verifies two datasets reconcile: records match on key fields and
numeric totals agree within tolerance.

Domain-neutral: works for financial reconciliation, data pipeline
validation, inventory checks, clinical data matching, etc.
"""

from __future__ import annotations

from typing import Any

from ..result import CheckResult


def check_reconciliation(
    *,
    input: Any,
    output: Any = None,
    context: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
) -> CheckResult:
    """Verify two datasets reconcile on key fields and numeric totals.

    input must be a dict containing:
      - source: list of dicts (records)
      - target: list of dicts (records)
      - key_fields: list of field names to match on
      - sum_fields: (optional) list of numeric fields to compare totals

    config options:
      - tolerance: float (default 0.0) — allowed absolute difference
        for numeric comparisons.
    """
    config = config or {}
    input_data = input if isinstance(input, dict) else {}

    source = input_data.get("source")
    target = input_data.get("target")
    key_fields = input_data.get("key_fields")

    if source is None or target is None or key_fields is None:
        return CheckResult(
            passed=False,
            check_id="reconciliation_check",
            evidence="Missing required input keys: source, target, key_fields",
            proof_ceiling="mathematical",
        )

    if not isinstance(source, list) or not isinstance(target, list):
        return CheckResult(
            passed=False,
            check_id="reconciliation_check",
            evidence="source and target must be lists of records",
            proof_ceiling="mathematical",
        )

    tolerance = float(config.get("tolerance", 0.0))
    sum_fields = input_data.get("sum_fields", [])
    errors: list[str] = []

    # Build key-indexed lookups
    def _make_key(record: dict[str, Any]) -> tuple[Any, ...]:
        return tuple(record.get(k) for k in key_fields)

    source_by_key: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for rec in source:
        if not isinstance(rec, dict):
            continue
        k = _make_key(rec)
        source_by_key.setdefault(k, []).append(rec)

    target_by_key: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for rec in target:
        if not isinstance(rec, dict):
            continue
        k = _make_key(rec)
        target_by_key.setdefault(k, []).append(rec)

    # Key presence checks
    source_only = set(source_by_key.keys()) - set(target_by_key.keys())
    target_only = set(target_by_key.keys()) - set(target_by_key.keys()) | (
        set(target_by_key.keys()) - set(source_by_key.keys())
    )

    if source_only:
        errors.append(f"{len(source_only)} key(s) in source but not target")
    if target_only:
        errors.append(f"{len(target_only)} key(s) in target but not source")

    # Count mismatches (same key, different number of records)
    common_keys = set(source_by_key.keys()) & set(target_by_key.keys())
    count_mismatches = 0
    for k in common_keys:
        if len(source_by_key[k]) != len(target_by_key[k]):
            count_mismatches += 1
    if count_mismatches:
        errors.append(f"{count_mismatches} key(s) with record count mismatch")

    # Sum field comparisons
    sum_mismatches: list[str] = []
    for sf in sum_fields:
        source_total = sum(
            float(r.get(sf, 0)) for r in source if isinstance(r, dict)
        )
        target_total = sum(
            float(r.get(sf, 0)) for r in target if isinstance(r, dict)
        )
        diff = abs(source_total - target_total)
        if diff > tolerance:
            sum_mismatches.append(
                f"{sf}: source={source_total}, target={target_total}, diff={diff}"
            )

    if sum_mismatches:
        errors.append(f"Sum field mismatches: {'; '.join(sum_mismatches)}")

    passed = len(errors) == 0
    return CheckResult(
        passed=passed,
        check_id="reconciliation_check",
        evidence=(
            f"reconciled: {len(common_keys)} matching key(s)"
            if passed
            else f"{len(errors)} reconciliation error(s)"
        ),
        details={
            "common_keys": len(common_keys),
            "source_only_keys": len(source_only),
            "target_only_keys": len(target_only),
            "count_mismatches": count_mismatches,
            "sum_mismatches": sum_mismatches,
            "errors": errors,
        },
        proof_ceiling="mathematical",
    )
