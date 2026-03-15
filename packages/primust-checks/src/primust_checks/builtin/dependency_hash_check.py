"""Dependency hash check -- mathematical proof ceiling.

Verifies file/artifact hashes match expected values. Works for
SBOM verification, lockfile integrity, build artifact validation,
or any scenario where artifacts must match known-good hashes.

Domain-neutral: applies to software supply chain, manufacturing
batch records, pharmaceutical ingredient verification, etc.
"""

from __future__ import annotations

from typing import Any

from ..result import CheckResult


def check_dependency_hash(
    *,
    input: Any,
    output: Any = None,
    context: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
) -> CheckResult:
    """Verify artifact hashes match expected values.

    input must be a dict containing:
      - artifacts: list of {"name": str, "hash": str}
      - expected_hashes: dict mapping name -> expected hash string

    config options:
      - algorithm: str (default "sha256") — hash algorithm label
        (informational; actual hash comparison is string equality).
    """
    config = config or {}
    input_data = input if isinstance(input, dict) else {}

    artifacts = input_data.get("artifacts")
    expected_hashes = input_data.get("expected_hashes")

    if artifacts is None or expected_hashes is None:
        return CheckResult(
            passed=False,
            check_id="dependency_hash_check",
            evidence="Missing required input keys: artifacts, expected_hashes",
            proof_ceiling="mathematical",
        )

    if not isinstance(artifacts, list) or not isinstance(expected_hashes, dict):
        return CheckResult(
            passed=False,
            check_id="dependency_hash_check",
            evidence="artifacts must be a list, expected_hashes must be a dict",
            proof_ceiling="mathematical",
        )

    algorithm = config.get("algorithm", "sha256")
    mismatched: list[str] = []
    missing_expected: list[str] = []
    verified = 0

    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        name = artifact.get("name", "")
        actual_hash = artifact.get("hash", "")

        if name not in expected_hashes:
            missing_expected.append(name)
            continue

        expected = expected_hashes[name]
        if actual_hash != expected:
            mismatched.append(name)
        else:
            verified += 1

    errors: list[str] = []
    if mismatched:
        errors.append(f"Hash mismatch for: {', '.join(sorted(mismatched))}")
    if missing_expected:
        errors.append(
            f"No expected hash for: {', '.join(sorted(missing_expected))}"
        )

    passed = len(mismatched) == 0

    return CheckResult(
        passed=passed,
        check_id="dependency_hash_check",
        evidence=(
            f"all {verified} artifact(s) verified ({algorithm})"
            if passed
            else f"{len(mismatched)} hash mismatch(es)"
        ),
        details={
            "algorithm": algorithm,
            "verified": verified,
            "mismatched": mismatched,
            "missing_expected": missing_expected,
            "errors": errors,
        },
        proof_ceiling="mathematical",
    )
