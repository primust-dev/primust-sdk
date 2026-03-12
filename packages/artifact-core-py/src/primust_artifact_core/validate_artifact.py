"""VPEC Artifact validation — enforces all critical invariants.

This is structural/semantic validation beyond what JSON Schema covers.
JSON Schema handles type checks; this function enforces cross-field invariants.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

PROOF_LEVELS = frozenset(
    ["mathematical", "verifiable_inference", "execution", "witnessed", "attestation"]
)

GAP_TYPES = frozenset(
    [
        "check_not_executed",
        "enforcement_override",
        "engine_error",
        "check_degraded",
        "external_boundary_traversal",
        "lineage_token_missing",
        "admission_gate_override",
        "check_timing_suspect",
        "reviewer_credential_invalid",
        "witnessed_display_missing",
        "witnessed_rationale_missing",
        "deterministic_consistency_violation",
        "skip_rationale_missing",
        "policy_config_drift",
        "zkml_proof_pending_timeout",
        "zkml_proof_failed",
    ]
)

GAP_SEVERITIES = frozenset(["Critical", "High", "Medium", "Low", "Informational"])

PUBLIC_KEY_URL_PATTERN = re.compile(
    r"^https://primust\.com/\.well-known/primust-pubkeys/.+\.pem$"
)


@dataclass(frozen=True)
class ValidationError:
    code: str
    message: str
    path: str | None = None


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    errors: list[ValidationError] = field(default_factory=list)


def _check_nested_reliance_mode(
    obj: dict[str, Any], path: str, errors: list[ValidationError]
) -> None:
    """Recursively check for reliance_mode in any nested object."""
    for key, value in obj.items():
        current_path = f"{path}.{key}" if path else key
        if key == "reliance_mode" and current_path != "reliance_mode":
            errors.append(
                ValidationError(
                    code="RELIANCE_MODE_FORBIDDEN",
                    message=f"reliance_mode field is forbidden in VPEC artifacts (found at {current_path})",
                    path=current_path,
                )
            )
        if isinstance(value, dict):
            _check_nested_reliance_mode(value, current_path, errors)


def validate_artifact(artifact: dict[str, Any]) -> ValidationResult:
    """Validate a VPEC artifact against all critical invariants.

    Args:
        artifact: The artifact payload (parsed JSON dict).

    Returns:
        ValidationResult with errors if any invariants are violated.
    """
    errors: list[ValidationError] = []

    # Invariant 2: reliance_mode field ANYWHERE -> validation error
    if "reliance_mode" in artifact:
        errors.append(
            ValidationError(
                code="RELIANCE_MODE_FORBIDDEN",
                message="reliance_mode field is forbidden in VPEC artifacts",
                path="reliance_mode",
            )
        )
    _check_nested_reliance_mode(artifact, "", errors)

    # schema_version must be 4.0.0
    if artifact.get("schema_version") != "4.0.0":
        errors.append(
            ValidationError(
                code="INVALID_SCHEMA_VERSION",
                message=f'schema_version must be "4.0.0", got "{artifact.get("schema_version")}"',
                path="schema_version",
            )
        )

    # Invariant 1: proof_level MUST equal proof_distribution.weakest_link
    proof_dist = artifact.get("proof_distribution")
    if isinstance(proof_dist, dict) and artifact.get("proof_level") != proof_dist.get(
        "weakest_link"
    ):
        errors.append(
            ValidationError(
                code="PROOF_LEVEL_MISMATCH",
                message=f'proof_level "{artifact.get("proof_level")}" does not match proof_distribution.weakest_link "{proof_dist.get("weakest_link")}"',
                path="proof_level",
            )
        )

    # Validate proof_level is a valid enum value
    proof_level = artifact.get("proof_level")
    if proof_level and proof_level not in PROOF_LEVELS:
        errors.append(
            ValidationError(
                code="INVALID_PROOF_LEVEL",
                message=f'proof_level "{proof_level}" is not a valid proof level',
                path="proof_level",
            )
        )

    # Invariant 3: manifest_hashes MUST be object (map), not array
    if isinstance(artifact.get("manifest_hashes"), list):
        errors.append(
            ValidationError(
                code="MANIFEST_HASHES_NOT_MAP",
                message="manifest_hashes must be a dict (map), not a list",
                path="manifest_hashes",
            )
        )

    # Invariant 4: gaps[] entries MUST have gap_type and severity
    gaps = artifact.get("gaps")
    if isinstance(gaps, list):
        for i, gap in enumerate(gaps):
            if isinstance(gap, str):
                errors.append(
                    ValidationError(
                        code="GAP_BARE_STRING",
                        message=f"gaps[{i}] is a bare string — must be an object with gap_type and severity",
                        path=f"gaps[{i}]",
                    )
                )
                continue

            if not isinstance(gap, dict):
                errors.append(
                    ValidationError(
                        code="GAP_INVALID_TYPE",
                        message=f"gaps[{i}] must be a dict with gap_type and severity",
                        path=f"gaps[{i}]",
                    )
                )
                continue

            if not gap.get("gap_type") or not gap.get("severity"):
                errors.append(
                    ValidationError(
                        code="GAP_MISSING_FIELDS",
                        message=f"gaps[{i}] must have gap_type and severity fields",
                        path=f"gaps[{i}]",
                    )
                )

            if gap.get("gap_type") and gap["gap_type"] not in GAP_TYPES:
                errors.append(
                    ValidationError(
                        code="GAP_INVALID_TYPE_VALUE",
                        message=f'gaps[{i}].gap_type "{gap["gap_type"]}" is not a valid gap type',
                        path=f"gaps[{i}].gap_type",
                    )
                )

            if gap.get("severity") and gap["severity"] not in GAP_SEVERITIES:
                errors.append(
                    ValidationError(
                        code="GAP_INVALID_SEVERITY",
                        message=f'gaps[{i}].severity "{gap["severity"]}" is not a valid severity',
                        path=f"gaps[{i}].severity",
                    )
                )

    # Invariant 5: partial: true -> policy_coverage_pct must be 0
    coverage = artifact.get("coverage")
    if artifact.get("partial") is True and isinstance(coverage, dict):
        pct = coverage.get("policy_coverage_pct")
        if isinstance(pct, (int, float)) and pct != 0:
            errors.append(
                ValidationError(
                    code="PARTIAL_COVERAGE_NOT_ZERO",
                    message=f"partial: true requires policy_coverage_pct to be 0, got {pct}",
                    path="coverage.policy_coverage_pct",
                )
            )

    # Invariant 7: issuer.public_key_url must match primust.com/.well-known/ pattern
    issuer = artifact.get("issuer")
    if isinstance(issuer, dict) and isinstance(issuer.get("public_key_url"), str):
        if not PUBLIC_KEY_URL_PATTERN.match(issuer["public_key_url"]):
            errors.append(
                ValidationError(
                    code="ISSUER_URL_INVALID",
                    message=f'issuer.public_key_url must match https://primust.com/.well-known/primust-pubkeys/*.pem, got "{issuer["public_key_url"]}"',
                    path="issuer.public_key_url",
                )
            )

    return ValidationResult(valid=len(errors) == 0, errors=errors)
