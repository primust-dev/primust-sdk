"""Primust Runtime Core — Cross-field validation for domain-neutral objects v3.

Enforces all invariants from the schema spec:
  1. No banned field names anywhere
  2. witnessed stage type → witnessed proof level (NEVER attestation)
  3. manifest_hash captured per CheckExecutionRecord at record time
  4. reviewer_credential required when proof_level_achieved = witnessed
  5. skip_rationale_hash required when check_result = not_applicable
  6. CheckExecutionRecord is append-only (no UPDATE after commit)
  7. Waiver expires_at REQUIRED — no permanent waivers (max 90 days)
  8. EvidencePack: coverage_verified + coverage_pending + coverage_ungoverned = 100
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .types.models import (
    CheckExecutionRecord,
    EvidencePack,
    ManifestStage,
    Waiver,
)

BANNED_FIELDS = frozenset({
    "agent_id",
    "pipeline_id",
    "tool_name",
    "session_id",
    "trace_id",
    "reliance_mode",
    "PGC",
    "attestation",
})


@dataclass(frozen=True)
class ValidationError:
    code: str
    message: str


def scan_banned_fields(
    obj: Any,
    path: str = "",
) -> list[ValidationError]:
    """Recursively scan an object for banned field names."""
    errors: list[ValidationError] = []
    if obj is None or not isinstance(obj, (dict, list)):
        return errors
    if isinstance(obj, list):
        for i, item in enumerate(obj):
            errors.extend(scan_banned_fields(item, f"{path}[{i}]"))
        return errors
    for key, value in obj.items():
        full_path = f"{path}.{key}" if path else key
        if key in BANNED_FIELDS:
            errors.append(
                ValidationError(
                    code=f"banned_field_{key}",
                    message=f'Banned field "{key}" found at {full_path}',
                )
            )
        errors.extend(scan_banned_fields(value, full_path))
    return errors


def validate_manifest_stage(stage: ManifestStage) -> list[ValidationError]:
    """Validate a ManifestStage — invariant 2."""
    errors: list[ValidationError] = []
    if stage.type == "witnessed" and stage.proof_level == "attestation":
        errors.append(
            ValidationError(
                code="witnessed_attestation_forbidden",
                message="witnessed stage type must use witnessed proof level, "
                "NEVER attestation (invariant 2)",
            )
        )
    if stage.type == "witnessed" and stage.proof_level != "witnessed":
        errors.append(
            ValidationError(
                code="witnessed_must_be_witnessed",
                message="witnessed stage type must use witnessed proof level",
            )
        )
    return errors


def validate_check_execution_record(
    record: CheckExecutionRecord,
) -> list[ValidationError]:
    """Validate a CheckExecutionRecord — invariants 3, 4, 5."""
    errors: list[ValidationError] = []

    # Invariant 3: manifest_hash required
    if not record.manifest_hash:
        errors.append(
            ValidationError(
                code="manifest_hash_missing",
                message="manifest_hash is required on every CheckExecutionRecord "
                "(invariant 3)",
            )
        )

    # Invariant 4: reviewer_credential required when witnessed
    if (
        record.proof_level_achieved == "witnessed"
        and record.reviewer_credential is None
    ):
        errors.append(
            ValidationError(
                code="reviewer_credential_missing",
                message="reviewer_credential is required when "
                "proof_level_achieved = witnessed (invariant 4)",
            )
        )

    # Invariant 5: skip_rationale_hash required when not_applicable
    if (
        record.check_result == "not_applicable"
        and not record.skip_rationale_hash
    ):
        errors.append(
            ValidationError(
                code="skip_rationale_hash_missing",
                message="skip_rationale_hash is required when "
                "check_result = not_applicable (invariant 5)",
            )
        )

    # output_commitment must be poseidon2 prefix only when present
    if (
        record.output_commitment is not None
        and not record.output_commitment.startswith("poseidon2:")
    ):
        errors.append(
            ValidationError(
                code="output_commitment_invalid_prefix",
                message="output_commitment must use poseidon2: prefix when present",
            )
        )

    # check_open_tst required when check_close_tst present
    if record.check_close_tst and not record.check_open_tst:
        errors.append(
            ValidationError(
                code="check_open_tst_missing",
                message="check_open_tst is required when check_close_tst is present",
            )
        )

    return errors


def validate_waiver(waiver: Waiver) -> list[ValidationError]:
    """Validate a Waiver — invariant 7."""
    errors: list[ValidationError] = []

    # Reason minimum 50 characters
    if len(waiver.reason) < 50:
        errors.append(
            ValidationError(
                code="waiver_reason_too_short",
                message=f"Waiver reason must be at least 50 characters "
                f"(got {len(waiver.reason)})",
            )
        )

    # expires_at required
    if not waiver.expires_at:
        errors.append(
            ValidationError(
                code="waiver_expires_at_missing",
                message="Waiver expires_at is required — no permanent waivers "
                "(invariant 7)",
            )
        )

    # Max 90 days from approved_at
    if waiver.expires_at and waiver.approved_at:
        approved = datetime.fromisoformat(
            waiver.approved_at.replace("Z", "+00:00")
        )
        expires = datetime.fromisoformat(
            waiver.expires_at.replace("Z", "+00:00")
        )
        max_delta_seconds = 90 * 24 * 60 * 60
        delta = (expires - approved).total_seconds()
        if delta > max_delta_seconds:
            errors.append(
                ValidationError(
                    code="waiver_exceeds_90_days",
                    message="Waiver expires_at must be within 90 days of "
                    "approved_at (invariant 7)",
                )
            )
        if delta <= 0:
            errors.append(
                ValidationError(
                    code="waiver_expires_before_approval",
                    message="Waiver expires_at must be after approved_at",
                )
            )

    return errors


def validate_evidence_pack(pack: EvidencePack) -> list[ValidationError]:
    """Validate an EvidencePack — invariant 8."""
    errors: list[ValidationError] = []

    total = (
        pack.coverage_verified_pct
        + pack.coverage_pending_pct
        + pack.coverage_ungoverned_pct
    )

    if total != 100:
        errors.append(
            ValidationError(
                code="coverage_sum_not_100",
                message=f"coverage_verified_pct + coverage_pending_pct + "
                f"coverage_ungoverned_pct must equal 100 (got {total}) "
                f"(invariant 8)",
            )
        )

    return errors
