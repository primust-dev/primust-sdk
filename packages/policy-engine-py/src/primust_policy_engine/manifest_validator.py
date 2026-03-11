"""Primust Policy Engine — Manifest Validation + Proof Ceiling (Python).

Pure functions, no database dependency.

PROOF CEILING: weakest stage.proof_level across all stages.
Hierarchy: mathematical > execution_zkml > execution > witnessed > attestation

MANIFEST HASH: SHA256(canonical(manifest_without_manifest_id_manifest_hash_and_signature))
manifest_id = manifest_hash (content-addressed identity)
"""

from __future__ import annotations

import hashlib
from typing import Any, Literal

from primust_artifact_core.canonical import canonical
from primust_runtime_core.types.models import (
    CheckExecutionRecord,
    ManifestStage,
)
from primust_runtime_core.validate_schemas import (
    ValidationError,
    validate_check_execution_record,
    validate_manifest_stage,
)

# ── Constants ──

ProofLevel = Literal[
    "mathematical",
    "execution_zkml",
    "execution",
    "witnessed",
    "attestation",
]

PROOF_LEVEL_HIERARCHY: list[str] = [
    "mathematical",
    "execution_zkml",
    "execution",
    "witnessed",
    "attestation",
]
"""Proof level hierarchy: lower index = stronger."""


# ── Helpers ──


def _proof_level_rank(level: str) -> int:
    try:
        return PROOF_LEVEL_HIERARCHY.index(level)
    except ValueError:
        raise ValueError(f"Unknown proof level: {level}")


# ── Proof Ceiling ──


def compute_proof_ceiling(manifest: dict[str, Any]) -> str:
    """Compute the proof ceiling: weakest stage.proof_level across all stages."""
    stages = manifest.get("stages", [])
    if not stages:
        return "attestation"

    weakest = stages[0]["proof_level"]
    for stage in stages:
        if _proof_level_rank(stage["proof_level"]) > _proof_level_rank(weakest):
            weakest = stage["proof_level"]
    return weakest


# ── Manifest Hash ──


def compute_manifest_hash(manifest: dict[str, Any]) -> str:
    """Compute the manifest hash: SHA256(canonical(manifest without manifest_id,
    manifest_hash, and signature)). Returns 'sha256:' prefixed hex string."""
    content = {
        k: v
        for k, v in manifest.items()
        if k not in ("manifest_id", "manifest_hash", "signature")
    }
    canonical_str = canonical(content)
    hash_hex = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
    return f"sha256:{hash_hex}"


# ── Manifest Validation ──


def validate_manifest(manifest: dict[str, Any]) -> list[ValidationError]:
    """Validate a CheckManifest. Returns validation errors.

    Delegates to runtime-core validate_manifest_stage() per stage, then adds
    whole-manifest checks: proof ceiling consistency, stage numbering.
    """
    errors: list[ValidationError] = []

    stages = manifest.get("stages", [])
    if not stages:
        errors.append(ValidationError(
            code="manifest_no_stages",
            message="Manifest must have at least one stage",
        ))
        return errors

    # Validate each stage (convert dicts to ManifestStage dataclass for runtime-core)
    for stage in stages:
        stage_obj = ManifestStage(**stage)
        errors.extend(validate_manifest_stage(stage_obj))

    # Proof ceiling consistency
    computed_ceiling = compute_proof_ceiling(manifest)
    supported = manifest.get("supported_proof_level", "attestation")

    if _proof_level_rank(supported) < _proof_level_rank(computed_ceiling):
        errors.append(ValidationError(
            code="proof_level_above_ceiling",
            message=(
                f"supported_proof_level ({supported}) is above "
                f"the computed proof ceiling ({computed_ceiling})"
            ),
        ))

    if supported != computed_ceiling:
        errors.append(ValidationError(
            code="proof_ceiling_mismatch",
            message=(
                f"supported_proof_level ({supported}) does not match "
                f"computed proof ceiling ({computed_ceiling})"
            ),
        ))

    # evaluation_window_seconds required for per_window
    if (
        manifest.get("evaluation_scope") == "per_window"
        and manifest.get("evaluation_window_seconds") is None
    ):
        errors.append(ValidationError(
            code="window_seconds_required",
            message="evaluation_window_seconds is required when evaluation_scope = per_window",
        ))

    return errors


# ── Benchmark Binding ──


def bind_benchmark(
    manifest: dict[str, Any],
    benchmark: dict[str, Any],
) -> dict[str, Any]:
    """Bind a benchmark to a manifest. Returns a new manifest with the benchmark."""
    return {**manifest, "benchmark": benchmark}


# ── Record Field Validation ──


def validate_record_fields(record: dict[str, Any]) -> list[ValidationError]:
    """Validate required fields on a CheckExecutionRecord.
    Delegates to runtime-core validate_check_execution_record().
    """
    record_obj = CheckExecutionRecord(**record)
    return validate_check_execution_record(record_obj)
