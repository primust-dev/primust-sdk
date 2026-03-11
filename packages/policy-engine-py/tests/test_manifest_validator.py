"""Tests for manifest_validator — Python mirror of manifest_validator.test.ts."""

from __future__ import annotations

from typing import Any

import pytest

from primust_policy_engine.manifest_validator import (
    PROOF_LEVEL_HIERARCHY,
    bind_benchmark,
    compute_manifest_hash,
    compute_proof_ceiling,
    validate_manifest,
    validate_record_fields,
)


# ── Helpers ──


def make_manifest(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "manifest_id": "placeholder",
        "manifest_hash": "sha256:" + "a" * 64,
        "domain": "ai_agent",
        "name": "test_check",
        "semantic_version": "1.0.0",
        "check_type": "safety_check",
        "implementation_type": "rule",
        "supported_proof_level": "execution",
        "evaluation_scope": "per_run",
        "evaluation_window_seconds": None,
        "stages": [
            {
                "stage": 1,
                "name": "ML Eval",
                "type": "ml_model",
                "proof_level": "execution",
                "redacted": False,
            },
        ],
        "aggregation_config": {
            "method": "all_stages_must_pass",
            "threshold": None,
        },
        "freshness_threshold_hours": None,
        "benchmark": None,
        "model_or_tool_hash": None,
        "publisher": "primust",
        "signer_id": "signer_test",
        "kid": "kid_test",
        "signed_at": "2026-03-10T00:00:00Z",
        "signature": {
            "signer_id": "signer_test",
            "kid": "kid_test",
            "algorithm": "Ed25519",
            "signature": "sig_placeholder",
            "signed_at": "2026-03-10T00:00:00Z",
        },
    }
    base.update(overrides)
    return base


def make_record(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_id": "rec_001",
        "run_id": "run_001",
        "action_unit_id": "au_1",
        "manifest_id": "manifest_001",
        "manifest_hash": "sha256:" + "a" * 64,
        "surface_id": "surf_001",
        "commitment_hash": "poseidon2:" + "b" * 64,
        "output_commitment": None,
        "commitment_algorithm": "poseidon2",
        "commitment_type": "input_commitment",
        "check_result": "pass",
        "proof_level_achieved": "execution",
        "proof_pending": False,
        "zkml_proof_pending": False,
        "check_open_tst": None,
        "check_close_tst": None,
        "skip_rationale_hash": None,
        "reviewer_credential": None,
        "unverified_provenance": False,
        "freshness_warning": False,
        "chain_hash": "sha256:" + "c" * 64,
        "idempotency_key": "idem_001",
        "recorded_at": "2026-03-10T00:00:00Z",
    }
    base.update(overrides)
    return base


# ── Tests ──


class TestManifestValidator:
    def test_human_review_proof_ceiling_witnessed(self) -> None:
        manifest = make_manifest(
            supported_proof_level="witnessed",
            stages=[
                {"stage": 1, "name": "Human Review", "type": "human_review",
                 "proof_level": "witnessed", "redacted": False},
            ],
        )
        assert compute_proof_ceiling(manifest) == "witnessed"

    def test_human_review_never_attestation(self) -> None:
        manifest = make_manifest(
            supported_proof_level="attestation",
            stages=[
                {"stage": 1, "name": "Human Review", "type": "human_review",
                 "proof_level": "attestation", "redacted": False},
            ],
        )
        errors = validate_manifest(manifest)
        codes = [e.code for e in errors]
        assert "human_review_attestation_forbidden" in codes

    def test_proof_level_above_ceiling_error(self) -> None:
        manifest = make_manifest(
            supported_proof_level="mathematical",
            stages=[
                {"stage": 1, "name": "ML Eval", "type": "ml_model",
                 "proof_level": "execution", "redacted": False},
            ],
        )
        errors = validate_manifest(manifest)
        codes = [e.code for e in errors]
        assert "proof_level_above_ceiling" in codes

    def test_manifest_hash_deterministic(self) -> None:
        manifest = make_manifest()
        hash1 = compute_manifest_hash(manifest)
        hash2 = compute_manifest_hash(manifest)
        assert hash1 == hash2
        assert hash1.startswith("sha256:")
        assert len(hash1) == len("sha256:") + 64

    def test_manifest_id_equals_manifest_hash(self) -> None:
        manifest = make_manifest()
        h = compute_manifest_hash(manifest)
        well_formed = make_manifest(manifest_id=h, manifest_hash=h)
        assert well_formed["manifest_id"] == well_formed["manifest_hash"]
        assert well_formed["manifest_id"] == compute_manifest_hash(well_formed)

    def test_benchmark_present_changes_hash(self) -> None:
        bench_a = {
            "benchmark_id": "bench_001",
            "benchmark_hash": "sha256:" + "a" * 64,
            "precision": 0.95, "recall": 0.92, "f1": 0.935,
            "test_dataset": "test_v1", "published_by": "primust",
        }
        bench_b = {
            "benchmark_id": "bench_002",
            "benchmark_hash": "sha256:" + "b" * 64,
            "precision": 0.88, "recall": 0.85, "f1": 0.865,
            "test_dataset": "test_v2", "published_by": "primust",
        }
        hash_a = compute_manifest_hash(make_manifest(benchmark=bench_a))
        hash_b = compute_manifest_hash(make_manifest(benchmark=bench_b))
        assert hash_a != hash_b

    def test_benchmark_absent_no_impact(self) -> None:
        manifest = make_manifest(benchmark=None)
        h = compute_manifest_hash(manifest)
        assert manifest["benchmark"] is None
        assert h.startswith("sha256:")
        assert compute_manifest_hash(make_manifest(benchmark=None)) == h

    def test_all_5_proof_levels(self) -> None:
        assert PROOF_LEVEL_HIERARCHY == [
            "mathematical", "execution_zkml", "execution", "witnessed", "attestation",
        ]
        assert len(PROOF_LEVEL_HIERARCHY) == 5

    def test_zkml_model_proof_ceiling(self) -> None:
        manifest = make_manifest(
            supported_proof_level="execution_zkml",
            stages=[
                {"stage": 1, "name": "ZKML Eval", "type": "zkml_model",
                 "proof_level": "execution_zkml", "redacted": False},
            ],
        )
        assert compute_proof_ceiling(manifest) == "execution_zkml"

    def test_skip_rationale_required_not_applicable(self) -> None:
        record = make_record(check_result="not_applicable", skip_rationale_hash=None)
        errors = validate_record_fields(record)
        codes = [e.code for e in errors]
        assert "skip_rationale_hash_missing" in codes

    def test_mixed_stages_weakest_ceiling(self) -> None:
        manifest = make_manifest(
            supported_proof_level="witnessed",
            stages=[
                {"stage": 1, "name": "Rule", "type": "deterministic_rule",
                 "proof_level": "mathematical", "redacted": False},
                {"stage": 2, "name": "Review", "type": "human_review",
                 "proof_level": "witnessed", "redacted": False},
            ],
        )
        assert compute_proof_ceiling(manifest) == "witnessed"

    def test_bind_benchmark(self) -> None:
        manifest = make_manifest(benchmark=None)
        benchmark = {
            "benchmark_id": "bench_001",
            "benchmark_hash": "sha256:" + "a" * 64,
            "precision": 0.95, "recall": 0.92, "f1": 0.935,
            "test_dataset": "test_v1", "published_by": "primust",
        }
        bound = bind_benchmark(manifest, benchmark)
        assert bound["benchmark"] is benchmark
        assert bound["name"] == manifest["name"]
