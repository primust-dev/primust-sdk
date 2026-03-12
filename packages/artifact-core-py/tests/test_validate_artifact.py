"""Tests for VPEC artifact validation — mirrors TypeScript validate-artifact.test.ts."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from primust_artifact_core.validate_artifact import validate_artifact


def valid_artifact(**overrides: Any) -> dict[str, Any]:
    """Build a valid VPEC artifact fixture. Override fields as needed."""
    base: dict[str, Any] = {
        "vpec_id": "vpec_00000000-0000-0000-0000-000000000001",
        "schema_version": "4.0.0",
        "org_id": "org_test",
        "run_id": "run_00000000-0000-0000-0000-000000000001",
        "workflow_id": "wf_test",
        "process_context_hash": None,
        "policy_snapshot_hash": "sha256:" + "a" * 64,
        "policy_basis": "P1_self_declared",
        "partial": False,
        "surface_summary": [
            {
                "surface_id": "surf_1",
                "surface_type": "in_process_adapter",
                "observation_mode": "pre_action",
                "proof_ceiling": "execution",
                "scope_type": "full_workflow",
                "scope_description": "Full workflow adapter",
                "surface_coverage_statement": "All tool calls in graph scope",
            },
        ],
        "proof_level": "execution",
        "proof_distribution": {
            "mathematical": 0,
            "verifiable_inference": 0,
            "execution": 5,
            "witnessed": 0,
            "attestation": 0,
            "weakest_link": "execution",
            "weakest_link_explanation": "All checks ran in execution mode",
        },
        "state": "signed",
        "coverage": {
            "records_total": 5,
            "records_pass": 4,
            "records_fail": 0,
            "records_degraded": 1,
            "records_not_applicable": 0,
            "policy_coverage_pct": 100,
            "instrumentation_surface_pct": 95.5,
            "instrumentation_surface_basis": "LangGraph full_workflow adapter — all tool calls in graph scope.",
        },
        "gaps": [],
        "manifest_hashes": {
            "manifest_001": "sha256:" + "b" * 64,
        },
        "commitment_root": "poseidon2:" + "c" * 64,
        "commitment_algorithm": "poseidon2",
        "zk_proof": None,
        "issuer": {
            "signer_id": "signer_test",
            "kid": "kid_test",
            "algorithm": "Ed25519",
            "public_key_url": "https://primust.com/.well-known/primust-pubkeys/abc123.pem",
            "org_region": "us",
        },
        "signature": {
            "signer_id": "signer_test",
            "kid": "kid_test",
            "algorithm": "Ed25519",
            "signature": "dGVzdF9zaWduYXR1cmU",
            "signed_at": "2026-03-10T00:00:00Z",
        },
        "timestamp_anchor": {
            "type": "none",
            "tsa": "none",
            "value": None,
        },
        "transparency_log": {
            "rekor_log_id": None,
            "rekor_entry_url": None,
            "published_at": None,
        },
        "issued_at": "2026-03-10T00:00:00Z",
        "pending_flags": {
            "signature_pending": False,
            "proof_pending": False,
            "zkml_proof_pending": False,
            "submission_pending": False,
            "rekor_pending": True,
        },
        "test_mode": False,
    }
    # Deep copy to avoid mutations across tests, then merge overrides
    result = copy.deepcopy(base)
    result.update(overrides)
    return result


class TestValidateArtifact:
    def test_valid_artifact_passes(self):
        result = validate_artifact(valid_artifact())
        assert result.valid is True
        assert len(result.errors) == 0

    # ── MUST PASS: invariant enforcement ──

    def test_proof_level_above_weakest_link_error(self):
        artifact = valid_artifact(
            proof_level="mathematical",
            proof_distribution={
                "mathematical": 0,
                "verifiable_inference": 0,
                "execution": 5,
                "witnessed": 0,
                "attestation": 0,
                "weakest_link": "execution",
                "weakest_link_explanation": "All checks ran in execution mode",
            },
        )
        result = validate_artifact(artifact)
        assert result.valid is False
        assert any(e.code == "PROOF_LEVEL_MISMATCH" for e in result.errors)

    def test_reliance_mode_top_level_error(self):
        artifact = valid_artifact(reliance_mode="full")
        result = validate_artifact(artifact)
        assert result.valid is False
        assert any(e.code == "RELIANCE_MODE_FORBIDDEN" for e in result.errors)

    def test_reliance_mode_nested_error(self):
        artifact = valid_artifact()
        artifact["coverage"]["reliance_mode"] = "partial"
        result = validate_artifact(artifact)
        assert result.valid is False
        assert any(e.code == "RELIANCE_MODE_FORBIDDEN" for e in result.errors)

    def test_manifest_hashes_as_list_error(self):
        artifact = valid_artifact(
            manifest_hashes=["sha256:" + "a" * 64],
        )
        result = validate_artifact(artifact)
        assert result.valid is False
        assert any(e.code == "MANIFEST_HASHES_NOT_MAP" for e in result.errors)

    def test_gaps_bare_string_error(self):
        artifact = valid_artifact(gaps=["gap_001", "gap_002"])
        result = validate_artifact(artifact)
        assert result.valid is False
        assert any(e.code == "GAP_BARE_STRING" for e in result.errors)

    def test_test_mode_true_proof_pending_valid(self):
        artifact = valid_artifact(
            test_mode=True,
            state="provisional",
            pending_flags={
                "signature_pending": False,
                "proof_pending": True,
                "zkml_proof_pending": False,
                "submission_pending": False,
                "rekor_pending": True,
            },
        )
        result = validate_artifact(artifact)
        assert result.valid is True

    def test_schema_version_must_be_3(self):
        artifact = valid_artifact(schema_version="2.0.0")
        result = validate_artifact(artifact)
        assert result.valid is False
        assert any(e.code == "INVALID_SCHEMA_VERSION" for e in result.errors)

    def test_all_5_proof_levels_valid(self):
        levels = [
            "mathematical",
            "verifiable_inference",
            "execution",
            "witnessed",
            "attestation",
        ]
        for level in levels:
            artifact = valid_artifact(
                proof_level=level,
                proof_distribution={
                    "mathematical": 0,
                    "verifiable_inference": 0,
                    "execution": 0,
                    "witnessed": 0,
                    "attestation": 0,
                    level: 5,
                    "weakest_link": level,
                    "weakest_link_explanation": f"All at {level}",
                },
            )
            result = validate_artifact(artifact)
            assert not any(e.code == "INVALID_PROOF_LEVEL" for e in result.errors), (
                f"proof_level '{level}' should be valid"
            )

    def test_all_16_gap_types_valid(self):
        gap_types = [
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
        assert len(gap_types) == 16

        gaps = [
            {"gap_id": f"gap_{i}", "gap_type": gt, "severity": "Medium"}
            for i, gt in enumerate(gap_types)
        ]
        artifact = valid_artifact(gaps=gaps)
        result = validate_artifact(artifact)
        assert not any(e.code == "GAP_INVALID_TYPE_VALUE" for e in result.errors)

    # ── Additional invariants ──

    def test_partial_true_nonzero_coverage_error(self):
        artifact = valid_artifact(
            partial=True,
            coverage={
                "records_total": 5,
                "records_pass": 3,
                "records_fail": 0,
                "records_degraded": 0,
                "records_not_applicable": 2,
                "policy_coverage_pct": 60,
                "instrumentation_surface_pct": 100,
                "instrumentation_surface_basis": "Full scope",
            },
        )
        result = validate_artifact(artifact)
        assert result.valid is False
        assert any(e.code == "PARTIAL_COVERAGE_NOT_ZERO" for e in result.errors)

    def test_partial_true_zero_coverage_valid(self):
        artifact = valid_artifact(
            partial=True,
            coverage={
                "records_total": 5,
                "records_pass": 3,
                "records_fail": 0,
                "records_degraded": 0,
                "records_not_applicable": 2,
                "policy_coverage_pct": 0,
                "instrumentation_surface_pct": None,
                "instrumentation_surface_basis": "Partial — coverage not calculated",
            },
        )
        result = validate_artifact(artifact)
        assert result.valid is True

    def test_issuer_url_wrong_domain_error(self):
        artifact = valid_artifact(
            issuer={
                "signer_id": "signer_test",
                "kid": "kid_test",
                "algorithm": "Ed25519",
                "public_key_url": "https://evil.com/.well-known/primust-pubkeys/abc.pem",
                "org_region": "us",
            },
        )
        result = validate_artifact(artifact)
        assert result.valid is False
        assert any(e.code == "ISSUER_URL_INVALID" for e in result.errors)

    def test_invalid_gap_type_error(self):
        artifact = valid_artifact(
            gaps=[{"gap_id": "g1", "gap_type": "nonexistent_type", "severity": "High"}],
        )
        result = validate_artifact(artifact)
        assert result.valid is False
        assert any(e.code == "GAP_INVALID_TYPE_VALUE" for e in result.errors)

    def test_gap_missing_fields_error(self):
        artifact = valid_artifact(gaps=[{"gap_id": "g1"}])
        result = validate_artifact(artifact)
        assert result.valid is False
        assert any(e.code == "GAP_MISSING_FIELDS" for e in result.errors)

    def test_invalid_proof_level_error(self):
        artifact = valid_artifact(
            proof_level="quantum_proof",
            proof_distribution={
                "mathematical": 0,
                "verifiable_inference": 0,
                "execution": 0,
                "witnessed": 0,
                "attestation": 5,
                "weakest_link": "quantum_proof",
                "weakest_link_explanation": "invalid",
            },
        )
        result = validate_artifact(artifact)
        assert result.valid is False
        assert any(e.code == "INVALID_PROOF_LEVEL" for e in result.errors)
