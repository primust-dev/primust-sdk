"""Tests for primust-runtime-core — mirrors TypeScript validate-schemas.test.ts."""

from __future__ import annotations

import sys
from pathlib import Path

# Add source paths for imports
sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)
sys.path.insert(
    0,
    str(
        Path(__file__).resolve().parents[3]
        / "artifact-core-py"
        / "src"
    ),
)

import pytest

from primust_runtime_core.types.models import (
    CheckExecutionRecord,
    EvidencePack,
    GapSummary,
    ManifestStage,
    ObservationSummaryEntry,
    ProofDistribution,
    ReviewerCredential,
    SignatureEnvelopeRef,
    TimestampAnchorRef,
    Waiver,
)
from primust_runtime_core.validate_schemas import (
    ValidationError,
    scan_banned_fields,
    validate_check_execution_record,
    validate_evidence_pack,
    validate_manifest_stage,
    validate_waiver,
)


# ── Helpers ──

_SIG = SignatureEnvelopeRef(
    signer_id="signer_test",
    kid="kid_test",
    algorithm="Ed25519",
    signature="sig_placeholder",
    signed_at="2026-03-10T00:00:00Z",
)

_TSA = TimestampAnchorRef(type="none", tsa="none", value=None)


def _make_check_record(**overrides) -> CheckExecutionRecord:
    defaults = dict(
        record_id="rec_001",
        run_id="run_001",
        action_unit_id="au_001",
        manifest_id="manifest_001",
        manifest_hash="sha256:" + "a" * 64,
        surface_id="surf_001",
        commitment_hash="poseidon2:" + "b" * 64,
        output_commitment=None,
        commitment_algorithm="poseidon2",
        commitment_type="input_commitment",
        check_result="pass",
        proof_level_achieved="execution",
        proof_pending=False,
        zkml_proof_pending=False,
        check_open_tst=None,
        check_close_tst=None,
        skip_rationale_hash=None,
        reviewer_credential=None,
        unverified_provenance=False,
        freshness_warning=False,
        chain_hash="sha256:" + "c" * 64,
        idempotency_key="idem_001",
        recorded_at="2026-03-10T00:00:00Z",
    )
    defaults.update(overrides)
    return CheckExecutionRecord(**defaults)


def _make_waiver(**overrides) -> Waiver:
    defaults = dict(
        waiver_id="waiver_001",
        gap_id="gap_001",
        org_id="org_test",
        requestor_user_id="user_req",
        approver_user_id="user_apr",
        reason="This is a sufficiently long reason that explains why "
        "this waiver is needed for the gap.",
        compensating_control=None,
        risk_treatment="accept",
        expires_at="2026-04-10T00:00:00Z",
        signature=_SIG,
        approved_at="2026-03-10T00:00:00Z",
    )
    defaults.update(overrides)
    return Waiver(**defaults)


def _make_evidence_pack(**overrides) -> EvidencePack:
    defaults = dict(
        pack_id="pack_001",
        org_id="org_test",
        period_start="2026-03-01T00:00:00Z",
        period_end="2026-03-10T00:00:00Z",
        artifact_ids=["vpec_001"],
        merkle_root="sha256:" + "d" * 64,
        proof_distribution=ProofDistribution(
            mathematical=0,
            verifiable_inference=0,
            execution=5,
            witnessed=0,
            attestation=0,
        ),
        coverage_verified_pct=80,
        coverage_pending_pct=15,
        coverage_ungoverned_pct=5,
        observation_summary=[
            ObservationSummaryEntry(
                surface_id="surf_1",
                surface_coverage_statement="All tool calls",
            ),
        ],
        gap_summary=GapSummary(
            Critical=0, High=0, Medium=1, Low=0, Informational=0
        ),
        report_hash="sha256:" + "e" * 64,
        signature=_SIG,
        timestamp_anchor=_TSA,
        generated_at="2026-03-10T00:00:00Z",
    )
    defaults.update(overrides)
    return EvidencePack(**defaults)


# ── scan_banned_fields ──


class TestScanBannedFields:
    def test_clean_object(self):
        assert scan_banned_fields({"name": "test", "org_id": "org_1"}) == []

    def test_detects_reliance_mode(self):
        errors = scan_banned_fields({"reliance_mode": "full"})
        assert len(errors) == 1
        assert errors[0].code == "banned_field_reliance_mode"

    def test_detects_nested_agent_id(self):
        errors = scan_banned_fields({"config": {"agent_id": "agent_123"}})
        assert len(errors) == 1
        assert errors[0].code == "banned_field_agent_id"
        assert "config.agent_id" in errors[0].message

    def test_detects_banned_in_arrays(self):
        errors = scan_banned_fields(
            {"items": [{"pipeline_id": "p1"}, {"ok": True}]}
        )
        assert len(errors) == 1
        assert errors[0].code == "banned_field_pipeline_id"

    def test_detects_all_8_banned_fields(self):
        obj = {
            "agent_id": "x",
            "pipeline_id": "x",
            "tool_name": "x",
            "session_id": "x",
            "trace_id": "x",
            "reliance_mode": "x",
            "PGC": "x",
            "attestation": "x",
        }
        errors = scan_banned_fields(obj)
        assert len(errors) == 8

    def test_handles_none(self):
        assert scan_banned_fields(None) == []


# ── validate_manifest_stage ──


class TestValidateManifestStage:
    def test_human_review_witnessed_passes(self):
        stage = ManifestStage(
            stage=1,
            name="Human Review",
            type="witnessed",
            proof_level="witnessed",
            redacted=False,
        )
        assert validate_manifest_stage(stage) == []

    def test_human_review_attestation_rejected(self):
        stage = ManifestStage(
            stage=1,
            name="Human Review",
            type="witnessed",
            proof_level="attestation",
            redacted=False,
        )
        errors = validate_manifest_stage(stage)
        codes = [e.code for e in errors]
        assert "witnessed_attestation_forbidden" in codes

    def test_human_review_execution_rejected(self):
        stage = ManifestStage(
            stage=1,
            name="Human Review",
            type="witnessed",
            proof_level="execution",
            redacted=False,
        )
        errors = validate_manifest_stage(stage)
        codes = [e.code for e in errors]
        assert "witnessed_must_be_witnessed" in codes

    def test_deterministic_rule_mathematical_passes(self):
        stage = ManifestStage(
            stage=1,
            name="Rule Check",
            type="deterministic_rule",
            proof_level="mathematical",
            redacted=False,
        )
        assert validate_manifest_stage(stage) == []


# ── validate_check_execution_record ──


class TestValidateCheckExecutionRecord:
    def test_valid_record_passes(self):
        assert validate_check_execution_record(_make_check_record()) == []

    def test_missing_manifest_hash(self):
        errors = validate_check_execution_record(
            _make_check_record(manifest_hash="")
        )
        codes = [e.code for e in errors]
        assert "manifest_hash_missing" in codes

    def test_witnessed_without_reviewer_credential(self):
        errors = validate_check_execution_record(
            _make_check_record(
                proof_level_achieved="witnessed",
                reviewer_credential=None,
            )
        )
        codes = [e.code for e in errors]
        assert "reviewer_credential_missing" in codes

    def test_witnessed_with_reviewer_credential_passes(self):
        cred = ReviewerCredential(
            reviewer_key_id="key_1",
            key_binding="software",
            role="reviewer",
            org_credential_ref=None,
            reviewer_signature="ed25519:sig",
            display_hash="poseidon2:" + "f" * 64,
            rationale_hash="poseidon2:" + "f" * 64,
            signed_content_hash="poseidon2:" + "f" * 64,
            open_tst="base64:token",
            close_tst="base64:token",
        )
        errors = validate_check_execution_record(
            _make_check_record(
                proof_level_achieved="witnessed",
                reviewer_credential=cred,
            )
        )
        assert errors == []

    def test_not_applicable_without_skip_rationale_hash(self):
        errors = validate_check_execution_record(
            _make_check_record(
                check_result="not_applicable",
                skip_rationale_hash=None,
            )
        )
        codes = [e.code for e in errors]
        assert "skip_rationale_hash_missing" in codes

    def test_not_applicable_with_skip_rationale_hash_passes(self):
        errors = validate_check_execution_record(
            _make_check_record(
                check_result="not_applicable",
                skip_rationale_hash="poseidon2:" + "a" * 64,
            )
        )
        assert errors == []

    def test_output_commitment_invalid_prefix(self):
        errors = validate_check_execution_record(
            _make_check_record(
                output_commitment="sha256:" + "a" * 64,
            )
        )
        codes = [e.code for e in errors]
        assert "output_commitment_invalid_prefix" in codes

    def test_close_tst_without_open_tst(self):
        errors = validate_check_execution_record(
            _make_check_record(
                check_close_tst="base64:token",
                check_open_tst=None,
            )
        )
        codes = [e.code for e in errors]
        assert "check_open_tst_missing" in codes


# ── validate_waiver ──


class TestValidateWaiver:
    def test_valid_waiver_passes(self):
        assert validate_waiver(_make_waiver()) == []

    def test_reason_too_short(self):
        errors = validate_waiver(_make_waiver(reason="Too short"))
        codes = [e.code for e in errors]
        assert "waiver_reason_too_short" in codes

    def test_exceeds_90_days(self):
        errors = validate_waiver(
            _make_waiver(
                approved_at="2026-03-10T00:00:00Z",
                expires_at="2026-07-10T00:00:00Z",
            )
        )
        codes = [e.code for e in errors]
        assert "waiver_exceeds_90_days" in codes

    def test_expires_before_approval(self):
        errors = validate_waiver(
            _make_waiver(
                approved_at="2026-03-10T00:00:00Z",
                expires_at="2026-03-09T00:00:00Z",
            )
        )
        codes = [e.code for e in errors]
        assert "waiver_expires_before_approval" in codes

    def test_exactly_90_days_passes(self):
        errors = validate_waiver(
            _make_waiver(
                approved_at="2026-03-10T00:00:00Z",
                expires_at="2026-06-08T00:00:00Z",
            )
        )
        assert errors == []


# ── validate_evidence_pack ──


class TestValidateEvidencePack:
    def test_valid_pack_passes(self):
        assert validate_evidence_pack(_make_evidence_pack()) == []

    def test_coverage_not_100(self):
        errors = validate_evidence_pack(
            _make_evidence_pack(
                coverage_verified_pct=80,
                coverage_pending_pct=15,
                coverage_ungoverned_pct=10,
            )
        )
        codes = [e.code for e in errors]
        assert "coverage_sum_not_100" in codes

    def test_100_0_0_split(self):
        assert (
            validate_evidence_pack(
                _make_evidence_pack(
                    coverage_verified_pct=100,
                    coverage_pending_pct=0,
                    coverage_ungoverned_pct=0,
                )
            )
            == []
        )

    def test_0_0_100_split(self):
        assert (
            validate_evidence_pack(
                _make_evidence_pack(
                    coverage_verified_pct=0,
                    coverage_pending_pct=0,
                    coverage_ungoverned_pct=100,
                )
            )
            == []
        )
