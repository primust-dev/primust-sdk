"""Tests for primust-verify — mirrors TypeScript verifier.test.ts."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

# Add artifact-core-py to path for imports
sys.path.insert(
    0,
    str(
        Path(__file__).resolve().parents[3]
        / "artifact-core-py"
        / "src"
    ),
)
sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

from primust_artifact_core.signing import generate_key_pair, sign
from primust_verify.verifier import verify
from primust_verify.types import VerifyOptions, VerificationResult
from primust_verify.cli import main


def _build_artifact_body(
    kid: str,
    public_key_b64url: str,
    **overrides: Any,
) -> dict[str, Any]:
    """Build a valid artifact body (without signature)."""
    base: dict[str, Any] = {
        "vpec_id": "vpec_00000000-0000-0000-0000-000000000001",
        "schema_version": "3.0.0",
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
            "execution_zkml": 0,
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
            "instrumentation_surface_basis": "LangGraph full_workflow adapter.",
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
            "kid": kid,
            "algorithm": "Ed25519",
            "public_key_url": "https://primust.com/.well-known/primust-pubkeys/test.pem",
            "org_region": "us",
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
    base.update(overrides)
    return base


def _create_signed_artifact(
    **overrides: Any,
) -> tuple[dict[str, Any], str]:
    """Create a fully signed artifact + public key b64url."""
    signer_record, private_key = generate_key_pair(
        "signer_test", "org_test", "artifact_signer"
    )

    body = _build_artifact_body(
        signer_record.kid,
        signer_record.public_key_b64url,
        **overrides,
    )

    _, envelope = sign(body, private_key, signer_record)

    artifact: dict[str, Any] = {
        **body,
        "signature": {
            "signer_id": envelope.signer_id,
            "kid": envelope.kid,
            "algorithm": envelope.algorithm,
            "signature": envelope.signature,
            "signed_at": envelope.signed_at,
        },
    }

    return artifact, signer_record.public_key_b64url


def _write_trust_root(tmp_path: Path, public_key_b64url: str) -> str:
    """Write a trust root file and return its path."""
    pem_path = tmp_path / "test-key.pem"
    pem_path.write_text(public_key_b64url)
    return str(pem_path)


# ── Verifier MUST PASS tests ──


class TestVerify:
    def test_valid_signed_artifact(self, tmp_path: Path):
        artifact, pub_key = _create_signed_artifact()
        trust_root = _write_trust_root(tmp_path, pub_key)

        result = verify(artifact, VerifyOptions(skip_network=True, trust_root=trust_root))
        assert result.valid is True
        assert result.errors == []

    def test_tampered_artifact(self, tmp_path: Path):
        artifact, pub_key = _create_signed_artifact()
        trust_root = _write_trust_root(tmp_path, pub_key)

        artifact["org_id"] = "org_tampered"

        result = verify(artifact, VerifyOptions(skip_network=True, trust_root=trust_root))
        assert result.valid is False
        assert "integrity_check_failed" in result.errors

    def test_wrong_kid(self, tmp_path: Path):
        artifact, pub_key = _create_signed_artifact()
        trust_root = _write_trust_root(tmp_path, pub_key)

        artifact["issuer"]["kid"] = "kid_wrong"

        result = verify(artifact, VerifyOptions(skip_network=True, trust_root=trust_root))
        assert result.valid is False
        assert "kid_mismatch" in result.errors

    def test_reliance_mode_banned(self, tmp_path: Path):
        artifact, pub_key = _create_signed_artifact()
        trust_root = _write_trust_root(tmp_path, pub_key)

        artifact["reliance_mode"] = "full"

        result = verify(artifact, VerifyOptions(skip_network=True, trust_root=trust_root))
        assert result.valid is False
        assert "banned_field_reliance_mode" in result.errors

    def test_proof_level_mismatch(self, tmp_path: Path):
        artifact, pub_key = _create_signed_artifact(proof_level="mathematical")
        trust_root = _write_trust_root(tmp_path, pub_key)

        result = verify(artifact, VerifyOptions(skip_network=True, trust_root=trust_root))
        assert result.valid is False
        assert any("PROOF_LEVEL_MISMATCH" in e for e in result.errors)

    def test_test_mode_production_rejected(self, tmp_path: Path):
        artifact, pub_key = _create_signed_artifact(test_mode=True)
        trust_root = _write_trust_root(tmp_path, pub_key)

        result = verify(
            artifact,
            VerifyOptions(skip_network=True, trust_root=trust_root, production=True),
        )
        assert result.valid is False
        assert "test_mode_rejected_in_production" in result.errors

    def test_skip_network_no_http(self, tmp_path: Path):
        artifact, pub_key = _create_signed_artifact()
        trust_root = _write_trust_root(tmp_path, pub_key)

        with patch("primust_verify.key_cache.urlopen") as mock_urlopen:
            result = verify(
                artifact, VerifyOptions(skip_network=True, trust_root=trust_root)
            )
            assert result.valid is True
            mock_urlopen.assert_not_called()

    def test_all_5_proof_levels(self, tmp_path: Path):
        levels = [
            "mathematical",
            "execution_zkml",
            "execution",
            "witnessed",
            "attestation",
        ]
        for level in levels:
            artifact, pub_key = _create_signed_artifact(
                proof_level=level,
                proof_distribution={
                    "mathematical": 0,
                    "execution_zkml": 0,
                    "execution": 0,
                    "witnessed": 0,
                    "attestation": 0,
                    level: 5,
                    "weakest_link": level,
                    "weakest_link_explanation": f"All at {level}",
                },
            )
            trust_root = _write_trust_root(tmp_path, pub_key)

            result = verify(
                artifact, VerifyOptions(skip_network=True, trust_root=trust_root)
            )
            assert result.proof_level == level, f"proof_level should be {level}"

    def test_all_16_gap_types(self, tmp_path: Path):
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
        gaps = [
            {"gap_id": f"gap_{i}", "gap_type": gt, "severity": "Medium"}
            for i, gt in enumerate(gap_types)
        ]

        artifact, pub_key = _create_signed_artifact(gaps=gaps)
        trust_root = _write_trust_root(tmp_path, pub_key)

        result = verify(artifact, VerifyOptions(skip_network=True, trust_root=trust_root))
        assert result.valid is True
        assert len(result.gaps) == 16
        for i, gt in enumerate(gap_types):
            assert result.gaps[i]["gap_type"] == gt

    def test_manifest_hashes_array_error(self, tmp_path: Path):
        artifact, pub_key = _create_signed_artifact(
            manifest_hashes=["sha256:" + "a" * 64]
        )
        trust_root = _write_trust_root(tmp_path, pub_key)

        result = verify(artifact, VerifyOptions(skip_network=True, trust_root=trust_root))
        assert result.valid is False
        assert "manifest_hashes_not_object" in result.errors

    def test_mathematical_proof_level_without_zk_verifier_fails(self, tmp_path: Path):
        """mathematical proof_level + unverifiable ZK proof → error, not silent pass."""
        artifact, pub_key = _create_signed_artifact(
            proof_level="mathematical",
            proof_distribution={
                "mathematical": 5,
                "execution_zkml": 0,
                "execution": 0,
                "witnessed": 0,
                "attestation": 0,
                "weakest_link": "mathematical",
                "weakest_link_explanation": "All at mathematical",
            },
            zk_proof={
                "proving_system": "ultrahonk",
                "proof": "dGVzdA==",
                "public_inputs": ["0x01"],
                "verification_key": "dGVzdA==",
            },
        )
        trust_root = _write_trust_root(tmp_path, pub_key)

        # Mock subprocess.run to raise FileNotFoundError (bb CLI not installed)
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = verify(artifact, VerifyOptions(skip_network=True, trust_root=trust_root))
        assert result.valid is False
        assert "mathematical_proof_not_verified" in result.errors

    def test_test_mode_non_production_warning(self, tmp_path: Path):
        artifact, pub_key = _create_signed_artifact(test_mode=True)
        trust_root = _write_trust_root(tmp_path, pub_key)

        result = verify(artifact, VerifyOptions(skip_network=True, trust_root=trust_root))
        assert result.valid is True
        assert "test_credential" in result.warnings


# ── CLI MUST PASS tests ──


class TestCLI:
    def _write_artifact_file(
        self, tmp_path: Path, artifact: dict[str, Any]
    ) -> str:
        file_path = tmp_path / "artifact.json"
        file_path.write_text(json.dumps(artifact, indent=2))
        return str(file_path)

    def test_valid_artifact_exit_0(self, tmp_path: Path):
        artifact, pub_key = _create_signed_artifact()
        trust_root = _write_trust_root(tmp_path, pub_key)
        file_path = self._write_artifact_file(tmp_path, artifact)

        code = main([file_path, "--skip-network", "--trust-root", trust_root])
        assert code == 0

    def test_tampered_artifact_exit_1(self, tmp_path: Path):
        artifact, pub_key = _create_signed_artifact()
        trust_root = _write_trust_root(tmp_path, pub_key)
        artifact["org_id"] = "tampered"
        file_path = self._write_artifact_file(tmp_path, artifact)

        code = main([file_path, "--skip-network", "--trust-root", trust_root])
        assert code == 1

    def test_file_not_found_exit_2(self):
        code = main(["/nonexistent/file.json", "--skip-network"])
        assert code == 2

    def test_production_test_mode_exit_1(self, tmp_path: Path):
        artifact, pub_key = _create_signed_artifact(test_mode=True)
        trust_root = _write_trust_root(tmp_path, pub_key)
        file_path = self._write_artifact_file(tmp_path, artifact)

        code = main(
            [file_path, "--production", "--skip-network", "--trust-root", trust_root]
        )
        assert code == 1

    def test_json_output(self, tmp_path: Path, capsys):
        artifact, pub_key = _create_signed_artifact()
        trust_root = _write_trust_root(tmp_path, pub_key)
        file_path = self._write_artifact_file(tmp_path, artifact)

        code = main(
            [file_path, "--json", "--skip-network", "--trust-root", trust_root]
        )
        assert code == 0

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["valid"] is True
        assert output["vpec_id"] == "vpec_00000000-0000-0000-0000-000000000001"
        assert output["errors"] == []

    def test_all_5_proof_levels_display(self, tmp_path: Path, capsys):
        levels = [
            "mathematical",
            "execution_zkml",
            "execution",
            "witnessed",
            "attestation",
        ]
        expected = [
            "mathematical",
            "execution+zkml",
            "execution",
            "witnessed",
            "attestation",
        ]

        for i, level in enumerate(levels):
            artifact, pub_key = _create_signed_artifact(
                proof_level=level,
                proof_distribution={
                    "mathematical": 0,
                    "execution_zkml": 0,
                    "execution": 0,
                    "witnessed": 0,
                    "attestation": 0,
                    level: 5,
                    "weakest_link": level,
                    "weakest_link_explanation": f"All at {level}",
                },
            )
            trust_root = _write_trust_root(tmp_path, pub_key)
            file_path = self._write_artifact_file(tmp_path, artifact)

            main([file_path, "--skip-network", "--trust-root", trust_root])

            captured = capsys.readouterr()
            assert expected[i] in captured.out, (
                f"Expected '{expected[i]}' in output for proof level '{level}'"
            )

    def test_skip_network_no_http(self, tmp_path: Path):
        artifact, pub_key = _create_signed_artifact()
        trust_root = _write_trust_root(tmp_path, pub_key)
        file_path = self._write_artifact_file(tmp_path, artifact)

        with patch("primust_verify.key_cache.urlopen") as mock_urlopen:
            code = main(
                [file_path, "--skip-network", "--trust-root", trust_root]
            )
            assert code == 0
            mock_urlopen.assert_not_called()

    def test_execution_zkml_renders_as_execution_plus_zkml(
        self, tmp_path: Path, capsys
    ):
        artifact, pub_key = _create_signed_artifact(
            proof_level="execution_zkml",
            proof_distribution={
                "mathematical": 0,
                "execution_zkml": 5,
                "execution": 0,
                "witnessed": 0,
                "attestation": 0,
                "weakest_link": "execution_zkml",
                "weakest_link_explanation": "All at execution_zkml",
            },
        )
        trust_root = _write_trust_root(tmp_path, pub_key)
        file_path = self._write_artifact_file(tmp_path, artifact)

        main([file_path, "--skip-network", "--trust-root", trust_root])

        captured = capsys.readouterr()
        assert "execution+zkml" in captured.out
        assert "execution_zkml" not in captured.out
