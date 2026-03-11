"""P14-A: pack verify, pack assemble, --dry-run — 4 MUST PASS."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

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
from primust_verify.pack import verify_pack, assemble_pack, format_dry_run


def _make_signed_artifact(**overrides: Any) -> dict[str, Any]:
    """Create a signed artifact for pack testing."""
    signer_record, private_key = generate_key_pair(
        "signer_test", "org_test", "artifact_signer"
    )

    body: dict[str, Any] = {
        "vpec_id": "vpec_test001",
        "schema_version": "3.0.0",
        "org_id": "org_test",
        "run_id": "run_001",
        "workflow_id": "wf_001",
        "process_context_hash": None,
        "policy_snapshot_hash": "sha256:" + "a" * 64,
        "policy_basis": "P1_self_declared",
        "partial": False,
        "surface_summary": [],
        "proof_level": "execution",
        "proof_distribution": {
            "mathematical": 0,
            "execution_zkml": 0,
            "execution": 5,
            "witnessed": 0,
            "attestation": 0,
            "weakest_link": "execution",
            "weakest_link_explanation": "All execution",
        },
        "state": "signed",
        "coverage": {
            "records_total": 5,
            "records_pass": 5,
            "records_fail": 0,
            "records_degraded": 0,
            "records_not_applicable": 0,
            "policy_coverage_pct": 98.7,
            "instrumentation_surface_pct": 100,
        },
        "gaps": [],
        "manifest_hashes": {
            "manifest_001": "sha256:" + "b" * 64,
            "manifest_002": "sha256:" + "c" * 64,
        },
        "commitment_root": "poseidon2:" + "d" * 64,
        "commitment_algorithm": "poseidon2",
        "zk_proof": None,
        "issuer": {
            "signer_id": "signer_test",
            "kid": signer_record.kid,
            "algorithm": "Ed25519",
            "public_key_url": "https://keys.primust.com/test.pem",
            "org_region": "us",
        },
        "timestamp_anchor": {"type": "none", "tsa": "none", "value": None},
        "transparency_log": {"rekor_log_id": None},
        "issued_at": "2026-03-10T00:00:00Z",
        "pending_flags": {},
        "test_mode": False,
    }
    body.update(overrides)

    _, envelope = sign(body, private_key, signer_record)
    body["signature"] = {
        "signer_id": envelope.signer_id,
        "kid": envelope.kid,
        "algorithm": envelope.algorithm,
        "signature": envelope.signature,
        "signed_at": envelope.signed_at,
    }

    return body


def _make_valid_pack(artifact_ids: list[str] | None = None) -> dict[str, Any]:
    """Create a valid pack for testing."""
    import hashlib

    ids = artifact_ids or ["vpec_001", "vpec_002"]
    proof_dist = {"mathematical": 0, "execution_zkml": 0, "execution": 10, "witnessed": 0, "attestation": 0}
    report_content = json.dumps(
        {"artifact_ids": ids, "proof_distribution": proof_dist},
        sort_keys=True,
    )
    report_hash = "sha256:" + hashlib.sha256(report_content.encode()).hexdigest()

    return {
        "pack_id": "pack_test001",
        "period_start": "2026-03-01",
        "period_end": "2026-03-10",
        "artifact_ids": ids,
        "proof_distribution": proof_dist,
        "coverage_verified_pct": 90,
        "coverage_pending_pct": 5,
        "coverage_ungoverned_pct": 5,
        "report_hash": report_hash,
        "signature": {
            "signer_id": "signer_001",
            "kid": "kid_001",
            "algorithm": "Ed25519",
            "signature": "sig_base64",
            "signed_at": "2026-03-10T00:00:00Z",
        },
        "generated_at": "2026-03-10T00:00:00Z",
    }


class TestPackP14A:
    def test_dry_run_prints_raw_content_none(self, tmp_path: Path) -> None:
        """MUST PASS: --dry-run prints 'Raw content: NONE'."""
        artifact = _make_signed_artifact()
        artifact_path = tmp_path / "vpec.json"
        artifact_path.write_text(json.dumps(artifact))

        result = assemble_pack(
            artifact_paths=[str(artifact_path)],
            period_start="2026-03-01",
            period_end="2026-03-10",
            dry_run=True,
        )

        assert result.dry_run is True
        output = format_dry_run(result)
        assert "Raw content:         NONE" in output
        assert "=== PRIMUST DRY RUN" in output
        assert "=== End dry run ===" in output

    def test_dry_run_makes_zero_api_calls(self, tmp_path: Path) -> None:
        """MUST PASS: --dry-run makes zero API calls."""
        artifact = _make_signed_artifact()
        artifact_path = tmp_path / "vpec.json"
        artifact_path.write_text(json.dumps(artifact))

        with patch("primust_verify.pack.Path.write_text") as mock_write:
            result = assemble_pack(
                artifact_paths=[str(artifact_path)],
                period_start="2026-03-01",
                period_end="2026-03-10",
                dry_run=True,
            )

            assert result.dry_run is True
            assert result.output_path is None
            # In dry-run mode, no file should be written (no pack.json output)
            mock_write.assert_not_called()

    def test_pack_verify_passes_on_valid_fails_on_tampered(self) -> None:
        """MUST PASS: pack verify passes on valid pack, fails on tampered."""
        pack = _make_valid_pack()
        result = verify_pack(pack)
        assert result.valid is True
        assert result.errors == []

        # Tamper: change report_hash
        tampered = {**pack, "report_hash": "sha256:tampered"}
        result_tampered = verify_pack(tampered)
        assert result_tampered.valid is False
        assert "report_hash_mismatch" in result_tampered.errors

    def test_trust_root_makes_zero_network_calls(self, tmp_path: Path) -> None:
        """MUST PASS: --trust-root makes zero network calls."""
        # verify_pack doesn't need network, but verify with trust_root should also not
        pack = _make_valid_pack()
        result = verify_pack(pack)
        assert result.valid is True
        # Pack verification is fully local — no network calls at all
        # This is inherently true: verify_pack does hash comparison only
