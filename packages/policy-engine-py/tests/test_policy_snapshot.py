"""Tests for PolicySnapshotService — Python mirror of policy_snapshot.test.ts."""

from __future__ import annotations

from typing import Any

import pytest

from primust_policy_engine.manifest_validator import compute_manifest_hash
from primust_policy_engine.policy_snapshot import PolicySnapshotService
from primust_runtime_core.store.sqlite_store import SqliteStore


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


def make_policy_pack(manifest_ids: list[str]) -> dict[str, Any]:
    return {
        "policy_pack_id": "pp_001",
        "org_id": "org_test",
        "name": "Test Pack",
        "version": "1.0.0",
        "checks": [
            {
                "check_id": f"check_{i + 1}",
                "manifest_id": mid,
                "required": True,
                "evaluation_scope": "per_run",
                "action_unit_count": None,
            }
            for i, mid in enumerate(manifest_ids)
        ],
        "created_at": "2026-03-10T00:00:00Z",
        "signer_id": "signer_test",
        "kid": "kid_test",
        "signature": {
            "signer_id": "signer_test",
            "kid": "kid_test",
            "algorithm": "Ed25519",
            "signature": "sig_placeholder",
            "signed_at": "2026-03-10T00:00:00Z",
        },
    }


def register_manifest(manifests: dict[str, dict[str, Any]], manifest: dict[str, Any]) -> str:
    """Register a manifest by content hash (mirrors ManifestRegistry)."""
    manifest_id = compute_manifest_hash(manifest)
    manifests[manifest_id] = manifest
    return manifest_id


# ── Tests ──


class TestPolicySnapshotService:
    def setup_method(self) -> None:
        self.store = SqliteStore(":memory:")
        self.manifests: dict[str, dict[str, Any]] = {}
        self.policy_packs: dict[str, dict[str, Any]] = {}

    def teardown_method(self) -> None:
        self.store.close()

    def test_snapshot_unchanged_after_policy_edit(self) -> None:
        manifest = make_manifest()
        mid = register_manifest(self.manifests, manifest)
        pack = make_policy_pack([mid])
        self.policy_packs[pack["policy_pack_id"]] = pack

        service = PolicySnapshotService(
            store=self.store, manifests=self.manifests, policy_packs=self.policy_packs,
        )
        result = service.open_run(
            workflow_id="wf_001", surface_id="surf_001",
            policy_pack_id="pp_001", org_id="org_test", action_unit_count=5,
        )

        snapshot = self.store.get_policy_snapshot(result["policy_snapshot_hash"])
        assert snapshot is not None
        original_checks = snapshot["effective_checks"]

        # Mutate the policy pack
        manifest2 = make_manifest(name="new_check")
        mid2 = register_manifest(self.manifests, manifest2)
        pack["checks"].append({
            "check_id": "check_new",
            "manifest_id": mid2,
            "required": True,
            "evaluation_scope": "per_run",
            "action_unit_count": None,
        })

        # Snapshot in DB should be unchanged
        snapshot_after = self.store.get_policy_snapshot(result["policy_snapshot_hash"])
        assert snapshot_after["effective_checks"] == original_checks

    def test_same_inputs_same_hash(self) -> None:
        manifest = make_manifest()
        mid = register_manifest(self.manifests, manifest)
        pack = make_policy_pack([mid])
        self.policy_packs[pack["policy_pack_id"]] = pack

        service = PolicySnapshotService(
            store=self.store, manifests=self.manifests, policy_packs=self.policy_packs,
        )
        r1 = service.open_run(
            workflow_id="wf_001", surface_id="surf_001",
            policy_pack_id="pp_001", org_id="org_test", action_unit_count=5,
        )
        r2 = service.open_run(
            workflow_id="wf_002", surface_id="surf_001",
            policy_pack_id="pp_001", org_id="org_test", action_unit_count=5,
        )
        assert r1["policy_snapshot_hash"] == r2["policy_snapshot_hash"]
        assert r1["run_id"] != r2["run_id"]

    def test_drift_gap_on_manifest_hash_change(self) -> None:
        manifest = make_manifest()
        mid = register_manifest(self.manifests, manifest)
        pack = make_policy_pack([mid])
        self.policy_packs[pack["policy_pack_id"]] = pack

        service = PolicySnapshotService(
            store=self.store, manifests=self.manifests, policy_packs=self.policy_packs,
        )
        r1 = service.open_run(
            workflow_id="wf_drift", surface_id="surf_001",
            policy_pack_id="pp_001", org_id="org_test", action_unit_count=5,
        )

        # Append check record with a DIFFERENT manifest_hash (simulates prior state)
        old_hash = "sha256:" + "1" * 64
        self.store.append_check_record({
            "record_id": "rec_001",
            "run_id": r1["run_id"],
            "action_unit_id": "au_1",
            "manifest_id": mid,
            "manifest_hash": old_hash,
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
            "idempotency_key": "idem_001",
            "recorded_at": "2026-03-10T00:00:00Z",
        })
        self.store.close_run(r1["run_id"], "closed")

        # Open run2 — should detect drift
        r2 = service.open_run(
            workflow_id="wf_drift", surface_id="surf_001",
            policy_pack_id="pp_001", org_id="org_test", action_unit_count=5,
        )
        gaps = self.store.get_gaps(r2["run_id"])
        drift_gap = next((g for g in gaps if g["gap_type"] == "policy_config_drift"), None)
        assert drift_gap is not None
        assert drift_gap["severity"] == "Medium"

    def test_per_action_unit_denominator(self) -> None:
        manifest = make_manifest()
        mid = register_manifest(self.manifests, manifest)
        pack = make_policy_pack([mid])
        pack["checks"] = [{
            "check_id": "check_per_au",
            "manifest_id": mid,
            "required": True,
            "evaluation_scope": "per_action_unit",
            "action_unit_count": None,
        }]
        self.policy_packs[pack["policy_pack_id"]] = pack

        service = PolicySnapshotService(
            store=self.store, manifests=self.manifests, policy_packs=self.policy_packs,
        )
        result = service.open_run(
            workflow_id="wf_001", surface_id="surf_001",
            policy_pack_id="pp_001", org_id="org_test", action_unit_count=10,
        )
        snapshot = self.store.get_policy_snapshot(result["policy_snapshot_hash"])
        assert snapshot is not None
        checks = snapshot["effective_checks"]
        assert checks[0]["action_unit_count"] == 10

    def test_process_context_hash_stored(self) -> None:
        manifest = make_manifest()
        mid = register_manifest(self.manifests, manifest)
        pack = make_policy_pack([mid])
        self.policy_packs[pack["policy_pack_id"]] = pack

        context_hash = "sha256:" + "f" * 64
        service = PolicySnapshotService(
            store=self.store, manifests=self.manifests, policy_packs=self.policy_packs,
        )
        result = service.open_run(
            workflow_id="wf_001", surface_id="surf_001",
            policy_pack_id="pp_001", org_id="org_test", action_unit_count=5,
            process_context_hash=context_hash,
        )
        run = self.store.get_process_run(result["run_id"])
        assert run is not None
        assert run["process_context_hash"] == context_hash
