"""Primust Policy Engine — Policy Snapshot Binding (Python).

PolicySnapshotService.open_run() orchestrates:
1. Resolve PolicyPack → manifest_ids → manifests
2. Build effective_checks with manifest_hash per check
3. Compute snapshot_hash = SHA256(canonical(sorted effective_checks))
4. Write immutable PolicySnapshot to store
5. Open ProcessRun with drift detection
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

from primust_artifact_core.canonical import canonical
from primust_runtime_core.store.sqlite_store import SqliteStore

from primust_policy_engine.manifest_validator import compute_manifest_hash


class PolicySnapshotService:
    """Policy snapshot binding service.

    Accepts:
      - store: SqliteStore
      - manifests: dict mapping manifest_id → manifest dict
      - policy_packs: dict mapping policy_pack_id → policy pack dict
    """

    def __init__(
        self,
        *,
        store: SqliteStore,
        manifests: dict[str, dict[str, Any]],
        policy_packs: dict[str, dict[str, Any]],
    ) -> None:
        self._store = store
        self._manifests = manifests
        self._policy_packs = policy_packs

    def open_run(
        self,
        *,
        workflow_id: str,
        surface_id: str,
        policy_pack_id: str,
        org_id: str,
        process_context_hash: str | None = None,
        action_unit_count: int,
        ttl_seconds: int = 3600,
        policy_basis: str = "P1_self_declared",
    ) -> dict[str, str]:
        """Open a new process run with policy snapshot binding.

        Returns { run_id, policy_snapshot_hash }.
        """
        # 1. Resolve policy pack
        pack = self._policy_packs.get(policy_pack_id)
        if pack is None:
            raise ValueError(f"PolicyPack not found: {policy_pack_id}")

        # 2-3. Build effective checks
        effective_checks: list[dict[str, Any]] = []
        manifest_hashes: dict[str, str] = {}

        for check in pack["checks"]:
            manifest_id = check["manifest_id"]
            manifest = self._manifests.get(manifest_id)
            if manifest is None:
                raise ValueError(f"Manifest not found: {manifest_id}")

            manifest_hash = compute_manifest_hash(manifest)
            manifest_hashes[manifest_id] = manifest_hash

            # Coverage denominator: override for per_action_unit
            au_count = check.get("action_unit_count")
            if check.get("evaluation_scope") == "per_action_unit":
                au_count = action_unit_count

            effective_checks.append({
                "check_id": check["check_id"],
                "manifest_id": manifest_id,
                "manifest_hash": manifest_hash,
                "required": check["required"],
                "evaluation_scope": check["evaluation_scope"],
                "action_unit_count": au_count,
            })

        # 4. Compute snapshot hash (deterministic: sort by check_id)
        sorted_checks = sorted(effective_checks, key=lambda c: c["check_id"])
        snapshot_content = canonical(sorted_checks)
        hash_hex = hashlib.sha256(snapshot_content.encode("utf-8")).hexdigest()
        snapshot_hash = f"sha256:{hash_hex}"

        # 5. Write immutable PolicySnapshot
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        self._store.write_policy_snapshot(
            snapshot_id=snapshot_hash,
            policy_pack_id=pack["policy_pack_id"],
            policy_pack_version=pack["version"],
            effective_checks=effective_checks,
            snapshotted_at=now,
            policy_basis=policy_basis,
        )

        # 6. Open process run with drift detection
        run_id = f"run_{uuid.uuid4()}"

        self._store.open_run(
            run_id=run_id,
            workflow_id=workflow_id,
            org_id=org_id,
            surface_id=surface_id,
            policy_snapshot_hash=snapshot_hash,
            process_context_hash=process_context_hash,
            action_unit_count=action_unit_count,
            ttl_seconds=ttl_seconds,
            manifest_hashes=manifest_hashes,
        )

        return {
            "run_id": run_id,
            "policy_snapshot_hash": snapshot_hash,
        }
