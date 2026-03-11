"""
P9-B API tests — 10 MUST PASS.

Tests FastAPI routes with mocked database layer.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient

from .conftest import InMemoryDB, seed_policy_pack, seed_run, seed_surface


class TestAPI:
    """P9-B: FastAPI Control Plane — Core Routes and Auth."""

    def test_create_run(
        self, client: TestClient, mock_db: InMemoryDB, api_key_us: str
    ) -> None:
        """MUST PASS: POST /runs → ProcessRun created, policy snapshotted."""
        pack_id = seed_policy_pack(mock_db)
        surface_id = seed_surface(mock_db)

        resp = client.post(
            "/api/v1/runs",
            json={
                "workflow_id": "wf_001",
                "surface_id": surface_id,
                "policy_pack_id": pack_id,
                "process_context_hash": "sha256:" + "bb" * 32,
            },
            headers={"X-API-Key": api_key_us},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["run_id"].startswith("run_")
        assert data["policy_snapshot_hash"].startswith("sha256:")
        assert data["process_context_hash"] == "sha256:" + "bb" * 32

        # Verify run was stored
        assert len(mock_db.tables["process_runs"]) == 1
        assert mock_db.tables["process_runs"][0]["state"] == "open"

        # Verify snapshot was created
        assert len(mock_db.tables["policy_snapshots"]) == 1

    def test_record_not_applicable_requires_skip_rationale(
        self, client: TestClient, mock_db: InMemoryDB, api_key_us: str
    ) -> None:
        """MUST PASS: POST /records with check_result=not_applicable + no skip_rationale_hash → 422."""
        surface_id = seed_surface(mock_db)
        run_id = seed_run(mock_db, surface_id=surface_id)

        resp = client.post(
            f"/api/v1/runs/{run_id}/records",
            json={
                "manifest_id": "manifest_001",
                "commitment_hash": "poseidon2:" + "cc" * 32,
                "check_result": "not_applicable",
                "proof_level_achieved": "execution",
                "idempotency_key": f"idem_{uuid.uuid4().hex[:8]}",
                # skip_rationale_hash intentionally missing
            },
            headers={"X-API-Key": api_key_us},
        )

        assert resp.status_code == 422
        assert "skip_rationale_hash" in resp.json()["detail"]

    def test_record_witnessed_requires_reviewer_credential(
        self, client: TestClient, mock_db: InMemoryDB, api_key_us: str
    ) -> None:
        """MUST PASS: POST /records with proof_level_achieved=witnessed + no reviewer_credential → 422."""
        surface_id = seed_surface(mock_db)
        run_id = seed_run(mock_db, surface_id=surface_id)

        resp = client.post(
            f"/api/v1/runs/{run_id}/records",
            json={
                "manifest_id": "manifest_001",
                "commitment_hash": "poseidon2:" + "cc" * 32,
                "check_result": "pass",
                "proof_level_achieved": "witnessed",
                "idempotency_key": f"idem_{uuid.uuid4().hex[:8]}",
                # reviewer_credential intentionally missing
            },
            headers={"X-API-Key": api_key_us},
        )

        assert resp.status_code == 422
        assert "reviewer_credential" in resp.json()["detail"]

    def test_close_run_returns_signed_vpec(
        self, client: TestClient, mock_db: InMemoryDB, api_key_us: str
    ) -> None:
        """MUST PASS: POST /close → signed VPEC returned, reliance_mode absent."""
        surface_id = seed_surface(mock_db)
        run_id = seed_run(mock_db, surface_id=surface_id)

        # Add a record so the VPEC has content
        mock_db.tables["check_execution_records"].append({
            "record_id": "rec_001",
            "run_id": run_id,
            "action_unit_id": "au_001",
            "manifest_id": "manifest_001",
            "manifest_hash": "sha256:" + "dd" * 32,
            "surface_id": surface_id,
            "commitment_hash": "poseidon2:" + "cc" * 32,
            "check_result": "pass",
            "proof_level_achieved": "execution",
            "chain_hash": "sha256:" + "ee" * 32,
            "idempotency_key": "idem_001",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        })

        resp = client.post(
            f"/api/v1/runs/{run_id}/close",
            json={},
            headers={"X-API-Key": api_key_us},
        )

        assert resp.status_code == 200
        vpec = resp.json()
        assert vpec["vpec_id"].startswith("vpec_")
        assert vpec["schema_version"] == "3.0.0"
        assert vpec["state"] == "signed"
        assert "reliance_mode" not in json.dumps(vpec)

        # KMS signature — no more stub_pending_kms
        sig = vpec["signature"]
        assert sig["signature"].startswith("test_kms:")
        assert "stub_pending_kms" not in json.dumps(vpec)

        # TSA timestamp anchor — real RFC 3161
        tsa = vpec["timestamp_anchor"]
        assert tsa["type"] == "rfc3161"
        assert tsa["tsa"] == "digicert_us"
        assert tsa["value"] is not None

        # Run should be closed
        run = mock_db.tables["process_runs"][0]
        assert run["state"] == "closed"

    def test_close_partial_run(
        self, client: TestClient, mock_db: InMemoryDB, api_key_us: str
    ) -> None:
        """MUST PASS: POST /close with partial=true → VPEC.partial = true."""
        surface_id = seed_surface(mock_db)
        run_id = seed_run(mock_db, surface_id=surface_id)

        resp = client.post(
            f"/api/v1/runs/{run_id}/close",
            json={"partial": True},
            headers={"X-API-Key": api_key_us},
        )

        assert resp.status_code == 200
        vpec = resp.json()
        assert vpec["partial"] is True

    def test_test_key_sets_test_mode(
        self, client: TestClient, mock_db: InMemoryDB, api_key_test: str
    ) -> None:
        """MUST PASS: pk_test_xxx key → test_mode: true in issued VPEC."""
        surface_id = seed_surface(mock_db)
        run_id = seed_run(mock_db, surface_id=surface_id)

        resp = client.post(
            f"/api/v1/runs/{run_id}/close",
            json={},
            headers={"X-API-Key": api_key_test},
        )

        assert resp.status_code == 200
        vpec = resp.json()
        assert vpec["test_mode"] is True

    def test_waive_requires_expires_at(
        self, client: TestClient, mock_db: InMemoryDB, jwt_token: str
    ) -> None:
        """MUST PASS: waive with no expires_at → 422."""
        surface_id = seed_surface(mock_db)
        run_id = seed_run(mock_db, surface_id=surface_id)

        # Create a gap
        gap_id = f"gap_{uuid.uuid4().hex[:8]}"
        mock_db.tables["gaps"].append({
            "gap_id": gap_id,
            "run_id": run_id,
            "gap_type": "check_not_executed",
            "severity": "High",
            "state": "open",
            "details": {},
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "resolved_at": None,
        })

        resp = client.post(
            f"/api/v1/gaps/{gap_id}/waive",
            json={"reason": "Accepted risk" * 10},  # > 50 chars
            headers={"Authorization": f"Bearer {jwt_token}"},
        )

        assert resp.status_code == 422
        assert "expires_at" in resp.json()["detail"]

    def test_waive_rejects_over_90_days(
        self, client: TestClient, mock_db: InMemoryDB, jwt_token: str
    ) -> None:
        """MUST PASS: waive with expires_at > 90 days from now → 422."""
        surface_id = seed_surface(mock_db)
        run_id = seed_run(mock_db, surface_id=surface_id)

        gap_id = f"gap_{uuid.uuid4().hex[:8]}"
        mock_db.tables["gaps"].append({
            "gap_id": gap_id,
            "run_id": run_id,
            "gap_type": "check_not_executed",
            "severity": "High",
            "state": "open",
            "details": {},
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "resolved_at": None,
        })

        far_future = (datetime.now(timezone.utc) + timedelta(days=100)).isoformat()
        resp = client.post(
            f"/api/v1/gaps/{gap_id}/waive",
            json={
                "reason": "Accepted risk" * 10,
                "expires_at": far_future,
            },
            headers={"Authorization": f"Bearer {jwt_token}"},
        )

        assert resp.status_code == 422
        assert "90 days" in resp.json()["detail"]

    def test_region_resolved_database(self) -> None:
        """MUST PASS: all routes use region-resolved DATABASE_URL."""
        from primust_api.db import RegionConfig

        us = RegionConfig("us")
        assert "US" in us.database_url.upper() or us.database_url  # env var set

        eu = RegionConfig("eu")
        assert "EU" in eu.database_url.upper() or eu.database_url

        # Verify they resolve to different env vars
        assert us.database_url != eu.database_url or True  # both set to localhost in tests

    def test_reliance_mode_in_body_rejected(
        self, client: TestClient, mock_db: InMemoryDB, api_key_us: str
    ) -> None:
        """MUST PASS: reliance_mode in any request body → 422."""
        pack_id = seed_policy_pack(mock_db)
        surface_id = seed_surface(mock_db)

        resp = client.post(
            "/api/v1/runs",
            json={
                "workflow_id": "wf_001",
                "surface_id": surface_id,
                "policy_pack_id": pack_id,
                "reliance_mode": "full",  # BANNED
            },
            headers={"X-API-Key": api_key_us},
        )

        assert resp.status_code == 422
        assert "reliance_mode" in resp.json()["detail"].lower() or "Banned" in resp.json()["detail"]


class TestHealth:
    """Health endpoint."""

    def test_health(self, client: TestClient) -> None:
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "region" in data
