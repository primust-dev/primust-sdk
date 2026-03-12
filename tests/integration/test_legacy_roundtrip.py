"""
Integration tests: Legacy Pipeline API → real API server → real Postgres.

This is the SDK path that works today. The legacy Pipeline.record()
sends exactly the fields CreateRecordRequest expects.
"""

from __future__ import annotations

import hashlib
import hmac
import uuid

import httpx
import pytest

from conftest import API_KEY_SECRET, API_URL, _make_api_key


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


class TestHealth:
    def test_health_endpoint(self, api_server):
        resp = httpx.get(f"{API_URL}/api/v1/health", timeout=5.0)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("ok", "degraded")
        assert data["db"] == "ok"
        assert data["kms"] == {"us": "dev_stub", "eu": "dev_stub"}


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


class TestAuth:
    def test_valid_api_key_accepted(self, http_client):
        resp = http_client.post(
            "/api/v1/runs",
            json={
                "workflow_id": "auth-test",
                "surface_id": "default",
                "policy_pack_id": "default",
            },
        )
        assert resp.status_code == 200

    def test_invalid_api_key_rejected(self, api_server):
        resp = httpx.post(
            f"{API_URL}/api/v1/runs",
            json={
                "workflow_id": "auth-test",
                "surface_id": "default",
                "policy_pack_id": "default",
            },
            headers={"X-API-Key": "pk_test_testorg_us_badhmacsecret00000000"},
            timeout=5.0,
        )
        assert resp.status_code == 401

    def test_missing_api_key_rejected(self, api_server):
        resp = httpx.post(
            f"{API_URL}/api/v1/runs",
            json={"workflow_id": "test", "surface_id": "default", "policy_pack_id": "default"},
            timeout=5.0,
        )
        assert resp.status_code in (401, 422)

    def test_wrong_org_api_key(self, api_server):
        """Key for different org should still HMAC-validate but run against that org's data."""
        key = _make_api_key("test", org_id="otherorg")
        resp = httpx.post(
            f"{API_URL}/api/v1/runs",
            json={
                "workflow_id": "test",
                "surface_id": "default",
                "policy_pack_id": "default",
            },
            headers={"X-API-Key": key},
            timeout=5.0,
        )
        # policy_pack_id="default" belongs to testorg, not otherorg → 404
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Legacy Pipeline round-trip
# ---------------------------------------------------------------------------


class TestLegacyRoundTrip:
    def test_open_check_creates_run(self, legacy_pipeline):
        """pipeline._ensure_run() should succeed and create a run."""
        run_id = legacy_pipeline._ensure_run("default")
        assert run_id.startswith("run_")

    def test_record_single_check(self, legacy_pipeline):
        """Record a single check and get back record_id + chain_hash."""
        session = legacy_pipeline.open_check("test_check", "manifest_001")
        result = legacy_pipeline.record(session, input="test input data", check_result="pass")
        assert result.record_id.startswith("rec_")
        assert result.chain_hash.startswith("sha256:")
        assert result.commitment_hash  # poseidon2 or sha256 hash
        assert result.commitment_algorithm in ("poseidon2", "sha256")

    def test_record_returns_proof_level(self, legacy_pipeline):
        """Server doesn't return proof_level in record response — SDK uses its estimate."""
        session = legacy_pipeline.open_check("test_check", "manifest_001")
        result = legacy_pipeline.record(session, input="data", check_result="pass")
        assert result.proof_level in ("execution", "attestation", "witnessed", "mathematical")

    def test_close_returns_vpec(self, legacy_pipeline):
        """Close run and get signed VPEC dict."""
        session = legacy_pipeline.open_check("close_test", "manifest_001")
        legacy_pipeline.record(session, input="close test data", check_result="pass")
        vpec = legacy_pipeline.close()

        assert "vpec_id" in vpec
        assert vpec["vpec_id"].startswith("vpec_")
        assert vpec["schema_version"] == "4.0.0"
        assert vpec["org_id"] == "testorg"
        assert vpec["test_mode"] is True
        assert vpec["proof_level"] in (
            "mathematical", "verifiable_inference", "execution", "witnessed", "attestation"
        )

    def test_vpec_has_dev_signature(self, legacy_pipeline):
        """In dev mode, VPEC should have LOCAL_DEV_SHA256 signature."""
        session = legacy_pipeline.open_check("sig_test", "manifest_001")
        legacy_pipeline.record(session, input="sig test", check_result="pass")
        vpec = legacy_pipeline.close()

        sig = vpec.get("signature", {})
        assert sig["algorithm"] == "LOCAL_DEV_SHA256"
        assert sig["signature"].startswith("local_dev:")

    def test_vpec_has_no_tsa(self, legacy_pipeline):
        """In dev mode with no TSA URL, timestamp_anchor should be stub."""
        session = legacy_pipeline.open_check("tsa_test", "manifest_001")
        legacy_pipeline.record(session, input="tsa test", check_result="pass")
        vpec = legacy_pipeline.close()

        ts = vpec.get("timestamp_anchor", {})
        assert ts["type"] == "none"
        assert ts["value"] is None

    def test_vpec_coverage_stats(self, legacy_pipeline):
        """VPEC coverage reflects the records submitted."""
        s1 = legacy_pipeline.open_check("cov_check_1", "manifest_001")
        legacy_pipeline.record(s1, input="cov data 1", check_result="pass")
        s2 = legacy_pipeline.open_check("cov_check_2", "manifest_002")
        legacy_pipeline.record(s2, input="cov data 2", check_result="pass")
        s3 = legacy_pipeline.open_check("cov_check_3", "manifest_003")
        legacy_pipeline.record(s3, input="cov data 3", check_result="fail")

        vpec = legacy_pipeline.close()

        cov = vpec["coverage"]
        assert cov["records_total"] == 3
        assert cov["records_pass"] == 2
        assert cov["records_fail"] == 1

    def test_proof_distribution(self, legacy_pipeline):
        """VPEC proof_distribution counts records by proof level."""
        s = legacy_pipeline.open_check("proof_check", "manifest_001")
        legacy_pipeline.record(s, input="proof data", check_result="pass")
        vpec = legacy_pipeline.close()

        dist = vpec["proof_distribution"]
        assert "weakest_link" in dist
        total = sum(
            dist.get(level, 0)
            for level in ("mathematical", "verifiable_inference", "execution", "witnessed", "attestation")
        )
        assert total == 1


class TestLegacyMultiRecord:
    def test_chain_hash_links_records(self, legacy_pipeline):
        """Multiple records produce linked chain hashes."""
        s1 = legacy_pipeline.open_check("chain_1", "manifest_001")
        r1 = legacy_pipeline.record(s1, input="chain data 1", check_result="pass")
        s2 = legacy_pipeline.open_check("chain_2", "manifest_001")
        r2 = legacy_pipeline.record(s2, input="chain data 2", check_result="pass")

        # chain_hash should differ between records (rolling hash)
        assert r1.chain_hash != r2.chain_hash
        assert r1.chain_hash.startswith("sha256:")
        assert r2.chain_hash.startswith("sha256:")


class TestLegacyEdgeCases:
    def test_close_partial_with_no_records(self, legacy_pipeline):
        """partial=True allows closing with zero records."""
        # Force run creation
        legacy_pipeline._ensure_run("default")
        vpec = legacy_pipeline.close(partial=True)
        assert vpec["partial"] is True
        assert vpec["coverage"]["records_total"] == 0

    def test_record_after_close_rejected(self, http_client):
        """Recording on a closed run returns 409."""
        # Create and close a run
        resp = http_client.post(
            "/api/v1/runs",
            json={
                "workflow_id": "close-test",
                "surface_id": "default",
                "policy_pack_id": "default",
            },
        )
        run_id = resp.json()["run_id"]

        # Record one check
        http_client.post(
            f"/api/v1/runs/{run_id}/records",
            json={
                "manifest_id": "manifest_001",
                "commitment_hash": "sha256:abc123",
                "commitment_algorithm": "sha256",
                "commitment_type": "input_only",
                "check_result": "pass",
                "proof_level_achieved": "execution",
                "idempotency_key": f"idem_{uuid.uuid4().hex[:16]}",
            },
        )

        # Close the run
        http_client.post(f"/api/v1/runs/{run_id}/close", json={"partial": False})

        # Attempt to record on closed run
        resp = http_client.post(
            f"/api/v1/runs/{run_id}/records",
            json={
                "manifest_id": "manifest_001",
                "commitment_hash": "sha256:def456",
                "commitment_algorithm": "sha256",
                "commitment_type": "input_only",
                "check_result": "pass",
                "proof_level_achieved": "execution",
                "idempotency_key": f"idem_{uuid.uuid4().hex[:16]}",
            },
        )
        assert resp.status_code == 409

    def test_skip_rationale_required(self, http_client):
        """check_result=not_applicable without skip_rationale_hash → 422."""
        resp = http_client.post(
            "/api/v1/runs",
            json={
                "workflow_id": "skip-test",
                "surface_id": "default",
                "policy_pack_id": "default",
            },
        )
        run_id = resp.json()["run_id"]

        resp = http_client.post(
            f"/api/v1/runs/{run_id}/records",
            json={
                "manifest_id": "manifest_001",
                "commitment_hash": "sha256:abc",
                "commitment_algorithm": "sha256",
                "commitment_type": "input_only",
                "check_result": "not_applicable",
                "proof_level_achieved": "execution",
                "idempotency_key": f"idem_{uuid.uuid4().hex[:16]}",
                # skip_rationale_hash intentionally missing
            },
        )
        assert resp.status_code == 422

    def test_idempotency_key_uniqueness(self, http_client):
        """Duplicate idempotency_key on same run → error."""
        resp = http_client.post(
            "/api/v1/runs",
            json={
                "workflow_id": "idem-test",
                "surface_id": "default",
                "policy_pack_id": "default",
            },
        )
        run_id = resp.json()["run_id"]

        idem_key = f"idem_duplicate_{uuid.uuid4().hex[:8]}"
        body = {
            "manifest_id": "manifest_001",
            "commitment_hash": "sha256:idem_test",
            "commitment_algorithm": "sha256",
            "commitment_type": "input_only",
            "check_result": "pass",
            "proof_level_achieved": "execution",
            "idempotency_key": idem_key,
        }

        # First record succeeds
        resp1 = http_client.post(f"/api/v1/runs/{run_id}/records", json=body)
        assert resp1.status_code == 200

        # Duplicate idempotency_key should fail
        resp2 = http_client.post(f"/api/v1/runs/{run_id}/records", json=body)
        assert resp2.status_code in (409, 500)  # unique constraint violation


class TestWitnessedRecord:
    def test_witnessed_record_with_reviewer_credential(self, legacy_pipeline):
        """ReviewSession + reviewer_signature → witnessed proof level."""
        review = legacy_pipeline.open_review(
            check="human_review",
            manifest_id="manifest_review",
            reviewer_key_id="reviewer_001",
            min_duration_seconds=0,  # no wait for integration test
        )
        # The review requires a reviewer_signature
        result = legacy_pipeline.record(
            review,
            input="reviewed content",
            check_result="pass",
            reviewer_signature="sig_base64_test",
            display_content="display text",
            rationale="approved after review",
        )
        assert result.proof_level == "witnessed"

    def test_witnessed_vpec_proof_level(self, legacy_pipeline):
        """VPEC with witnessed record shows witnessed as weakest link."""
        review = legacy_pipeline.open_review(
            "witnessed_vpec_test", "manifest_review",
            reviewer_key_id="rev_001", min_duration_seconds=0,
        )
        legacy_pipeline.record(
            review, input="data", check_result="pass",
            reviewer_signature="sig", display_content="d", rationale="r",
        )
        vpec = legacy_pipeline.close()
        assert vpec["proof_level"] == "witnessed"
        assert vpec["proof_distribution"]["witnessed"] >= 1
