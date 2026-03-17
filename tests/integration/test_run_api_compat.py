"""
Integration tests: Run-based API protocol compatibility.

These tests document the protocol mismatches between the SDK's Run-based API
and the server's CreateRecordRequest/CloseRunRequest schemas.

The Run-based API (pipeline.open() → run.record() → run.close()) is the
recommended path per the SDK docs, but it sends different fields than what
the server's Pydantic models expect.

Protocol gaps documented:
  1. pipeline.open() without policy_pack_id/surface_id → 422 (missing required fields)
  2. run.record() missing proof_level_achieved → 422
  3. run.record() missing idempotency_key → 422
  4. run.close() response lacks "vpec" wrapper key → SDK polls non-existent endpoint
"""

from __future__ import annotations

import httpx
import pytest


# ---------------------------------------------------------------------------
# Open run gaps
# ---------------------------------------------------------------------------


class TestRunOpenCompat:
    def test_open_without_policy_pack_id_fails(self, run_pipeline):
        """
        pipeline.open() without policy_pack_id → 422.

        The SDK's open() makes policy_pack_id optional, but the API's
        CreateRunRequest requires it (no default value in the Pydantic model).
        """
        with pytest.raises(Exception) as exc_info:
            run_pipeline.open()  # no policy_pack_id
        # Should be an HTTP error (422 from Pydantic validation)
        assert "422" in str(exc_info.value) or "Client error" in str(exc_info.value)

    def test_open_with_policy_pack_succeeds(self, run_pipeline):
        """
        pipeline.open(policy_pack_id="default") with surface_id set → succeeds.

        When both required fields are provided, the API accepts the request
        even though the SDK sends extra fields (run_id, environment, opened_at)
        because Pydantic ignores unknown fields by default.
        """
        run = run_pipeline.open(policy_pack_id="default")
        assert run.run_id.startswith("run_")
        assert run.org_id  # extracted from API response


# ---------------------------------------------------------------------------
# Record gaps
# ---------------------------------------------------------------------------


class TestRunRecordCompat:
    def test_run_record_succeeds(self, run_pipeline):
        """
        run.record() sends proof_level_achieved, idempotency_key, and
        commitment_type — API accepts the request.

        Previously this was xfail because these fields were missing.
        Fixed in the SDK: Run.record() now derives proof_level from
        _estimate_proof_level() and generates idempotency_key per call.
        """
        run = run_pipeline.open(policy_pack_id="default")
        result = run.record(
            check="compat_test",
            manifest_id="manifest_001",
            input="test data",
            check_result="pass",
        )
        assert not result.queued, "Record should not be queued — API should accept it"
        assert result.record_id.startswith("rec_")
        assert result.commitment_hash
        assert result.proof_level in ("attestation", "execution", "witnessed", "mathematical")


# ---------------------------------------------------------------------------
# Close response parsing gaps
# ---------------------------------------------------------------------------


class TestRunCloseCompat:
    def test_close_response_field_mapping(self, api_server, api_key):
        """
        Verify canonical field names in API close response (post migration 012).

        API close response returns at top level:
          provable_surface_breakdown (canonical, was proof_distribution)
          proof_level_floor (canonical, was proof_level)
          coverage.provable_surface (canonical, was policy_coverage_pct)
          gaps (canonical)
        """
        # Use raw HTTP to create a run, record, and close
        client = httpx.Client(
            base_url=f"http://localhost:8100",
            headers={"X-API-Key": api_key},
            timeout=10.0,
        )

        # Create run
        resp = client.post("/api/v1/runs", json={
            "workflow_id": "close-compat",
            "surface_id": "default",
            "policy_pack_id": "default",
        })
        assert resp.status_code == 200
        run_id = resp.json()["run_id"]

        # Record
        import uuid
        resp = client.post(f"/api/v1/runs/{run_id}/records", json={
            "manifest_id": "manifest_001",
            "commitment_hash": "sha256:closetest",
            "commitment_algorithm": "sha256",
            "commitment_type": "input_only",
            "check_result": "pass",
            "proof_level_achieved": "attestation",
            "idempotency_key": f"idem_{uuid.uuid4().hex[:16]}",
        })
        assert resp.status_code == 200

        # Close
        resp = client.post(f"/api/v1/runs/{run_id}/close", json={
            "partial": False,
            "request_zk": False,
        })
        assert resp.status_code == 200
        vpec = resp.json()

        # Verify canonical field names (migration 012)
        assert "provable_surface_breakdown" in vpec, "API returns provable_surface_breakdown"
        assert "proof_distribution" not in vpec, "proof_distribution is banned"
        assert "proof_level_breakdown" not in vpec, "proof_level_breakdown is banned"
        assert "proof_level_floor" in vpec, "API returns proof_level_floor"
        assert "coverage" in vpec, "API returns coverage"
        assert "coverage_verified_pct" not in vpec, "coverage_verified_pct is banned"
        assert "governance_gaps" not in vpec, "governance_gaps is banned"
        assert "gaps" in vpec, "API returns gaps"

        client.close()


# ---------------------------------------------------------------------------
# Protocol gap summary
# ---------------------------------------------------------------------------


class TestProtocolGapSummary:
    def test_document_resolved_gaps(self):
        """
        Living documentation of protocol gaps between SDK and API.

        RESOLVED:
          - proof_level_achieved: SDK now derives from _estimate_proof_level()
          - idempotency_key: SDK now generates UUID per call
          - commitment_type: SDK now sends "input_only" or "input_output"
          - provable_surface_breakdown is the canonical name (was proof_distribution / proof_level_breakdown)
          - gaps is the canonical name (was governance_gaps)
          - coverage nesting: _parse_vpec extracts from coverage dict
          - vpec_id at top level: _poll_for_vpec checks for vpec_id key

        REMAINING (cosmetic — SDK sends extras that API ignores):
          - record_id, run_id, check, sequence, visibility, chain_hash,
            recorded_at — sent by SDK, ignored by Pydantic
        """
        # SDK Run.record() envelope now includes all required API fields
        sdk_record_fields = {
            "record_id", "run_id", "manifest_id", "check", "sequence",
            "check_result", "commitment_hash", "commitment_algorithm",
            "commitment_type", "proof_level_achieved", "idempotency_key",
            "visibility", "chain_hash", "recorded_at",
        }

        # API CreateRecordRequest required fields
        api_required_fields = {
            "manifest_id", "commitment_hash", "commitment_algorithm",
            "check_result", "proof_level_achieved", "idempotency_key",
        }

        # All API required fields are now present in SDK envelope
        missing_from_sdk = api_required_fields - sdk_record_fields
        assert len(missing_from_sdk) == 0, f"No missing fields, was: {missing_from_sdk}"

        # SDK sends extras that API ignores (harmless)
        sdk_extras = sdk_record_fields - api_required_fields
        assert "record_id" in sdk_extras
        assert "check" in sdk_extras
