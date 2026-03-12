"""
Primust SDK — Run-based API tests (P10-A).

MUST PASS:
  1. pipeline.open() → run.record() → run.close() → valid VPEC structure
  2. Raw input NEVER appears in any API call (intercept and inspect)
  3. commitment_hash is in RecordResult
  4. API unavailable → local queue, no exception thrown to caller
  5. run.close() works after queue flush
  6. commitment is deterministic
  7. test_mode flag from pk_test_ prefix

Run: pytest tests/test_run_api.py -v
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from primust.pipeline import Pipeline
from primust.models import CheckResult, ProofLevel, VPEC, RecordResult
from primust_artifact_core import commit


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

RAW_INPUT = "John Smith SSN 123-45-6789 account balance $50,000"
SENSITIVE_DICT = {"patient_id": "pt_abc123", "medication": "warfarin", "dose_mg": 5.0}
TEST_API_KEY = "pk_test_abc123"
MANIFEST_ID = "sha256:deadbeef00000000000000000000000000000000000000000000000000000000"

MOCK_OPEN_RESPONSE = {
    "run_id": "run_test001",
    "org_id": "org_test",
    "policy_snapshot_hash": "sha256:aabbcc",
    "opened_at": "2026-03-11T00:00:00Z",
}

MOCK_RECORD_RESPONSE = {
    "record_id": "rec_test001",
    "proof_level": "attestation",
    "recorded_at": "2026-03-11T00:00:00Z",
}

MOCK_CLOSE_RESPONSE = {
    "vpec": {
        "vpec_id": "vpec_test001",
        "run_id": "run_test001",
        "org_id": "org_test",
        "workflow_id": "test-workflow",
        "issued_at": "2026-03-11T00:00:00Z",
        "proof_level": "attestation",
        "proof_level_breakdown": {"attestation": 1},
        "coverage_verified_pct": 100.0,
        "total_checks_run": 1,
        "checks_passed": 1,
        "checks_failed": 0,
        "governance_gaps": [],
        "chain_intact": True,
        "merkle_root": "sha256:merkle",
        "signature": "ed25519:sig",
        "timestamp_rfc3161": "base64:tst",
    }
}

MOCK_MANIFEST_RESPONSE = {
    "manifest_id": MANIFEST_ID,
    "registered_at": "2026-03-11T00:00:00Z",
}


# ---------------------------------------------------------------------------
# TEST 1: Basic flow — open → record → close → valid VPEC
# ---------------------------------------------------------------------------

def test_basic_flow_produces_vpec(tmp_path, respx_mock):
    """MUST PASS: pipeline.open() → run.record() → run.close() → valid VPEC."""
    respx_mock.post("https://api.primust.com/api/v1/runs").mock(
        return_value=httpx.Response(200, json=MOCK_OPEN_RESPONSE)
    )
    respx_mock.post(re.compile(r"https://api\.primust\.com/api/v1/runs/.+/records")).mock(
        return_value=httpx.Response(200, json=MOCK_RECORD_RESPONSE)
    )
    respx_mock.post(re.compile(r"https://api\.primust\.com/api/v1/runs/.+/close")).mock(
        return_value=httpx.Response(200, json=MOCK_CLOSE_RESPONSE)
    )

    p = Pipeline(
        api_key=TEST_API_KEY,
        workflow_id="test-workflow",
        queue_path=tmp_path / "queue.db",
        _base_url="https://api.primust.com/api/v1",
    )
    run = p.open()
    result = run.record(
        check="aml_screen",
        manifest_id=MANIFEST_ID,
        input=RAW_INPUT,
        check_result="pass",
    )
    vpec = run.close()

    assert vpec is not None
    assert isinstance(vpec, VPEC)
    assert vpec.vpec_id == "vpec_test001"
    assert vpec.chain_intact is True
    assert vpec.total_checks_run == 1


# ---------------------------------------------------------------------------
# TEST 2: Raw input NEVER appears in any API call
# ---------------------------------------------------------------------------

def test_raw_input_never_transits(tmp_path, respx_mock):
    """
    MUST PASS: Intercept every outbound HTTP request and assert that
    RAW_INPUT and SENSITIVE_DICT contents never appear in any request body.
    """
    transmitted_bodies = []

    def capture_and_respond(request, response_data):
        body = request.content.decode("utf-8", errors="replace")
        transmitted_bodies.append(body)
        return httpx.Response(200, json=response_data)

    respx_mock.post("https://api.primust.com/api/v1/runs").mock(
        side_effect=lambda req: capture_and_respond(req, MOCK_OPEN_RESPONSE)
    )
    respx_mock.post(re.compile(r"https://api\.primust\.com/api/v1/runs/.+/records")).mock(
        side_effect=lambda req: capture_and_respond(req, MOCK_RECORD_RESPONSE)
    )
    respx_mock.post(re.compile(r"https://api\.primust\.com/api/v1/runs/.+/close")).mock(
        side_effect=lambda req: capture_and_respond(req, MOCK_CLOSE_RESPONSE)
    )

    p = Pipeline(
        api_key=TEST_API_KEY,
        workflow_id="test-workflow",
        queue_path=tmp_path / "queue.db",
        _base_url="https://api.primust.com/api/v1",
    )
    run = p.open()

    run.record(
        check="aml_screen",
        manifest_id=MANIFEST_ID,
        input=RAW_INPUT,
        check_result="pass",
    )
    run.record(
        check="drug_interaction",
        manifest_id=MANIFEST_ID,
        input=SENSITIVE_DICT,
        check_result="pass",
    )
    run.close()

    all_transmitted = " ".join(transmitted_bodies)

    assert "John Smith" not in all_transmitted, "PII leaked in transit!"
    assert "123-45-6789" not in all_transmitted, "SSN leaked in transit!"
    assert "50,000" not in all_transmitted, "Account balance leaked in transit!"
    assert "warfarin" not in all_transmitted, "Medication name leaked in transit!"
    assert "pt_abc123" not in all_transmitted, "Patient ID leaked in transit!"

    # Commitment hashes SHOULD appear
    assert "poseidon2:" in all_transmitted or "sha256:" in all_transmitted


# ---------------------------------------------------------------------------
# TEST 3: commitment_hash is in RecordResult
# ---------------------------------------------------------------------------

def test_commitment_hash_in_result(tmp_path, respx_mock):
    """MUST PASS: commitment_hash is present in RecordResult."""
    respx_mock.post("https://api.primust.com/api/v1/runs").mock(
        return_value=httpx.Response(200, json=MOCK_OPEN_RESPONSE)
    )
    respx_mock.post(re.compile(r"https://api\.primust\.com/api/v1/runs/.+/records")).mock(
        return_value=httpx.Response(200, json=MOCK_RECORD_RESPONSE)
    )
    respx_mock.post(re.compile(r"https://api\.primust\.com/api/v1/runs/.+/close")).mock(
        return_value=httpx.Response(200, json=MOCK_CLOSE_RESPONSE)
    )

    p = Pipeline(
        api_key=TEST_API_KEY,
        workflow_id="test-workflow",
        queue_path=tmp_path / "queue.db",
        _base_url="https://api.primust.com/api/v1",
    )
    run = p.open()
    result = run.record(
        check="aml_screen",
        manifest_id=MANIFEST_ID,
        input=RAW_INPUT,
        check_result="pass",
    )

    assert result.commitment_hash is not None
    assert result.commitment_hash != ""
    assert result.commitment_hash.startswith("poseidon2:") or \
           result.commitment_hash.startswith("sha256:")
    assert result.record_id is not None
    assert result.proof_level is not None

    # Commitment is deterministic — same input produces same hash
    input_bytes = RAW_INPUT.encode("utf-8")
    hash2, _ = commit(input_bytes)
    assert result.commitment_hash == hash2


# ---------------------------------------------------------------------------
# TEST 4: API unavailable → local queue, no exception thrown
# ---------------------------------------------------------------------------

def test_api_unavailable_queues_locally_no_exception(tmp_path, respx_mock):
    """
    MUST PASS: When API is unreachable, SDK queues records locally.
    No exception is thrown to the caller. run.close() still returns a VPEC.
    """
    # Open succeeds
    respx_mock.post("https://api.primust.com/api/v1/runs").mock(
        return_value=httpx.Response(200, json=MOCK_OPEN_RESPONSE)
    )
    # All records fail (network error)
    respx_mock.post(re.compile(r"https://api\.primust\.com/api/v1/runs/.+/records")).mock(
        side_effect=httpx.ConnectError("Connection refused")
    )
    # Close also fails
    respx_mock.post(re.compile(r"https://api\.primust\.com/api/v1/runs/.+/close")).mock(
        side_effect=httpx.ConnectError("Connection refused")
    )

    p = Pipeline(
        api_key=TEST_API_KEY,
        workflow_id="test-workflow",
        queue_path=tmp_path / "queue.db",
        _base_url="https://api.primust.com/api/v1",
    )
    run = p.open()

    # MUST NOT raise — queued locally
    result = run.record(
        check="aml_screen",
        manifest_id=MANIFEST_ID,
        input=RAW_INPUT,
        check_result="pass",
    )

    assert result.commitment_hash is not None
    assert result.queued is True

    # close() MUST NOT raise — returns pending VPEC
    vpec = run.close()
    assert vpec is not None
    assert isinstance(vpec, VPEC)

    # Queue has items waiting
    assert p.pending_queue_count() > 0

    # VPEC has system_unavailable gap
    gap_types = [g.gap_type for g in vpec.governance_gaps]
    assert "system_unavailable" in gap_types


# ---------------------------------------------------------------------------
# TEST 5: run.close() works after queue flush
# ---------------------------------------------------------------------------

def test_queue_flushes_on_reconnect(tmp_path, respx_mock):
    """MUST PASS: Queue flushes when API comes back."""
    respx_mock.post("https://api.primust.com/api/v1/runs").mock(
        return_value=httpx.Response(200, json=MOCK_OPEN_RESPONSE)
    )
    respx_mock.post(re.compile(r"https://api\.primust\.com/api/v1/runs/.+/records")).mock(
        return_value=httpx.Response(200, json=MOCK_RECORD_RESPONSE)
    )
    respx_mock.post(re.compile(r"https://api\.primust\.com/api/v1/runs/.+/close")).mock(
        return_value=httpx.Response(200, json=MOCK_CLOSE_RESPONSE)
    )

    p = Pipeline(
        api_key=TEST_API_KEY,
        workflow_id="test-workflow",
        queue_path=tmp_path / "queue.db",
        _base_url="https://api.primust.com/api/v1",
    )

    # Manually enqueue a record to simulate prior offline period
    p._queue.enqueue_record(
        "run_old",
        "/runs/run_old/records",
        {"record_id": "rec_old", "check": "old_check", "commitment_hash": "sha256:old"}
    )
    assert p.pending_queue_count() == 1

    run = p.open()
    run.record(
        check="aml_screen",
        manifest_id=MANIFEST_ID,
        input=RAW_INPUT,
        check_result="pass",
    )

    # Queue flushed
    assert p.pending_queue_count() == 0

    vpec = run.close()
    assert isinstance(vpec, VPEC)


# ---------------------------------------------------------------------------
# TEST 6: commitment is deterministic
# ---------------------------------------------------------------------------

def test_commitment_is_deterministic():
    """Same input always produces same commitment hash."""
    h1, alg1 = commit(b"test input")
    h2, alg2 = commit(b"test input")
    assert h1 == h2
    assert alg1 == alg2

    # Dict ordering shouldn't matter (canonicalization)
    d1_bytes = json.dumps({"key": "value", "num": 42}, sort_keys=True, separators=(",", ":")).encode()
    d2_bytes = json.dumps({"num": 42, "key": "value"}, sort_keys=True, separators=(",", ":")).encode()
    d1, _ = commit(d1_bytes)
    d2, _ = commit(d2_bytes)
    assert d1 == d2


# ---------------------------------------------------------------------------
# TEST 7: test_mode flag from pk_test_ prefix
# ---------------------------------------------------------------------------

def test_test_mode_from_key_prefix(tmp_path, respx_mock):
    """pk_test_ prefix → test_mode=True on VPEC."""
    respx_mock.post("https://api.primust.com/api/v1/runs").mock(
        return_value=httpx.Response(200, json=MOCK_OPEN_RESPONSE)
    )
    respx_mock.post(re.compile(r"https://api\.primust\.com/api/v1/runs/.+/records")).mock(
        return_value=httpx.Response(200, json=MOCK_RECORD_RESPONSE)
    )
    respx_mock.post(re.compile(r"https://api\.primust\.com/api/v1/runs/.+/close")).mock(
        return_value=httpx.Response(200, json=MOCK_CLOSE_RESPONSE)
    )

    p = Pipeline(
        api_key="pk_test_xyz",
        workflow_id="test-workflow",
        queue_path=tmp_path / "queue.db",
        _base_url="https://api.primust.com/api/v1",
    )
    assert p.test_mode is True
    run = p.open()
    run.record(check="c", manifest_id=MANIFEST_ID, input="x", check_result="pass")
    vpec = run.close()
    assert vpec.test_mode is True
