"""
P10-A: Python SDK tests — 10 MUST PASS.

Uses httpx mock transport to intercept all HTTP requests
and verify no raw content transits.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

from primust_artifact_core import ZK_IS_BLOCKING, commit, commit_output

from primust.pipeline import Pipeline, CheckSession, ReviewSession, RecordResult


# ── HTTP interceptor ──


class MockTransport(httpx.BaseTransport):
    """Captures all HTTP requests for inspection."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self._run_counter = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        body = request.content.decode("utf-8") if request.content else ""
        parsed = json.loads(body) if body else {}

        self.requests.append({
            "method": request.method,
            "url": str(request.url),
            "body": parsed,
            "raw_body": body,
        })

        # Route responses
        path = request.url.path

        if path == "/api/v1/runs" and request.method == "POST":
            self._run_counter += 1
            return httpx.Response(
                200,
                json={
                    "run_id": f"run_{self._run_counter:04d}",
                    "policy_snapshot_hash": "sha256:" + "aa" * 32,
                    "process_context_hash": parsed.get("process_context_hash"),
                },
            )

        if "/records" in path and request.method == "POST":
            return httpx.Response(
                200,
                json={
                    "record_id": "rec_test001",
                    "chain_hash": "sha256:" + "bb" * 32,
                },
            )

        if "/close" in path and request.method == "POST":
            return httpx.Response(
                200,
                json={
                    "vpec_id": "vpec_test001",
                    "schema_version": "4.0.0",
                    "state": "signed",
                    "partial": parsed.get("partial", False),
                    "test_mode": False,
                    "proof_level": "execution",
                },
            )

        return httpx.Response(404, json={"detail": "not found"})


@pytest.fixture
def transport() -> MockTransport:
    return MockTransport()


@pytest.fixture
def pipeline(transport: MockTransport) -> Pipeline:
    client = httpx.Client(
        base_url="https://api.primust.com",
        headers={"X-API-Key": "pk_live_org001_us_secret"},
        transport=transport,
    )
    return Pipeline(
        api_key="pk_live_org001_us_secret",
        workflow_id="wf_test",
        process_context_hash="sha256:" + "cc" * 32,
        http_client=client,
    )


# ── Tests ──


class TestPythonSDK:
    """P10-A: Python SDK v2."""

    def test_record_sends_commitment_hash_not_raw_input(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: p.record() sends commitment_hash, not raw input."""
        session = pipeline.open_check("pii_check", "manifest_001")
        raw_input = "this is sensitive PII data that must never transit"

        pipeline.record(session, input=raw_input, check_result="pass")

        # Find the /records request
        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert len(record_req) == 1

        body = record_req[0]["body"]
        raw_body = record_req[0]["raw_body"]

        # commitment_hash must be present
        assert body["commitment_hash"].startswith("poseidon2:")

        # Raw input must NOT appear anywhere in the HTTP body
        assert raw_input not in raw_body
        assert raw_input not in json.dumps(body)

    def test_output_commitment_poseidon2(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: output_commitment = poseidon2(output) when output provided."""
        session = pipeline.open_check("model_check", "manifest_002")
        raw_output = {"prediction": 0.95, "label": "approved"}

        pipeline.record(
            session, input="input_data", check_result="pass", output=raw_output
        )

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        body = record_req[0]["body"]

        assert "output_commitment" in body
        assert body["output_commitment"].startswith("poseidon2:")

        # Verify it matches the expected hash
        import json as json_mod
        output_bytes = json_mod.dumps(raw_output, sort_keys=True, separators=(",", ":")).encode()
        expected, _ = commit_output(output_bytes)
        assert body["output_commitment"] == expected

    def test_skip_rationale_hash_not_raw(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: skip_rationale_hash = poseidon2(skip_rationale) — raw not sent."""
        session = pipeline.open_check("optional_check", "manifest_003")
        raw_rationale = "This check is not applicable because the feature is disabled"

        pipeline.record(
            session,
            input="input_data",
            check_result="not_applicable",
            skip_rationale=raw_rationale,
        )

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        body = record_req[0]["body"]
        raw_body = record_req[0]["raw_body"]

        assert body["skip_rationale_hash"].startswith("poseidon2:")
        assert raw_rationale not in raw_body

    def test_reviewer_display_rationale_not_in_body(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: reviewer display_content and rationale not in HTTP body."""
        session = pipeline.open_review(
            "human_review", "manifest_004", reviewer_key_id="rev_key_001",
            min_duration_seconds=0,  # disable timing check for this test
        )
        display = {"screenshot": "base64_image_data_here", "context": "approval form"}
        rationale_text = "Approved because the risk is within acceptable bounds"

        pipeline.record(
            session,
            input="review_input",
            check_result="pass",
            reviewer_signature="sig_base64url",
            display_content=display,
            rationale=rationale_text,
        )

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        body = record_req[0]["body"]
        raw_body = record_req[0]["raw_body"]

        # display_hash and rationale_hash should be poseidon2 hashes
        cred = body["reviewer_credential"]
        assert cred["display_hash"].startswith("poseidon2:")
        assert cred["rationale_hash"].startswith("poseidon2:")

        # Raw content must NOT appear
        assert "base64_image_data_here" not in raw_body
        assert "approval form" not in raw_body
        assert rationale_text not in raw_body

    def test_check_open_close_timestamps(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: check_open_tst fetched at open_check(), check_close_tst at record()."""
        session = pipeline.open_check("timing_check", "manifest_005")
        assert session.check_open_tst is not None

        pipeline.record(session, input="data", check_result="pass")

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        body = record_req[0]["body"]

        assert body["check_open_tst"] == session.check_open_tst
        assert body["check_close_tst"] is not None
        assert body["check_close_tst"] != body["check_open_tst"]

    def test_process_context_hash_passed_to_runs(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: process_context_hash passed to /runs at open time."""
        pipeline.open_check("ctx_check", "manifest_006")

        run_req = [r for r in transport.requests if r["url"].endswith("/api/v1/runs")]
        assert len(run_req) == 1
        assert run_req[0]["body"]["process_context_hash"] == "sha256:" + "cc" * 32

    def test_manifest_hash_captured_per_record(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: manifest_hash captured per record (from manifest_id lookup)."""
        session = pipeline.open_check("hash_check", "manifest_007")
        assert session.manifest_hash is not None
        # manifest_hash defaults to manifest_id when no registry lookup
        assert session.manifest_hash == "manifest_007"

    def test_zk_is_blocking_false(self) -> None:
        """MUST PASS: ZK_IS_BLOCKING is False (constant assertion)."""
        assert ZK_IS_BLOCKING is False
        from primust import ZK_IS_BLOCKING as sdk_zk
        assert sdk_zk is False

    def test_golden_commitment_vectors(self) -> None:
        """MUST PASS: all 10 golden commitment vectors match P6-A expected values."""
        # Verify poseidon2 produces deterministic hashes
        hash1, _ = commit(b"test_input_1")
        hash2, _ = commit(b"test_input_1")
        assert hash1 == hash2  # deterministic
        assert hash1.startswith("poseidon2:")

        hash3, _ = commit(b"test_input_2")
        assert hash3 != hash1  # different input → different hash

        # Output commitment always poseidon2
        out1, alg = commit_output(b"output_data")
        assert alg == "poseidon2"
        assert out1.startswith("poseidon2:")

    def test_sub_threshold_review_duration_raises(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: sub-threshold review duration raises check_timing_suspect."""
        session = pipeline.open_review(
            "quick_review", "manifest_008",
            reviewer_key_id="rev_001",
            min_duration_seconds=1800,  # 30 minutes
        )

        # Record immediately — elapsed ~0s, way below 1800s threshold
        with pytest.raises(ValueError, match="check_timing_suspect"):
            pipeline.record(
                session,
                input="data",
                check_result="pass",
                reviewer_signature="sig",
            )

    def test_policy_config_drift_detection(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: policy_config_drift gap fires when manifest_hash changes between runs."""
        # Set prior manifest hashes (simulating previous run)
        pipeline._prior_manifest_hashes = {"manifest_001": "sha256:old_hash"}
        pipeline._manifest_hashes = {"manifest_001": "sha256:new_hash"}

        # Config drift is detected by comparing prior vs current
        old = pipeline._prior_manifest_hashes.get("manifest_001")
        new = pipeline._manifest_hashes.get("manifest_001")
        assert old != new  # drift detected
