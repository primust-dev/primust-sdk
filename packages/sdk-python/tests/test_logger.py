"""
P10-A Logger Callback tests — 6 MUST PASS.

Tests set_logger() callback for SIEM linkage.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

from primust.models import LoggerOptions, PrimustLogEvent
from primust.pipeline import Pipeline


# ── HTTP interceptor (reused from test_sdk.py) ──


class MockTransport(httpx.BaseTransport):
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

        path = request.url.path
        if path == "/api/v1/runs" and request.method == "POST":
            self._run_counter += 1
            return httpx.Response(200, json={
                "run_id": f"run_{self._run_counter:04d}",
                "policy_snapshot_hash": "sha256:" + "aa" * 32,
            })
        if "/records" in path and request.method == "POST":
            return httpx.Response(200, json={
                "record_id": "rec_test001",
                "chain_hash": "sha256:" + "bb" * 32,
            })
        if "/close" in path and request.method == "POST":
            return httpx.Response(200, json={
                "vpec_id": "vpec_test001",
                "schema_version": "4.0.0",
                "state": "signed",
            })
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
        http_client=client,
    )


# ── Tests ──


class TestLoggerCallback:
    """P10-A: Logger Callback for SIEM Linkage."""

    def test_callback_fires_on_every_record(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: callback fires on every p.record() call."""
        events: list[PrimustLogEvent] = []
        pipeline.set_logger(lambda event: events.append(event))

        session = pipeline.open_check("check_1", "manifest_001")
        pipeline.record(session, input="data_1", check_result="pass")
        pipeline.record(session, input="data_2", check_result="fail")

        assert len(events) == 2
        assert events[0].primust_check_result == "pass"
        assert events[1].primust_check_result == "fail"

    def test_callback_receives_correct_commitment_hash(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: callback receives correct commitment_hash per record."""
        from primust_artifact_core import commit

        events: list[PrimustLogEvent] = []
        pipeline.set_logger(lambda event: events.append(event))

        session = pipeline.open_check("check_1", "manifest_001")
        raw_input = "test input for hash verification"
        pipeline.record(session, input=raw_input, check_result="pass")

        assert len(events) == 1
        # Verify hash matches what artifact-core produces
        expected_hash, _ = commit(raw_input.encode("utf-8"))
        assert events[0].primust_commitment_hash == expected_hash

    def test_exception_in_callback_does_not_interrupt_record(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: exception in callback does not interrupt p.record()."""
        def exploding_logger(event: PrimustLogEvent) -> None:
            raise RuntimeError("Logger crashed!")

        pipeline.set_logger(exploding_logger)

        session = pipeline.open_check("check_1", "manifest_001")
        # Should not raise despite callback exploding
        result = pipeline.record(session, input="data", check_result="pass")
        assert result.commitment_hash.startswith("poseidon2:") or result.commitment_hash.startswith("sha256:")

    def test_record_returns_normally_when_no_logger_set(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: p.record() returns normally when no logger set."""
        # No set_logger() call
        session = pipeline.open_check("check_1", "manifest_001")
        result = pipeline.record(session, input="data", check_result="pass")
        assert result.record_id is not None

    def test_callback_receives_no_content_fields(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: callback receives no content fields (allowlist test)."""
        events: list[PrimustLogEvent] = []
        pipeline.set_logger(lambda event: events.append(event))

        session = pipeline.open_check("check_1", "manifest_001")
        sensitive_input = "SUPER SECRET DATA that must not appear"
        pipeline.record(session, input=sensitive_input, check_result="pass")

        event = events[0]
        # Verify no content fields in the event
        event_dict = event.__dict__
        all_values = json.dumps(event_dict)
        assert sensitive_input not in all_values

        # Only allowed fields
        allowed_fields = {
            "primust_record_id", "primust_commitment_hash",
            "primust_check_result", "primust_proof_level",
            "primust_workflow_id", "primust_run_id",
            "primust_recorded_at", "gap_types_emitted",
        }
        assert set(event_dict.keys()) <= allowed_fields

    def test_callback_called_before_api_call(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: callback is called before ObservationEnvelope is sent."""
        call_order: list[str] = []

        def tracking_logger(event: PrimustLogEvent) -> None:
            call_order.append("logger")

        # Wrap transport to track API call timing
        original_handle = transport.handle_request

        def tracking_handle(request: httpx.Request) -> httpx.Response:
            if "/records" in str(request.url):
                call_order.append("api")
            return original_handle(request)

        transport.handle_request = tracking_handle  # type: ignore[assignment]

        pipeline.set_logger(tracking_logger)
        session = pipeline.open_check("check_1", "manifest_001")
        pipeline.record(session, input="data", check_result="pass")

        assert call_order == ["logger", "api"]
