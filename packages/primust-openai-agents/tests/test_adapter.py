"""
P11-D: OpenAI Agents SDK adapter tests — 5 MUST PASS.

Uses mock Pipeline and mock Agent objects.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from primust.pipeline import Pipeline

from primust_openai_agents import PrimustOpenAIAgents
from primust_openai_agents.adapter import PROOF_LEVEL_MAP


# ── Mock HTTP transport ──


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
                "process_context_hash": parsed.get("process_context_hash"),
            })
        if "/records" in path and request.method == "POST":
            return httpx.Response(200, json={
                "record_id": "rec_test001",
                "chain_hash": "sha256:" + "bb" * 32,
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
        workflow_id="wf_openai",
        process_context_hash="sha256:" + "cc" * 32,
        http_client=client,
    )


class TestOpenAIAgentsAdapter:
    """P11-D: OpenAI Agents SDK adapter."""

    def test_tool_call_creates_record_with_all_v2_fields(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: tool call → CheckExecutionRecord with all v2 fields."""
        adapter = PrimustOpenAIAgents(
            pipeline=pipeline,
            manifest_map={"search": "manifest_search_v1"},
        )
        wrapped = adapter.wrap_tool("search", lambda query: f"results: {query}")
        result = wrapped(query="test")
        assert result == "results: test"

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert len(record_req) == 1
        body = record_req[0]["body"]
        assert body["commitment_hash"].startswith("poseidon2:")
        assert body["output_commitment"].startswith("poseidon2:")
        assert body["check_open_tst"] is not None
        assert body["check_close_tst"] is not None
        assert body["manifest_id"] == "manifest_search_v1"

    def test_raw_content_not_in_http_body(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: raw content not in HTTP body."""
        adapter = PrimustOpenAIAgents(pipeline=pipeline)
        sensitive = "sensitive agent tool data never transit"
        wrapped = adapter.wrap_tool("tool", lambda data: "processed")
        wrapped(data=sensitive)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert sensitive not in record_req[0]["raw_body"]

    def test_timestamps_and_output_commitment_present(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: check_open_tst, check_close_tst, output_commitment, manifest_hash present."""
        adapter = PrimustOpenAIAgents(
            pipeline=pipeline,
            manifest_map={"calc": "manifest_calc_v1"},
        )
        wrapped = adapter.wrap_tool("calc", lambda x: x * 2)
        wrapped(x=21)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        body = record_req[0]["body"]
        assert body["check_open_tst"] is not None
        assert body["check_close_tst"] is not None
        assert body["output_commitment"].startswith("poseidon2:")
        assert body["manifest_id"] == "manifest_calc_v1"

    def test_process_context_hash_propagated(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: process_context_hash propagated."""
        adapter = PrimustOpenAIAgents(pipeline=pipeline)
        wrapped = adapter.wrap_tool("tool", lambda: "ok")
        wrapped()

        run_req = [r for r in transport.requests if r["url"].endswith("/api/v1/runs")]
        assert run_req[0]["body"]["process_context_hash"] == "sha256:" + "cc" * 32

    def test_all_five_proof_levels_reachable(self) -> None:
        """MUST PASS: all 5 proof levels reachable."""
        expected = {"mathematical", "execution_zkml", "execution", "witnessed", "attestation"}
        assert set(PROOF_LEVEL_MAP.values()) == expected

    def test_adapter_failure_does_not_block_tool(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """Adapter failure does not block tool execution."""
        adapter = PrimustOpenAIAgents(pipeline=pipeline)

        original_record = pipeline.record
        pipeline.record = None  # type: ignore — force error
        wrapped = adapter.wrap_tool("tool", lambda x: x + 1)
        result = wrapped(x=5)
        assert result == 6
        pipeline.record = original_record  # type: ignore
