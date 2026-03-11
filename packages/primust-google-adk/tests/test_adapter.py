"""
P11-B: Google ADK adapter tests — 5 MUST PASS.

Uses mock Pipeline and mock ADK Agent objects.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from primust.pipeline import Pipeline

from primust_google_adk import PrimustGoogleADK
from primust_google_adk.adapter import PROOF_LEVEL_MAP


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
        if "/close" in path and request.method == "POST":
            return httpx.Response(200, json={
                "vpec_id": "vpec_test001",
                "schema_version": "3.0.0",
                "state": "signed",
            })
        return httpx.Response(404, json={"detail": "not found"})


class MockADKAgent:
    """Simulates a Google ADK Agent with tools."""

    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}


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
        workflow_id="wf_adk",
        process_context_hash="sha256:" + "cc" * 32,
        http_client=client,
    )


class TestGoogleADKAdapter:
    """P11-B: Google ADK adapter."""

    def test_adk_tool_call_creates_record_with_all_v2_fields(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: ADK tool call → CheckExecutionRecord with all v2 fields."""
        adapter = PrimustGoogleADK(
            pipeline=pipeline,
            manifest_map={"search": "manifest_search_v1"},
        )
        wrapped = adapter.wrap_tool("search", lambda query: f"results for {query}")
        result = wrapped(query="hello")
        assert result == "results for hello"

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
        adapter = PrimustGoogleADK(pipeline=pipeline)
        sensitive = "sensitive ADK tool data never transit"
        wrapped = adapter.wrap_tool("tool", lambda data: "ok")
        wrapped(data=sensitive)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert sensitive not in record_req[0]["raw_body"]

    def test_all_five_proof_levels_reachable(self) -> None:
        """MUST PASS: all 5 proof levels reachable."""
        expected = {"mathematical", "execution_zkml", "execution", "witnessed", "attestation"}
        assert set(PROOF_LEVEL_MAP.values()) == expected

    def test_process_context_hash_propagated(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: process_context_hash propagated."""
        adapter = PrimustGoogleADK(pipeline=pipeline)
        wrapped = adapter.wrap_tool("tool", lambda: "ok")
        wrapped()

        run_req = [r for r in transport.requests if r["url"].endswith("/api/v1/runs")]
        assert run_req[0]["body"]["process_context_hash"] == "sha256:" + "cc" * 32

    def test_manifest_hash_per_record(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: manifest_hash per record."""
        adapter = PrimustGoogleADK(
            pipeline=pipeline,
            manifest_map={"my_tool": "manifest_my_tool_v2"},
        )
        wrapped = adapter.wrap_tool("my_tool", lambda: "done")
        wrapped()

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert record_req[0]["body"]["manifest_id"] == "manifest_my_tool_v2"

    def test_wrap_agent_instruments_tools(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """wrap() instruments all tools in an ADK Agent."""
        adapter = PrimustGoogleADK(
            pipeline=pipeline,
            manifest_map={"greet": "manifest_greet"},
        )
        agent = MockADKAgent()
        agent.tools["greet"] = lambda name: f"Hello {name}"
        adapter.wrap(agent)

        result = agent.tools["greet"](name="World")
        assert result == "Hello World"

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert len(record_req) == 1
