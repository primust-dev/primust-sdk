"""
P11-A: LangGraph adapter tests — 9 MUST PASS.

Uses mock Pipeline and mock LangGraph graph objects.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest

from primust_artifact_core import commit, commit_output
from primust.pipeline import Pipeline, CheckSession

from primust_langgraph import PrimustLangGraph


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


# ── Mock LangGraph graph ──


class MockStateGraph:
    """Simulates a LangGraph StateGraph with nodes."""

    def __init__(self) -> None:
        self.nodes: dict[str, Any] = {}

    def add_node(self, name: str, fn: Any) -> None:
        self.nodes[name] = fn


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
        workflow_id="wf_langgraph",
        process_context_hash="sha256:" + "cc" * 32,
        http_client=client,
    )


# ── Tests ──


class TestLangGraphAdapter:
    """P11-A: LangGraph adapter."""

    def test_tool_call_creates_record_with_commitment_hash(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: tool call → CheckExecutionRecord created with commitment_hash."""
        adapter = PrimustLangGraph(
            pipeline=pipeline,
            manifest_map={"search": "manifest_search_v1"},
        )

        def search_tool(query: str) -> str:
            return f"Results for {query}"

        wrapped = adapter.wrap_tool("search", search_tool)
        result = wrapped(query="test query")

        assert result == "Results for test query"

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert len(record_req) == 1
        body = record_req[0]["body"]
        assert body["commitment_hash"].startswith("poseidon2:")
        assert body["manifest_id"] == "manifest_search_v1"

    def test_raw_tool_input_not_in_http_body(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: raw tool input not in HTTP body (interceptor test)."""
        adapter = PrimustLangGraph(pipeline=pipeline)

        sensitive_input = "this is sensitive PII data that must never transit"

        def pii_tool(data: str) -> str:
            return "processed"

        wrapped = adapter.wrap_tool("pii_tool", pii_tool)
        wrapped(data=sensitive_input)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        raw_body = record_req[0]["raw_body"]
        assert sensitive_input not in raw_body

    def test_check_open_tst_fetched_before_tool_executes(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: check_open_tst fetched before tool executes."""
        adapter = PrimustLangGraph(pipeline=pipeline)

        def slow_tool(x: int) -> int:
            return x * 2

        wrapped = adapter.wrap_tool("slow_tool", slow_tool)
        wrapped(x=42)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        body = record_req[0]["body"]
        assert body["check_open_tst"] is not None
        from datetime import datetime
        datetime.fromisoformat(body["check_open_tst"])  # valid ISO string

    def test_check_close_tst_at_record_time(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: check_close_tst fetched at p.record() time."""
        adapter = PrimustLangGraph(pipeline=pipeline)

        def tool(x: int) -> int:
            return x + 1

        wrapped = adapter.wrap_tool("tool", tool)
        wrapped(x=1)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        body = record_req[0]["body"]
        assert body["check_close_tst"] is not None
        from datetime import datetime
        datetime.fromisoformat(body["check_close_tst"])

    def test_output_commitment_present_when_tool_returns(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: output_commitment present when tool returns output."""
        adapter = PrimustLangGraph(pipeline=pipeline)

        def calc_tool(a: int, b: int) -> dict[str, int]:
            return {"sum": a + b}

        wrapped = adapter.wrap_tool("calc_tool", calc_tool)
        result = wrapped(a=3, b=4)
        assert result == {"sum": 7}

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        body = record_req[0]["body"]
        assert body["output_commitment"].startswith("poseidon2:")

    def test_manifest_hash_captured_per_record(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: manifest_hash captured per record."""
        adapter = PrimustLangGraph(
            pipeline=pipeline,
            manifest_map={"tool_a": "manifest_a_v1"},
        )

        wrapped = adapter.wrap_tool("tool_a", lambda: "ok")
        wrapped()

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        body = record_req[0]["body"]
        assert body["manifest_id"] == "manifest_a_v1"

    def test_process_context_hash_propagated(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: process_context_hash propagated from Pipeline."""
        adapter = PrimustLangGraph(pipeline=pipeline)
        wrapped = adapter.wrap_tool("tool", lambda: "ok")
        wrapped()

        run_req = [r for r in transport.requests if r["url"].endswith("/api/v1/runs")]
        assert run_req[0]["body"]["process_context_hash"] == "sha256:" + "cc" * 32

    def test_surface_type_in_process_adapter(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: surface_type = in_process_adapter in ObservationSurface."""
        adapter = PrimustLangGraph(pipeline=pipeline)
        surface = adapter.get_surface_declaration()
        assert surface["surface_type"] == "in_process_adapter"
        assert surface["observation_mode"] == "post_action_realtime"
        assert surface["scope_type"] == "full_workflow"

    def test_all_five_proof_levels_reachable(self) -> None:
        """MUST PASS: all 5 proof levels reachable depending on manifest stage type."""
        from primust_langgraph.adapter import PROOF_LEVEL_MAP
        expected = {"mathematical", "execution_zkml", "execution", "witnessed", "attestation"}
        assert set(PROOF_LEVEL_MAP.values()) == expected

    def test_wrap_graph_instruments_nodes(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """wrap() instruments all nodes in a StateGraph."""
        adapter = PrimustLangGraph(
            pipeline=pipeline,
            manifest_map={"node_a": "manifest_a"},
        )

        graph = MockStateGraph()
        graph.add_node("node_a", lambda state: {"output": "done"})

        adapter.wrap(graph)

        # Call the wrapped node
        result = graph.nodes["node_a"](state={"input": "test"})
        assert result == {"output": "done"}

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert len(record_req) == 1

    def test_adapter_failure_does_not_block_tool(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """Adapter failure does not block tool execution (fail open)."""
        adapter = PrimustLangGraph(pipeline=pipeline)

        # Force pipeline.record to raise
        original_record = pipeline.record
        def broken_record(*a: Any, **kw: Any) -> Any:
            raise RuntimeError("record exploded")
        pipeline.record = broken_record  # type: ignore

        def tool(x: int) -> int:
            return x * 10

        wrapped = adapter.wrap_tool("tool", tool)
        result = wrapped(x=5)
        assert result == 50  # tool still returns correctly

        pipeline.record = original_record  # type: ignore
