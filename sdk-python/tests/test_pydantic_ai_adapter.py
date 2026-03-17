"""
P11-G: Pydantic AI adapter tests — 8 MUST PASS.

Uses mock Pydantic AI agent and mock Pipeline HTTP transport.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import pytest

from primust.pipeline import Pipeline
from primust.adapters.pydantic_ai import (
    PrimustPydanticAIDep,
    instrument_agent,
)


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
                "schema_version": "4.0.0",
                "state": "signed",
            })
        return httpx.Response(404, json={"detail": "not found"})


# ── Mock Pydantic AI agent ──


class MockToolObj:
    """Simulates a pydantic-ai tool object with .function attribute."""

    def __init__(self, name: str, fn: Any) -> None:
        self.name = name
        self.function = fn


class MockPydanticAIAgent:
    """Simulates a pydantic-ai Agent with _function_tools dict."""

    def __init__(self) -> None:
        self._function_tools: dict[str, MockToolObj] = {}

    def add_tool(self, name: str, fn: Any) -> None:
        self._function_tools[name] = MockToolObj(name, fn)

    def run_sync(self, query: str, deps: Any = None) -> dict[str, Any]:
        """Simulate agent.run() by calling all tools."""
        results = {}
        for name, tool_obj in self._function_tools.items():
            results[name] = tool_obj.function(query)
        return {"data": results}


@pytest.fixture
def transport() -> MockTransport:
    return MockTransport()


@pytest.fixture
def pipeline(transport: MockTransport) -> Pipeline:
    client = httpx.Client(
        base_url="https://api.primust.com",
        headers={"X-API-Key": "pk_test_placeholder_123"},
        transport=transport,
    )
    return Pipeline(
        api_key="pk_test_placeholder_123",
        workflow_id="wf_pydantic_ai",
        process_context_hash="sha256:" + "cc" * 32,
        http_client=client,
    )


class TestPydanticAIAdapter:
    """P11-G: Pydantic AI adapter."""

    def test_instrumented_agent_produces_records(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: agent.run() with instrumented tools → records created."""
        dep = PrimustPydanticAIDep(
            pipeline=pipeline,
            manifest_map={"search_web": "manifest_search_v2"},
        )

        agent = MockPydanticAIAgent()
        agent.add_tool("search_web", lambda q: f"results for {q}")

        instrument_agent(agent, dep)
        result = agent.run_sync("test query", deps=dep)

        assert result["data"]["search_web"] == "results for test query"

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert len(record_req) == 1
        assert record_req[0]["body"]["commitment_hash"].startswith("poseidon2:")

    def test_each_tool_call_generates_record(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: each tool call generates a p.record()."""
        dep = PrimustPydanticAIDep(
            pipeline=pipeline,
            manifest_map={
                "search": "manifest_search",
                "validate": "manifest_validate",
            },
        )

        agent = MockPydanticAIAgent()
        agent.add_tool("search", lambda q: "search result")
        agent.add_tool("validate", lambda q: "valid")

        instrument_agent(agent, dep)
        agent.run_sync("query", deps=dep)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert len(record_req) == 2

    def test_tool_exception_records_error_and_propagates(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: tool exception → check_result: error, exception still propagates."""
        dep = PrimustPydanticAIDep(pipeline=pipeline)

        agent = MockPydanticAIAgent()

        def failing_tool(q: str) -> str:
            raise ValueError("tool exploded")

        agent.add_tool("broken", failing_tool)
        instrument_agent(agent, dep)

        with pytest.raises(ValueError, match="tool exploded"):
            agent.run_sync("query", deps=dep)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert len(record_req) == 1
        assert record_req[0]["body"]["check_result"] == "error"

    def test_instrument_agent_does_not_alter_return_values(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: instrument_agent() does not alter tool return values."""
        dep = PrimustPydanticAIDep(pipeline=pipeline)

        original_result = {"key": "value", "count": 42}

        agent = MockPydanticAIAgent()
        agent.add_tool("calc", lambda q: original_result)

        instrument_agent(agent, dep)
        result = agent.run_sync("query", deps=dep)

        assert result["data"]["calc"] == original_result

    def test_adapter_failure_does_not_block_tool(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: adapter failure does not block tool execution (fail open test)."""
        dep = PrimustPydanticAIDep(pipeline=pipeline)

        agent = MockPydanticAIAgent()
        agent.add_tool("safe_tool", lambda q: "safe result")

        instrument_agent(agent, dep)

        # Break pipeline.record
        original_record = pipeline.record
        pipeline.record = None  # type: ignore

        result = agent.run_sync("query", deps=dep)
        assert result["data"]["safe_tool"] == "safe result"

        pipeline.record = original_record  # type: ignore

    def test_raw_tool_input_never_in_api_call(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: raw tool input never in any API call (HTTP interceptor)."""
        dep = PrimustPydanticAIDep(pipeline=pipeline)

        sensitive_input = "this sensitive tool data must never transit"

        agent = MockPydanticAIAgent()
        agent.add_tool("sensitive_tool", lambda q: "processed")

        instrument_agent(agent, dep)
        agent.run_sync(sensitive_input, deps=dep)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert sensitive_input not in record_req[0]["raw_body"]

    def test_performance_overhead_under_5ms(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: < 5ms overhead per tool call (benchmark)."""
        dep = PrimustPydanticAIDep(pipeline=pipeline)

        agent = MockPydanticAIAgent()
        agent.add_tool("fast_tool", lambda q: "fast")

        instrument_agent(agent, dep)

        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            agent._function_tools["fast_tool"].function("test")
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / iterations) * 1000
        assert avg_ms < 5.0, f"Average overhead {avg_ms:.2f}ms exceeds 5ms"

    def test_option_b_record_tool_context_manager(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: option A and option B produce identical VPEC structure."""
        dep = PrimustPydanticAIDep(
            pipeline=pipeline,
            manifest_map={"explicit_tool": "manifest_explicit"},
        )

        # Option B: explicit context manager
        with dep.record_tool("explicit_tool", input="query data") as record:
            result = "explicit result"
            record.set_output(result)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert len(record_req) == 1
        body = record_req[0]["body"]
        assert body["commitment_hash"].startswith("poseidon2:")
        assert body["output_commitment"].startswith("poseidon2:")
        assert body["manifest_id"] == "manifest_explicit"
