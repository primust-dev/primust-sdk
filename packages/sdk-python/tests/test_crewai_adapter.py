"""
P11-E: CrewAI adapter tests — 6 MUST PASS.

Uses mock CrewAI types and mock Pipeline HTTP transport.
"""

from __future__ import annotations

import json
import time
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

from primust.pipeline import Pipeline
from primust.adapters.crewai import PrimustCrewAICallback


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


# ── Mock CrewAI types ──


class MockAgent:
    def __init__(self, role: str) -> None:
        self.role = role


class MockAgentAction:
    """Simulates crewai AgentAction."""
    def __init__(self, agent: MockAgent, tool: str, tool_input: str) -> None:
        self.agent = agent
        self.tool = tool
        self.tool_input = tool_input
        self.output = None


class MockAgentFinish:
    """Simulates crewai AgentFinish."""
    def __init__(self, agent: MockAgent, output: str) -> None:
        self.agent = agent
        self.output = output
        self.text = "finish step"
        self.return_values = {"output": output}


@pytest.fixture
def transport() -> MockTransport:
    return MockTransport()


@pytest.fixture
def pipeline(transport: MockTransport) -> Pipeline:
    client = httpx.Client(
        base_url="https://api.primust.com",
        headers={"X-API-Key": "pk_sb_placeholder_123"},
        transport=transport,
    )
    return Pipeline(
        api_key="pk_sb_placeholder_123",
        workflow_id="wf_crewai",
        process_context_hash="sha256:" + "cc" * 32,
        http_client=client,
    )


class TestCrewAIAdapter:
    """P11-E: CrewAI adapter."""

    def test_crew_runs_to_completion_with_callback(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: Crew runs to completion with callback attached."""
        callback = PrimustCrewAICallback(
            pipeline=pipeline,
            manifest_map={"Research Analyst": "manifest_research_v1"},
        )

        agent = MockAgent(role="Research Analyst")
        action = MockAgentAction(agent=agent, tool="search", tool_input="query data")
        finish = MockAgentFinish(agent=agent, output="Research complete")

        # Simulate crew step_callback calls
        callback.on_step(action)
        callback.on_step(finish)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert len(record_req) == 2  # one action + one finish

    def test_agent_action_and_finish_both_produce_records(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: AgentAction + AgentFinish both produce records."""
        callback = PrimustCrewAICallback(
            pipeline=pipeline,
            manifest_map={"Writer": "manifest_writer_v1"},
        )

        agent = MockAgent(role="Writer")
        action = MockAgentAction(agent=agent, tool="draft", tool_input="outline")
        finish = MockAgentFinish(agent=agent, output="Draft complete")

        callback.on_step(action)
        callback.on_step(finish)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert len(record_req) == 2

        # Both should have commitment_hash
        for req in record_req:
            assert req["body"]["commitment_hash"].startswith("poseidon2:")

    def test_callback_exception_does_not_propagate(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: callback exception does not propagate into Crew (try/except test)."""
        callback = PrimustCrewAICallback(pipeline=pipeline)

        # Break the pipeline.record method
        original_record = pipeline.record
        pipeline.record = None  # type: ignore — force AttributeError

        # Should NOT raise — exception is swallowed
        callback.on_step({"type": "action", "tool": "broken", "input": "data", "agent_role": "test"})

        pipeline.record = original_record  # type: ignore

    def test_raw_output_never_in_api_call(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: raw output never in any API call (HTTP interceptor)."""
        callback = PrimustCrewAICallback(
            pipeline=pipeline,
            manifest_map={"Analyst": "manifest_analyst"},
        )

        agent = MockAgent(role="Analyst")
        sensitive_output = "this sensitive research data must never transit the API"
        finish = MockAgentFinish(agent=agent, output=sensitive_output)

        callback.on_step(finish)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert len(record_req) == 1
        assert sensitive_output not in record_req[0]["raw_body"]

    def test_performance_overhead_under_5ms(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: < 5ms overhead per step (benchmark)."""
        callback = PrimustCrewAICallback(
            pipeline=pipeline,
            manifest_map={"Fast Agent": "manifest_fast"},
        )

        agent = MockAgent(role="Fast Agent")
        action = MockAgentAction(agent=agent, tool="fast_tool", tool_input="data")

        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            callback.on_step(action)
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / iterations) * 1000
        assert avg_ms < 5.0, f"Average overhead {avg_ms:.2f}ms exceeds 5ms"

    def test_unmapped_agent_role_still_records(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: unmapped agent role → record still created (unverified_provenance)."""
        callback = PrimustCrewAICallback(
            pipeline=pipeline,
            manifest_map={"Known Role": "manifest_known"},
        )

        agent = MockAgent(role="Unknown Role")
        finish = MockAgentFinish(agent=agent, output="Result from unknown agent")

        callback.on_step(finish)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert len(record_req) == 1
        # Manifest should be auto-generated for unmapped roles
        assert record_req[0]["body"]["manifest_id"].startswith("auto:")
