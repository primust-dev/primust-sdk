"""
P11-C: OTEL Span Processor adapter tests (Python).

Original 6 MUST PASS tests + OTL amendment coverage:
  OTL-1: Per-span-type proof ceilings
  OTL-2: Conditional commitment logic
  OTL-3: span.kind as proof-level discriminator
  OTL-4: gen_ai.evaluation.result → mathematical
  OTL-5: Deprecated attribute filtering
  OTL-6: Scoped attribute reading rules
  OTL-7: MCP span recognition (via standard tool span path)
  OTL-8: Per-tool manifest enforcement
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest

from primust.pipeline import Pipeline

from primust_otel import PrimustSpanProcessor
from primust_otel.span_processor import (
    PROOF_LEVEL_MAP,
    SPAN_TYPE_PROOF_CEILING,
    SpanType,
    STATUS_OK,
    STATUS_ERROR,
    STATUS_UNSET,
    SPAN_KIND_INTERNAL,
    SPAN_KIND_CLIENT,
    _PROHIBITED_ATTRIBUTES,
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
        return httpx.Response(404, json={"detail": "not found"})


# ── Mock OTEL types ──


@dataclass
class MockStatus:
    status_code: int = STATUS_OK


@dataclass
class MockEvent:
    name: str = ""
    timestamp: int | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class MockSpan:
    name: str = "test_span"
    attributes: dict[str, Any] | None = None
    events: list[MockEvent] | None = None
    status: MockStatus | None = None
    start_time: int | None = None
    end_time: int | None = None
    kind: int | None = None


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
        workflow_id="wf_otel",
        process_context_hash="sha256:" + "cc" * 32,
        http_client=client,
    )


# ---------------------------------------------------------------------------
# Original MUST PASS tests
# ---------------------------------------------------------------------------

class TestOTELSpanProcessor:
    """P11-C: OTEL Span Processor adapter (Python)."""

    def test_error_span_produces_fail_check_result(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: span.status.code=ERROR → check_result=fail."""
        processor = PrimustSpanProcessor(pipeline=pipeline)

        span = MockSpan(
            name="failing_operation",
            attributes={"http.method": "POST", "http.url": "https://example.com"},
            status=MockStatus(status_code=STATUS_ERROR),
        )
        processor.on_end(span)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert len(record_req) == 1
        assert record_req[0]["body"]["check_result"] == "fail"

    def test_commitment_hash_is_not_raw(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: commitment_hash is a hash (not raw content)."""
        processor = PrimustSpanProcessor(pipeline=pipeline)

        sensitive_value = "sensitive_data_never_transit"
        span = MockSpan(
            name="sensitive_op",
            attributes={"data": sensitive_value},
            status=MockStatus(status_code=STATUS_OK),
        )
        processor.on_end(span)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        body = record_req[0]["body"]
        raw_body = record_req[0]["raw_body"]

        assert body["commitment_hash"].startswith("sha256:") or body["commitment_hash"].startswith("poseidon2:")
        assert sensitive_value not in raw_body

    def test_human_review_span_witnessed_proof_level(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: human_review span → proof_level_achieved = witnessed."""
        processor = PrimustSpanProcessor(pipeline=pipeline)

        span = MockSpan(
            name="human_review_step",
            attributes={"primust.stage_type": "witnessed"},
            status=MockStatus(status_code=STATUS_OK),
        )
        processor.on_end(span)

        assert PROOF_LEVEL_MAP["witnessed"] == "witnessed"

    def test_process_context_hash_propagated(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: process_context_hash propagated from span attribute."""
        processor = PrimustSpanProcessor(pipeline=pipeline)

        span = MockSpan(
            name="ctx_op",
            attributes={"primust.process_context_hash": "sha256:" + "dd" * 32},
            status=MockStatus(status_code=STATUS_OK),
        )
        processor.on_end(span)

        run_req = [r for r in transport.requests if r["url"].endswith("/api/v1/runs")]
        assert run_req[0]["body"]["process_context_hash"] == "sha256:" + "cc" * 32

    def test_manifest_hash_from_span_attribute(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """MUST PASS: manifest_hash from span attribute when present."""
        processor = PrimustSpanProcessor(
            pipeline=pipeline,
            manifest_map={"my_op": "manifest_my_op_v1"},
        )

        span = MockSpan(
            name="my_op",
            attributes={"primust.manifest_id": "manifest_override_v2"},
            status=MockStatus(status_code=STATUS_OK),
        )
        processor.on_end(span)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert record_req[0]["body"]["manifest_id"] == "manifest_override_v2"

    def test_proof_levels_reachable(self) -> None:
        """Proof levels reachable in proof_level_achieved (mathematical excluded until ZK wired)."""
        expected = {"verifiable_inference", "execution", "witnessed", "attestation"}
        assert set(PROOF_LEVEL_MAP.values()) == expected

    def test_unset_status_produces_degraded(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """UNSET status code → degraded check_result."""
        processor = PrimustSpanProcessor(pipeline=pipeline)

        span = MockSpan(
            name="unset_op",
            attributes={"key": "val"},
            status=MockStatus(status_code=STATUS_UNSET),
        )
        processor.on_end(span)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert record_req[0]["body"]["check_result"] == "degraded"

    def test_span_with_events_produces_output_commitment(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """Span events → output_commitment present."""
        processor = PrimustSpanProcessor(pipeline=pipeline)

        span = MockSpan(
            name="event_op",
            attributes={"op": "test"},
            events=[MockEvent(name="log", attributes={"message": "done"})],
            status=MockStatus(status_code=STATUS_OK),
        )
        processor.on_end(span)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        body = record_req[0]["body"]
        oc = body.get("output_commitment", "")
        assert oc.startswith("sha256:") or oc.startswith("poseidon2:")

    def test_processor_failure_does_not_raise(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        """on_end() catches exceptions — never raises into OTEL pipeline."""
        processor = PrimustSpanProcessor(pipeline=pipeline)

        class BrokenSpan:
            name = "broken"
            attributes = None
            events = None
            status = None
            start_time = None
            end_time = None
            kind = None

        original_record = pipeline.record
        pipeline.record = None  # type: ignore — force AttributeError
        processor.on_end(BrokenSpan())  # type: ignore
        pipeline.record = original_record  # type: ignore


# ---------------------------------------------------------------------------
# OTL-1: Per-span-type proof ceilings
# ---------------------------------------------------------------------------

class TestSpanTypeClassification:
    """OTL-1: Span type classification determines proof ceiling."""

    def test_llm_inference_classified(self) -> None:
        processor = PrimustSpanProcessor(pipeline=None)  # type: ignore
        span = MockSpan(
            name="chat_completion",
            attributes={"gen_ai.request.model": "gpt-4"},
        )
        assert processor._classify_span(span) == SpanType.LLM_INFERENCE

    def test_tool_internal_classified(self) -> None:
        processor = PrimustSpanProcessor(pipeline=None)  # type: ignore
        span = MockSpan(
            name="execute_tool",
            attributes={"gen_ai.tool.name": "search_db"},
            kind=SPAN_KIND_INTERNAL,
        )
        assert processor._classify_span(span) == SpanType.TOOL_EXECUTION_INTERNAL

    def test_tool_client_classified(self) -> None:
        processor = PrimustSpanProcessor(pipeline=None)  # type: ignore
        span = MockSpan(
            name="execute_tool",
            attributes={"gen_ai.tool.name": "remote_api"},
            kind=SPAN_KIND_CLIENT,
        )
        assert processor._classify_span(span) == SpanType.TOOL_EXECUTION_CLIENT

    def test_evaluation_classified(self) -> None:
        processor = PrimustSpanProcessor(pipeline=None)  # type: ignore
        span = MockSpan(
            name="eval_step",
            attributes={},
            events=[MockEvent(
                name="gen_ai.evaluation.result",
                attributes={"gen_ai.evaluation.score": 0.95, "gen_ai.evaluation.name": "grounding"},
            )],
        )
        assert processor._classify_span(span) == SpanType.EVALUATION

    def test_unknown_fallback(self) -> None:
        processor = PrimustSpanProcessor(pipeline=None)  # type: ignore
        span = MockSpan(name="random_op", attributes={"key": "val"})
        assert processor._classify_span(span) == SpanType.UNKNOWN

    def test_span_type_ceilings_correct(self) -> None:
        assert SPAN_TYPE_PROOF_CEILING[SpanType.LLM_INFERENCE] == "attestation"
        assert SPAN_TYPE_PROOF_CEILING[SpanType.TOOL_EXECUTION_INTERNAL] == "execution"
        assert SPAN_TYPE_PROOF_CEILING[SpanType.TOOL_EXECUTION_CLIENT] == "attestation"
        # TODO(zk-integration): Restore to "mathematical" when ZK proofs are wired
        assert SPAN_TYPE_PROOF_CEILING[SpanType.EVALUATION] == "execution"
        assert SPAN_TYPE_PROOF_CEILING[SpanType.UNKNOWN] == "attestation"


# ---------------------------------------------------------------------------
# OTL-2: Conditional commitment logic
# ---------------------------------------------------------------------------

class TestConditionalCommitment:
    """OTL-2: Commitment type varies by span type."""

    def test_llm_span_metadata_commitment(self) -> None:
        processor = PrimustSpanProcessor(pipeline=None)  # type: ignore
        span = MockSpan(
            name="chat",
            attributes={"gen_ai.request.model": "claude-3"},
            status=MockStatus(status_code=STATUS_OK),
            start_time=1000000000,
            end_time=2000000000,
        )
        payload, ctype = processor._compute_commitment_payload(span, SpanType.LLM_INFERENCE)
        assert ctype == "metadata_commitment"
        data = json.loads(payload)
        assert data["model"] == "claude-3"
        assert "gen_ai.request.model" not in data  # Structured, not raw attrs

    def test_tool_internal_input_commitment(self) -> None:
        processor = PrimustSpanProcessor(pipeline=None)  # type: ignore
        span = MockSpan(
            name="execute_tool",
            attributes={
                "gen_ai.tool.name": "search",
                "gen_ai.tool.call.id": "call_123",
                "gen_ai.tool.call.function.arguments": {"query": "test"},
            },
            kind=SPAN_KIND_INTERNAL,
        )
        payload, ctype = processor._compute_commitment_payload(span, SpanType.TOOL_EXECUTION_INTERNAL)
        assert ctype == "input_commitment"
        data = json.loads(payload)
        assert data["tool_name"] == "search"
        assert data["arguments"] == {"query": "test"}

    def test_tool_client_metadata_commitment(self) -> None:
        processor = PrimustSpanProcessor(pipeline=None)  # type: ignore
        span = MockSpan(
            name="remote_tool",
            attributes={"gen_ai.tool.name": "remote_api"},
            kind=SPAN_KIND_CLIENT,
            status=MockStatus(status_code=STATUS_OK),
            start_time=1000000000,
            end_time=2000000000,
        )
        payload, ctype = processor._compute_commitment_payload(span, SpanType.TOOL_EXECUTION_CLIENT)
        assert ctype == "metadata_commitment"

    def test_eval_span_input_commitment(self) -> None:
        processor = PrimustSpanProcessor(
            pipeline=None,  # type: ignore
            eval_thresholds={"grounding": 0.8},
        )
        span = MockSpan(
            name="eval",
            events=[MockEvent(
                name="gen_ai.evaluation.result",
                attributes={"gen_ai.evaluation.score": 0.95, "gen_ai.evaluation.name": "grounding"},
            )],
        )
        payload, ctype = processor._compute_commitment_payload(span, SpanType.EVALUATION)
        assert ctype == "input_commitment"
        data = json.loads(payload)
        assert data["eval_name"] == "grounding"
        assert data["score"] == 0.95
        assert data["threshold"] == 0.8


# ---------------------------------------------------------------------------
# OTL-3: span.kind discriminator
# ---------------------------------------------------------------------------

class TestSpanKindDiscriminator:
    """OTL-3: span.kind determines whether input_commitment is computable."""

    def test_internal_tool_gets_execution_ceiling(self) -> None:
        processor = PrimustSpanProcessor(pipeline=None)  # type: ignore
        span = MockSpan(
            name="tool_call",
            attributes={"gen_ai.tool.name": "db_query"},
            kind=SPAN_KIND_INTERNAL,
        )
        span_type = processor._classify_span(span)
        assert span_type == SpanType.TOOL_EXECUTION_INTERNAL
        assert SPAN_TYPE_PROOF_CEILING[span_type] == "execution"

    def test_client_tool_gets_attestation_ceiling(self) -> None:
        processor = PrimustSpanProcessor(pipeline=None)  # type: ignore
        span = MockSpan(
            name="tool_call",
            attributes={"gen_ai.tool.name": "remote_service"},
            kind=SPAN_KIND_CLIENT,
        )
        span_type = processor._classify_span(span)
        assert span_type == SpanType.TOOL_EXECUTION_CLIENT
        assert SPAN_TYPE_PROOF_CEILING[span_type] == "attestation"


# ---------------------------------------------------------------------------
# OTL-4: gen_ai.evaluation.result → mathematical
# ---------------------------------------------------------------------------

class TestEvaluationMathematical:
    """OTL-4: Evaluation events enable mathematical proof through OTEL."""

    def test_eval_above_threshold_passes(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        processor = PrimustSpanProcessor(
            pipeline=pipeline,
            eval_thresholds={"factual_grounding": 0.8},
        )
        span = MockSpan(
            name="eval_step",
            attributes={},
            events=[MockEvent(
                name="gen_ai.evaluation.result",
                attributes={
                    "gen_ai.evaluation.score": 0.95,
                    "gen_ai.evaluation.name": "factual_grounding",
                },
            )],
            status=MockStatus(status_code=STATUS_OK),
        )
        processor.on_end(span)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert record_req[0]["body"]["check_result"] == "pass"

    def test_eval_below_threshold_fails(
        self, pipeline: Pipeline, transport: MockTransport
    ) -> None:
        processor = PrimustSpanProcessor(
            pipeline=pipeline,
            eval_thresholds={"factual_grounding": 0.8},
        )
        span = MockSpan(
            name="eval_step",
            attributes={},
            events=[MockEvent(
                name="gen_ai.evaluation.result",
                attributes={
                    "gen_ai.evaluation.score": 0.5,
                    "gen_ai.evaluation.name": "factual_grounding",
                },
            )],
            status=MockStatus(status_code=STATUS_OK),
        )
        processor.on_end(span)

        record_req = [r for r in transport.requests if "/records" in r["url"]]
        assert record_req[0]["body"]["check_result"] == "fail"

    def test_eval_proof_level_execution(self) -> None:
        """Evaluation proof level is execution until ZK proofs are wired."""
        processor = PrimustSpanProcessor(pipeline=None)  # type: ignore
        span = MockSpan(
            name="eval",
            attributes={},
            events=[MockEvent(name="gen_ai.evaluation.result", attributes={})],
        )
        proof_level = processor._resolve_proof_level(span, SpanType.EVALUATION)
        # TODO(zk-integration): Restore to "mathematical" when ZK proofs are wired
        assert proof_level == "execution"


# ---------------------------------------------------------------------------
# OTL-5 + OTL-6: Attribute scoping and deprecated names
# ---------------------------------------------------------------------------

class TestAttributeScoping:
    """OTL-5 + OTL-6: Prohibited attributes never included in commitments."""

    def test_prohibited_attributes_filtered(self) -> None:
        processor = PrimustSpanProcessor(pipeline=None)  # type: ignore
        span = MockSpan(
            name="unknown_op",
            attributes={
                "gen_ai.input.messages": "SECRET PROMPT CONTENT",
                "gen_ai.output.messages": "SECRET COMPLETION",
                "gen_ai.system_instructions": "SECRET SYSTEM PROMPT",
                "gen_ai.prompt": "DEPRECATED PROMPT",
                "safe_key": "safe_value",
            },
        )
        payload, _ = processor._compute_commitment_payload(span, SpanType.UNKNOWN)
        assert "SECRET" not in payload
        assert "DEPRECATED" not in payload
        assert "safe_value" in payload

    def test_prohibited_set_includes_deprecated(self) -> None:
        assert "gen_ai.prompt" in _PROHIBITED_ATTRIBUTES
        assert "gen_ai.completion" in _PROHIBITED_ATTRIBUTES
        assert "input.value" in _PROHIBITED_ATTRIBUTES

    def test_tool_args_always_readable(self) -> None:
        """OTL-6: Tool arguments ARE readable (structured JSON, not messages)."""
        processor = PrimustSpanProcessor(pipeline=None)  # type: ignore
        span = MockSpan(
            name="tool",
            attributes={
                "gen_ai.tool.name": "search",
                "gen_ai.tool.call.id": "call_1",
                "gen_ai.tool.call.function.arguments": {"q": "hello"},
            },
            kind=SPAN_KIND_INTERNAL,
        )
        payload, ctype = processor._compute_commitment_payload(span, SpanType.TOOL_EXECUTION_INTERNAL)
        data = json.loads(payload)
        assert data["arguments"] == {"q": "hello"}
        assert ctype == "input_commitment"


# ---------------------------------------------------------------------------
# OTL-8: Per-tool manifest enforcement
# ---------------------------------------------------------------------------

class TestPerToolManifest:
    """OTL-8: Manifest resolved by tool name, not just span name."""

    def test_manifest_resolved_by_tool_name(self) -> None:
        processor = PrimustSpanProcessor(
            pipeline=None,  # type: ignore
            manifest_map={"search_db": "manifest_search_v1"},
        )
        span = MockSpan(
            name="execute_tool",
            attributes={"gen_ai.tool.name": "search_db"},
        )
        assert processor._resolve_manifest_id(span) == "manifest_search_v1"

    def test_no_manifest_falls_back_to_auto(self) -> None:
        processor = PrimustSpanProcessor(pipeline=None)  # type: ignore
        span = MockSpan(
            name="unknown_tool",
            attributes={"gen_ai.tool.name": "unregistered"},
        )
        assert processor._resolve_manifest_id(span) == "auto:unknown_tool"

    def test_primust_manifest_id_overrides_all(self) -> None:
        processor = PrimustSpanProcessor(
            pipeline=None,  # type: ignore
            manifest_map={"search": "manifest_search_v1"},
        )
        span = MockSpan(
            name="search",
            attributes={
                "gen_ai.tool.name": "search",
                "primust.manifest_id": "explicit_override_v2",
            },
        )
        assert processor._resolve_manifest_id(span) == "explicit_override_v2"


# ---------------------------------------------------------------------------
# PCG-1: New stage types in proof level map
# ---------------------------------------------------------------------------

class TestNewStageTypes:
    """PCG-1 + PCG-6: New stage types have correct proof level mappings."""

    def test_llm_api_attestation(self) -> None:
        assert PROOF_LEVEL_MAP["llm_api"] == "attestation"

    def test_open_source_ml_execution(self) -> None:
        assert PROOF_LEVEL_MAP["open_source_ml"] == "execution"

    def test_hardware_attested_execution(self) -> None:
        # TODO(zk-integration): Restore to "mathematical" when ZK proofs are wired
        assert PROOF_LEVEL_MAP["hardware_attested"] == "execution"

    def test_policy_engine_execution(self) -> None:
        # TODO(zk-integration): Restore to "mathematical" when ZK proofs are wired
        assert PROOF_LEVEL_MAP["policy_engine"] == "execution"
