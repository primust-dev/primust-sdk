"""
Primust OpenTelemetry Span Processor adapter.

Maps OTEL spans to Primust CheckExecutionRecords with span-type-aware
proof ceilings, conditional commitment logic, and attribute scoping.

Per-span-type proof ceilings (OTL-1):
  LLM inference spans    → attestation (gen_ai.request.model is a name string)
  Tool execution INTERNAL → execution (input_commitment computable locally)
  Tool execution CLIENT   → attestation (crosses process boundary)
  Evaluation result spans → execution (mathematical when ZK proofs are wired)
  Unknown                 → attestation (fallback)

span.kind is the proof-level discriminator (OTL-3):
  INTERNAL → eligible for input_commitment → execution ceiling
  CLIENT   → metadata_commitment only → attestation ceiling

Attribute reading rules (OTL-6):
  NEVER read: gen_ai.input.messages, gen_ai.output.messages, gen_ai.system_instructions
  ALWAYS read: gen_ai.tool.name, gen_ai.tool.call.id, gen_ai.tool.call.function.arguments,
               gen_ai.evaluation.result events

MCP tool spans (OTL-7):
  In-process MCP clients emit standard gen_ai.execute_tool spans with INTERNAL kind.
  No MCP-specific code needed — classified as TOOL_EXECUTION_INTERNAL automatically.

Surface declaration:
  surface_type: middleware_interceptor
  observation_mode: post_action_realtime
  scope_type: orchestration_boundary
  proof_ceiling: execution (tool spans), attestation (LLM spans)

Covers passively: LangChain, AutoGen, Semantic Kernel (Python), smolagents,
Haystack, Vertex AI, Amazon Bedrock, CrewAI (partial), MCP clients.
"""

from __future__ import annotations

import json
import logging
from enum import Enum
from typing import Any, Protocol

from primust import Pipeline

logger = logging.getLogger("primust.otel")


# ---------------------------------------------------------------------------
# Span type classification (OTL-1, OTL-3)
# ---------------------------------------------------------------------------

class SpanType(Enum):
    LLM_INFERENCE = "llm_inference"
    TOOL_EXECUTION_INTERNAL = "tool_execution_internal"
    TOOL_EXECUTION_CLIENT = "tool_execution_client"
    EVALUATION = "evaluation"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Proof level mapping — includes PCG-1, PCG-6 new stage types
# ---------------------------------------------------------------------------

PROOF_LEVEL_MAP = {
    "deterministic_rule": "mathematical",
    "policy_engine": "mathematical",
    "hardware_attested": "mathematical",
    "zkml_model": "verifiable_inference",
    "ml_model": "execution",
    "open_source_ml": "execution",
    "statistical_test": "execution",
    "custom_code": "execution",
    "witnessed": "witnessed",
    "llm_api": "attestation",
    "default": "attestation",
}

# Per-span-type proof ceilings (OTL-1)
SPAN_TYPE_PROOF_CEILING = {
    SpanType.LLM_INFERENCE: "attestation",
    SpanType.TOOL_EXECUTION_INTERNAL: "execution",
    SpanType.TOOL_EXECUTION_CLIENT: "attestation",
    SpanType.EVALUATION: "mathematical",
    SpanType.UNKNOWN: "attestation",
}

_PROOF_RANK = {
    "mathematical": 0,
    "verifiable_inference": 1,
    "execution": 2,
    "witnessed": 3,
    "attestation": 4,
}


def _proof_rank(level: str) -> int:
    """Lower rank = stronger proof. Used for ceiling enforcement."""
    return _PROOF_RANK.get(level, 4)


SURFACE_DECLARATION = {
    "surface_type": "middleware_interceptor",
    "surface_name": "otel_span_processor",
    "observation_mode": "post_action_realtime",
    "scope_type": "orchestration_boundary",
    "proof_ceiling": "execution",
    "surface_coverage_statement": (
        "All OTEL-instrumented spans processed via SpanProcessor.on_end(). "
        "Tool execution spans (INTERNAL kind) achieve execution-level proof. "
        "LLM inference spans achieve attestation-level proof. "
        "gen_ai.evaluation.result events achieve execution-level proof "
        "(upgradeable to mathematical when ZK proofs are wired). "
        "Covers LangChain, AutoGen, Semantic Kernel, smolagents, Haystack, "
        "Vertex AI, Amazon Bedrock, CrewAI, MCP clients."
    ),
}

# Attributes that MUST NEVER be included in commitments (OTL-6)
_PROHIBITED_ATTRIBUTES = frozenset({
    "gen_ai.input.messages",
    "gen_ai.output.messages",
    "gen_ai.system_instructions",
    # Deprecated names (OTL-5) — filter out if present
    "gen_ai.prompt",
    "gen_ai.completion",
    "input.value",
})

# OTEL StatusCode values
STATUS_OK = 1
STATUS_ERROR = 2
STATUS_UNSET = 0

# OTEL SpanKind values
SPAN_KIND_INTERNAL = 0
SPAN_KIND_SERVER = 1
SPAN_KIND_CLIENT = 2
SPAN_KIND_PRODUCER = 3
SPAN_KIND_CONSUMER = 4


class ReadableSpan(Protocol):
    """Protocol matching opentelemetry.sdk.trace.ReadableSpan."""

    @property
    def name(self) -> str: ...

    @property
    def attributes(self) -> dict[str, Any] | None: ...

    @property
    def events(self) -> list[Any] | None: ...

    @property
    def status(self) -> Any: ...

    @property
    def start_time(self) -> int | None: ...

    @property
    def end_time(self) -> int | None: ...

    @property
    def kind(self) -> int | None: ...


class PrimustSpanProcessor:
    """
    OpenTelemetry SpanProcessor that maps completed spans to Primust records.

    Implements the SpanProcessor interface:
      on_start(span, parent_context) — no-op
      on_end(span) — classifies span, computes commitment, records to Pipeline
      shutdown() — no-op
      force_flush() — no-op
    """

    def __init__(
        self,
        pipeline: Pipeline,
        manifest_map: dict[str, str] | None = None,
        eval_thresholds: dict[str, float] | None = None,
    ) -> None:
        self.pipeline = pipeline
        self.manifest_map = manifest_map or {}
        self.eval_thresholds = eval_thresholds or {}

    def on_start(self, span: Any, parent_context: Any = None) -> None:
        pass

    def on_end(self, span: ReadableSpan) -> None:
        try:
            self._process_span(span)
        except Exception:
            logger.exception("Failed to process span %s", span.name)

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True

    def _classify_span(self, span: ReadableSpan) -> SpanType:
        """Classify span type for proof level determination (OTL-1, OTL-3)."""
        attrs = span.attributes or {}
        kind = getattr(span, "kind", None)

        # Check for evaluation events first (OTL-4)
        if span.events:
            for event in span.events:
                if getattr(event, "name", "") == "gen_ai.evaluation.result":
                    return SpanType.EVALUATION

        # Tool execution spans (OTL-3: span.kind discriminates INTERNAL vs CLIENT)
        name_lower = span.name.lower()
        has_tool_name = "gen_ai.tool.name" in attrs
        is_tool_span = has_tool_name or "tool" in name_lower or "execute" in name_lower

        if is_tool_span:
            if kind == SPAN_KIND_CLIENT:
                return SpanType.TOOL_EXECUTION_CLIENT
            # INTERNAL or unset kind with tool attributes → INTERNAL
            if has_tool_name:
                return SpanType.TOOL_EXECUTION_INTERNAL

        # LLM inference spans
        if attrs.get("gen_ai.request.model"):
            return SpanType.LLM_INFERENCE

        return SpanType.UNKNOWN

    def _compute_commitment_payload(
        self, span: ReadableSpan, span_type: SpanType
    ) -> tuple[str, str]:
        """
        Compute commitment payload and type based on span classification (OTL-2).

        Returns (canonical_json, commitment_type).
        """
        attrs = span.attributes or {}

        if span_type == SpanType.LLM_INFERENCE:
            # Metadata commitment — only safe fields (OTL-2, OTL-6)
            payload = {
                "span_name": span.name,
                "model": str(attrs.get("gen_ai.request.model", "unknown")),
                "duration_ms": _duration_ms(span),
                "status": _status_name(span),
            }
            return json.dumps(payload, sort_keys=True, separators=(",", ":")), "metadata_commitment"

        elif span_type == SpanType.TOOL_EXECUTION_INTERNAL:
            # Input commitment — structured tool arguments (OTL-2, OTL-6)
            payload = {
                "tool_name": str(attrs.get("gen_ai.tool.name", span.name)),
                "action_unit_id": str(attrs.get("gen_ai.tool.call.id", "")),
                "arguments": attrs.get("gen_ai.tool.call.function.arguments", {}),
            }
            return json.dumps(payload, sort_keys=True, separators=(",", ":")), "input_commitment"

        elif span_type == SpanType.TOOL_EXECUTION_CLIENT:
            # Metadata commitment only — crosses process boundary (OTL-3)
            payload = {
                "span_name": span.name,
                "tool_name": str(attrs.get("gen_ai.tool.name", span.name)),
                "duration_ms": _duration_ms(span),
                "status": _status_name(span),
            }
            return json.dumps(payload, sort_keys=True, separators=(",", ":")), "metadata_commitment"

        elif span_type == SpanType.EVALUATION:
            # Input commitment over evaluation data (OTL-4)
            eval_data = self._extract_eval_data(span)
            return json.dumps(eval_data, sort_keys=True, separators=(",", ":")), "input_commitment"

        else:
            # Unknown — filter prohibited attributes, commit the rest (OTL-6)
            safe_attrs = {
                k: v for k, v in attrs.items()
                if k not in _PROHIBITED_ATTRIBUTES
            }
            return json.dumps(safe_attrs, sort_keys=True, separators=(",", ":")), "metadata_commitment"

    def _extract_eval_data(self, span: ReadableSpan) -> dict[str, Any]:
        """Extract evaluation event data for mathematical proof (OTL-4)."""
        for event in (span.events or []):
            if getattr(event, "name", "") == "gen_ai.evaluation.result":
                event_attrs = dict(getattr(event, "attributes", {}) or {})
                eval_name = str(event_attrs.get("gen_ai.evaluation.name", ""))
                score = event_attrs.get("gen_ai.evaluation.score")
                threshold = self.eval_thresholds.get(eval_name)
                return {
                    "eval_name": eval_name,
                    "score": score,
                    "threshold": threshold,
                }
        return {"span_name": span.name}

    def _resolve_proof_level(
        self, span: ReadableSpan, span_type: SpanType
    ) -> str:
        """
        Resolve proof level from stage_type attribute or span type ceiling.

        Stage type from primust.stage_type attribute takes precedence if set,
        but is capped by the span type ceiling.
        """
        attrs = span.attributes or {}
        ceiling = SPAN_TYPE_PROOF_CEILING.get(span_type, "attestation")

        stage_type = str(attrs.get("primust.stage_type", ""))
        if stage_type and stage_type in PROOF_LEVEL_MAP:
            mapped = PROOF_LEVEL_MAP[stage_type]
            # Enforce ceiling cap — mapped level cannot exceed span type ceiling
            if _proof_rank(mapped) < _proof_rank(ceiling):
                return mapped
            return ceiling

        return ceiling

    def _resolve_manifest_id(self, span: ReadableSpan) -> str:
        """
        Resolve manifest ID from span attribute, tool name, or manifest_map (OTL-8).

        Priority: primust.manifest_id attr > manifest_map[tool_name] > manifest_map[span.name] > auto
        """
        attrs = span.attributes or {}

        # Explicit override
        if "primust.manifest_id" in attrs:
            return str(attrs["primust.manifest_id"])

        # Per-tool manifest (OTL-8)
        tool_name = str(attrs.get("gen_ai.tool.name", ""))
        if tool_name and tool_name in self.manifest_map:
            return self.manifest_map[tool_name]

        # Span name fallback
        if span.name in self.manifest_map:
            return self.manifest_map[span.name]

        return f"auto:{span.name}"

    def _process_span(self, span: ReadableSpan) -> None:
        attrs = dict(span.attributes or {})

        span_type = self._classify_span(span)
        manifest_id = self._resolve_manifest_id(span)

        # Map status code to check_result
        status_code = getattr(span.status, "status_code", STATUS_UNSET) if span.status else STATUS_UNSET
        if span_type == SpanType.EVALUATION:
            # For eval spans, derive check_result from score vs threshold (OTL-4)
            eval_data = self._extract_eval_data(span)
            score = eval_data.get("score")
            threshold = eval_data.get("threshold")
            if score is not None and threshold is not None:
                check_result = "pass" if score >= threshold else "fail"
            elif status_code == STATUS_OK:
                check_result = "pass"
            elif status_code == STATUS_ERROR:
                check_result = "fail"
            else:
                check_result = "degraded"
        elif status_code == STATUS_OK:
            check_result = "pass"
        elif status_code == STATUS_ERROR:
            check_result = "fail"
        else:
            check_result = "degraded"

        # Compute commitment (OTL-2)
        input_canonical, commitment_type = self._compute_commitment_payload(span, span_type)

        # Resolve proof level
        proof_level = self._resolve_proof_level(span, span_type)

        # Open check and record
        session = self.pipeline.open_check(span.name, manifest_id)

        # Override timestamps from span if available
        if span.start_time is not None:
            session.check_open_tst = _ns_to_iso(span.start_time)

        # Build output from events if present
        output = None
        if span.events:
            output = [_event_to_dict(e) for e in span.events]

        self.pipeline.record(
            session,
            input=input_canonical,
            check_result=check_result,
            output=output,
        )

    def get_surface_declaration(self) -> dict[str, str]:
        return dict(SURFACE_DECLARATION)


def _duration_ms(span: ReadableSpan) -> float:
    """Compute span duration in milliseconds."""
    start = span.start_time
    end = span.end_time
    if start is not None and end is not None:
        return (end - start) / 1e6
    return 0.0


def _status_name(span: ReadableSpan) -> str:
    """Get status name from span."""
    status_code = getattr(span.status, "status_code", STATUS_UNSET) if span.status else STATUS_UNSET
    if status_code == STATUS_OK:
        return "OK"
    elif status_code == STATUS_ERROR:
        return "ERROR"
    return "UNSET"


def _ns_to_iso(ns: int) -> str:
    """Convert nanosecond timestamp to ISO 8601 string."""
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).isoformat()


def _event_to_dict(event: Any) -> dict[str, Any]:
    """Convert a span event to a dictionary."""
    return {
        "name": getattr(event, "name", ""),
        "timestamp": getattr(event, "timestamp", None),
        "attributes": dict(getattr(event, "attributes", {}) or {}),
    }
