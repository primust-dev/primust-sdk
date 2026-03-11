"""
Primust OpenTelemetry Span Processor adapter.

Maps OTEL spans to Primust CheckExecutionRecords.
commitment_hash = poseidon2(canonical(span.attributes)) — never raw span data.

Surface declaration:
  surface_type: middleware_interceptor
  observation_mode: post_action_realtime
  scope_type: orchestration_boundary
  proof_ceiling: attestation (witnessed when human_review span)

Covers passively: LangChain, AutoGen, Semantic Kernel (Python), smolagents,
Haystack, Vertex AI, Amazon Bedrock, CrewAI (partial).
"""

from __future__ import annotations

import json
import logging
from typing import Any, Protocol

from primust import Pipeline

logger = logging.getLogger("primust.otel")

PROOF_LEVEL_MAP = {
    "deterministic_rule": "mathematical",
    "zkml_model": "execution_zkml",
    "ml_model": "execution",
    "human_review": "witnessed",
    "default": "attestation",
}

SURFACE_DECLARATION = {
    "surface_type": "middleware_interceptor",
    "surface_name": "otel_span_processor",
    "observation_mode": "post_action_realtime",
    "scope_type": "orchestration_boundary",
    "proof_ceiling": "attestation",
    "surface_coverage_statement": (
        "All OTEL-instrumented spans processed via SpanProcessor.on_end(). "
        "Provides attestation-level coverage for LangChain, AutoGen, Semantic Kernel, "
        "smolagents, Haystack, Vertex AI, Amazon Bedrock, CrewAI. "
        "Spans without OTEL instrumentation are not observed."
    ),
}

# OTEL StatusCode values
STATUS_OK = 1
STATUS_ERROR = 2
STATUS_UNSET = 0


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


class PrimustSpanProcessor:
    """
    OpenTelemetry SpanProcessor that maps completed spans to Primust records.

    Implements the SpanProcessor interface:
      on_start(span, parent_context) — no-op
      on_end(span) — maps span to p.record()
      shutdown() — no-op
      force_flush() — no-op
    """

    def __init__(
        self,
        pipeline: Pipeline,
        manifest_map: dict[str, str] | None = None,
    ) -> None:
        self.pipeline = pipeline
        self.manifest_map = manifest_map or {}

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

    def _process_span(self, span: ReadableSpan) -> None:
        attrs = dict(span.attributes or {})

        manifest_id = str(attrs.get("primust.manifest_id", self.manifest_map.get(span.name, f"auto:{span.name}")))
        process_context_hash = attrs.get("primust.process_context_hash")

        # Map status code to check_result
        status_code = getattr(span.status, "status_code", STATUS_UNSET) if span.status else STATUS_UNSET
        if status_code == STATUS_OK:
            check_result = "pass"
        elif status_code == STATUS_ERROR:
            check_result = "fail"
        else:
            check_result = "degraded"

        # Determine proof level
        stage_type = str(attrs.get("primust.stage_type", "default"))
        proof_level = PROOF_LEVEL_MAP.get(stage_type, "attestation")

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
            input=_attrs_to_canonical(attrs),
            check_result=check_result,
            output=output,
        )

    def get_surface_declaration(self) -> dict[str, str]:
        return dict(SURFACE_DECLARATION)


def _attrs_to_canonical(attrs: dict[str, Any]) -> str:
    """Canonical JSON representation of span attributes for commitment."""
    return json.dumps(attrs, sort_keys=True, separators=(",", ":"))


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
