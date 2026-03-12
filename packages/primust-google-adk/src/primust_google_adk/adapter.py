"""
Primust Google ADK adapter — instruments agent tool/action execution.

Privacy invariant: raw tool input/output NEVER leaves the customer environment.
Only commitment hashes (poseidon2) transit to the Primust API.

Surface declaration:
  surface_type: in_process_adapter
  observation_mode: post_action_realtime
  scope_type: orchestration_boundary
  proof_ceiling: execution
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable

from primust import Pipeline, CheckSession

logger = logging.getLogger("primust.google_adk")

PROOF_LEVEL_MAP = {
    "deterministic_rule": "mathematical",
    "zkml_model": "execution_zkml",
    "ml_model": "execution",
    "human_review": "witnessed",
    "default": "attestation",
}

SURFACE_DECLARATION = {
    "surface_type": "in_process_adapter",
    "surface_name": "google_adk_tool_hooks",
    "observation_mode": "post_action_realtime",
    "scope_type": "orchestration_boundary",
    "proof_ceiling": "execution",
    "surface_coverage_statement": (
        "All Google ADK tool/action executions observed via agent orchestration hooks. "
        "Actions outside the ADK agent boundary are not observed."
    ),
}


class PrimustGoogleADK:
    """Wraps a Google ADK Agent. Instruments all tool/action executions."""

    def __init__(
        self,
        pipeline: Pipeline,
        manifest_map: dict[str, str] | None = None,
    ) -> None:
        self.pipeline = pipeline
        self.manifest_map = manifest_map or {}

    def wrap(self, agent: Any) -> Any:
        """
        Instrument a Google ADK Agent by wrapping its tool functions.

        Returns the same agent with instrumented tool calls.
        """
        if hasattr(agent, "tools"):
            wrapped_tools = {}
            for check_label, tool_fn in agent.tools.items():
                wrapped_tools[check_label] = self._wrap_tool(check_label, tool_fn)
            agent.tools = wrapped_tools
        return agent

    def wrap_tool(self, check_label: str, tool_fn: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap a single tool function with Primust instrumentation."""
        return self._wrap_tool(check_label, tool_fn)

    def _wrap_tool(self, check_label: str, tool_fn: Callable[..., Any]) -> Callable[..., Any]:
        adapter = self

        @functools.wraps(tool_fn)
        def instrumented(*args: Any, **kwargs: Any) -> Any:
            manifest_id = adapter.manifest_map.get(check_label, f"auto:{check_label}")
            session: CheckSession | None = None
            try:
                session = adapter.pipeline.open_check(check_label, manifest_id)
            except Exception:
                logger.exception("Failed to open check for %s", check_label)

            try:
                result = tool_fn(*args, **kwargs)
            except Exception as exc:
                if session:
                    try:
                        adapter.pipeline.record(
                            session,
                            input=_extract_input(args, kwargs),
                            check_result="error",
                        )
                    except Exception:
                        logger.exception("Failed to record error for %s", check_label)
                raise exc

            if session:
                try:
                    adapter.pipeline.record(
                        session,
                        input=_extract_input(args, kwargs),
                        check_result="pass",
                        output=result,
                    )
                except Exception:
                    logger.exception("Failed to record result for %s", check_label)

            return result

        return instrumented

    def get_surface_declaration(self) -> dict[str, str]:
        return dict(SURFACE_DECLARATION)


def _extract_input(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    if kwargs:
        return kwargs
    if len(args) == 1:
        return args[0]
    return list(args)
