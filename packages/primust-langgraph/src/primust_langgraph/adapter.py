"""
Primust LangGraph adapter — instruments tool calls and node transitions.

Privacy invariant: raw tool input/output NEVER leaves the customer environment.
Only commitment hashes (poseidon2) transit to the Primust API.

Surface declaration:
  surface_type: in_process_adapter
  observation_mode: post_action_realtime
  scope_type: full_workflow
  proof_ceiling: execution (mathematical for deterministic tools)
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable

from primust import Pipeline, CheckSession

logger = logging.getLogger("primust.langgraph")

PROOF_LEVEL_MAP = {
    "deterministic_rule": "mathematical",
    "zkml_model": "execution_zkml",
    "ml_model": "execution",
    "human_review": "witnessed",
    "default": "attestation",
}

SURFACE_DECLARATION = {
    "surface_type": "in_process_adapter",
    "surface_name": "langgraph_tool_hooks",
    "observation_mode": "post_action_realtime",
    "scope_type": "full_workflow",
    "proof_ceiling": "execution",
    "surface_coverage_statement": (
        "All LangGraph tool calls observed via tool execution lifecycle hooks. "
        "Actions outside the LangGraph graph scope are not observed."
    ),
}


class PrimustLangGraph:
    """Wraps a LangGraph graph. Instruments all tool calls and node transitions."""

    def __init__(
        self,
        pipeline: Pipeline,
        manifest_map: dict[str, str] | None = None,
    ) -> None:
        self.pipeline = pipeline
        self.manifest_map = manifest_map or {}

    def wrap(self, graph: Any) -> Any:
        """
        Instrument a LangGraph StateGraph by wrapping its tool nodes.

        Returns the same graph object with instrumented tool calls.
        """
        if hasattr(graph, "nodes"):
            for node_name, node_fn in list(graph.nodes.items()):
                if callable(node_fn):
                    graph.nodes[node_name] = self._wrap_node(node_name, node_fn)
        return graph

    def wrap_tool(self, tool_name: str, tool_fn: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap a single tool function with Primust instrumentation."""
        return self._wrap_node(tool_name, tool_fn)

    def _wrap_node(self, node_name: str, node_fn: Callable[..., Any]) -> Callable[..., Any]:
        adapter = self

        @functools.wraps(node_fn)
        def instrumented(*args: Any, **kwargs: Any) -> Any:
            manifest_id = adapter.manifest_map.get(node_name, f"auto:{node_name}")
            session: CheckSession | None = None
            try:
                session = adapter.pipeline.open_check(node_name, manifest_id)
            except Exception:
                logger.exception("Failed to open check for %s", node_name)

            try:
                result = node_fn(*args, **kwargs)
            except Exception as exc:
                if session:
                    try:
                        adapter.pipeline.record(
                            session,
                            input=_extract_input(args, kwargs),
                            check_result="error",
                        )
                    except Exception:
                        logger.exception("Failed to record error for %s", node_name)
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
                    logger.exception("Failed to record result for %s", node_name)

            return result

        @functools.wraps(node_fn)
        async def instrumented_async(*args: Any, **kwargs: Any) -> Any:
            manifest_id = adapter.manifest_map.get(node_name, f"auto:{node_name}")
            session: CheckSession | None = None
            try:
                session = adapter.pipeline.open_check(node_name, manifest_id)
            except Exception:
                logger.exception("Failed to open check for %s", node_name)

            try:
                result = await node_fn(*args, **kwargs)
            except Exception as exc:
                if session:
                    try:
                        adapter.pipeline.record(
                            session,
                            input=_extract_input(args, kwargs),
                            check_result="error",
                        )
                    except Exception:
                        logger.exception("Failed to record error for %s", node_name)
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
                    logger.exception("Failed to record result for %s", node_name)

            return result

        import asyncio
        if asyncio.iscoroutinefunction(node_fn):
            return instrumented_async
        return instrumented

    def get_surface_declaration(self) -> dict[str, str]:
        return dict(SURFACE_DECLARATION)


def _extract_input(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    """Extract tool input from args/kwargs for commitment hashing."""
    if kwargs:
        return kwargs
    if len(args) == 1:
        return args[0]
    return list(args)
