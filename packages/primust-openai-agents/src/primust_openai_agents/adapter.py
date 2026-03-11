"""
Primust OpenAI Agents SDK adapter — instruments agent tool calls.

Privacy invariant: raw tool input/output NEVER leaves the customer environment.
Only commitment hashes (poseidon2) transit to the Primust API.

Surface declaration:
  surface_type: in_process_adapter
  observation_mode: post_action_realtime
  scope_type: full_workflow
  proof_ceiling: execution
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable

from primust import Pipeline, CheckSession

logger = logging.getLogger("primust.openai_agents")

PROOF_LEVEL_MAP = {
    "deterministic_rule": "mathematical",
    "zkml_model": "execution_zkml",
    "ml_model": "execution",
    "human_review": "witnessed",
    "default": "attestation",
}

SURFACE_DECLARATION = {
    "surface_type": "in_process_adapter",
    "surface_name": "openai_agents_tool_hooks",
    "observation_mode": "post_action_realtime",
    "scope_type": "full_workflow",
    "proof_ceiling": "execution",
    "surface_coverage_statement": (
        "All OpenAI Agents SDK tool invocations observed via tool lifecycle hooks. "
        "Actions outside the agent tool invocation lifecycle are not observed."
    ),
}


class PrimustOpenAIAgents:
    """Wraps an OpenAI Agents SDK agent. Instruments all tool invocations."""

    def __init__(
        self,
        pipeline: Pipeline,
        manifest_map: dict[str, str] | None = None,
    ) -> None:
        self.pipeline = pipeline
        self.manifest_map = manifest_map or {}

    def wrap(self, agent: Any) -> Any:
        """
        Instrument an OpenAI Agent by wrapping its tool functions.

        Returns the same agent with instrumented tool calls.
        """
        if hasattr(agent, "tools"):
            for i, tool in enumerate(agent.tools):
                if hasattr(tool, "function") and callable(tool.function):
                    name = getattr(tool, "name", f"tool_{i}")
                    tool.function = self._wrap_fn(name, tool.function)
                elif callable(tool):
                    name = getattr(tool, "__name__", f"tool_{i}")
                    agent.tools[i] = self._wrap_fn(name, tool)
        return agent

    def wrap_tool(self, tool_name: str, tool_fn: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap a single tool function with Primust instrumentation."""
        return self._wrap_fn(tool_name, tool_fn)

    def _wrap_fn(self, tool_name: str, tool_fn: Callable[..., Any]) -> Callable[..., Any]:
        adapter = self

        @functools.wraps(tool_fn)
        def instrumented(*args: Any, **kwargs: Any) -> Any:
            manifest_id = adapter.manifest_map.get(tool_name, f"auto:{tool_name}")
            session: CheckSession | None = None
            try:
                session = adapter.pipeline.open_check(tool_name, manifest_id)
            except Exception:
                logger.exception("Failed to open check for %s", tool_name)

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
                        logger.exception("Failed to record error for %s", tool_name)
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
                    logger.exception("Failed to record result for %s", tool_name)

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
