"""
Primust Pydantic AI adapter — RunContext dependency injection + instrument_agent().

Privacy invariant: raw tool input/output NEVER leaves the customer environment.
Only commitment hashes (poseidon2) transit to the Primust API.

Usage (Option A — decorator instrumentation):
    from primust.adapters.pydantic_ai import PrimustPydanticAIDep, instrument_agent

    primust_dep = PrimustPydanticAIDep(
        pipeline=p,
        manifest_map={"search_web": "manifest_search_v2"}
    )
    agent = instrument_agent(agent=your_agent, primust_dep=primust_dep)
    result = await agent.run(user_query, deps=primust_dep)
    vpec = p.close()

Usage (Option B — explicit tool instrumentation):
    @your_agent.tool
    async def search_web(ctx: RunContext[PrimustPydanticAIDep], query: str) -> str:
        async with ctx.deps.record_tool("search_web", input=query) as record:
            result = await actual_search(query)
            record.set_output(result)
        return result

Surface declaration:
  surface_type: in_process_adapter
  surface_name: pydantic_ai_tool_hooks
  observation_mode: post_action_realtime
  scope_type: full_workflow
  proof_ceiling: execution
"""

from __future__ import annotations

import functools
import logging
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Generator

from primust import Pipeline, CheckSession

logger = logging.getLogger("primust.pydantic_ai")

SURFACE_DECLARATION = {
    "surface_type": "in_process_adapter",
    "surface_name": "pydantic_ai_tool_hooks",
    "observation_mode": "post_action_realtime",
    "scope_type": "full_workflow",
    "proof_ceiling": "execution",
    "surface_coverage_statement": (
        "All Pydantic AI tool calls observed via RunContext dependency injection. "
        "Model calls (LLM inference) observed at attestation level. "
        "Logic outside decorated tool functions is not observed."
    ),
}


@dataclass
class RecordContext:
    """Context manager helper for recording tool execution."""

    session: CheckSession
    pipeline: Pipeline
    tool_name: str
    input_data: Any
    _output: Any = None
    _has_output: bool = False

    def set_output(self, output: Any) -> None:
        self._output = output
        self._has_output = True


class PrimustPydanticAIDep:
    """
    Pydantic AI compatible dependency for Primust governance.

    Injected via deps= at agent.run() time.
    NEVER stored as a module-level singleton — one dep instance per pipeline run.
    """

    def __init__(
        self,
        pipeline: Pipeline,
        manifest_map: dict[str, str] | None = None,
    ) -> None:
        self.pipeline = pipeline
        self.manifest_map = manifest_map or {}

    @contextmanager
    def record_tool(
        self, tool_name: str, input: Any = None  # noqa: A002
    ) -> Generator[RecordContext, None, None]:
        """
        Context manager for explicit tool instrumentation (Option B).

        Usage:
            async with ctx.deps.record_tool("search", input=query) as record:
                result = await actual_search(query)
                record.set_output(result)
        """
        manifest_id = self.manifest_map.get(tool_name, f"auto:{tool_name}")
        session = self.pipeline.open_check(tool_name, manifest_id)

        ctx = RecordContext(
            session=session,
            pipeline=self.pipeline,
            tool_name=tool_name,
            input_data=input,
        )

        try:
            yield ctx
        except Exception as exc:
            try:
                self.pipeline.record(
                    session,
                    input=input,
                    check_result="error",
                )
            except Exception:
                logger.exception("Failed to record error for %s", tool_name)
            raise exc
        else:
            record_kwargs: dict[str, Any] = {}
            if ctx._has_output:
                record_kwargs["output"] = ctx._output
            try:
                self.pipeline.record(
                    session,
                    input=input,
                    check_result="pass",
                    **record_kwargs,
                )
            except Exception:
                logger.exception("Failed to record result for %s", tool_name)

    def get_surface_declaration(self) -> dict[str, str]:
        return dict(SURFACE_DECLARATION)


def instrument_agent(
    agent: Any,
    primust_dep: PrimustPydanticAIDep,
) -> Any:
    """
    Wrap all @agent.tool decorated functions with Primust instrumentation (Option A).

    Non-invasive. Falls back gracefully if tool signature is not inspectable.
    NEVER modifies agent behavior — purely observational wrapper.
    """
    if not hasattr(agent, "_function_tools"):
        # Try alternative attribute names
        tools_attr = None
        for attr in ("_function_tools", "tools", "_tools"):
            if hasattr(agent, attr):
                tools_attr = attr
                break
        if tools_attr is None:
            logger.warning("Cannot find tools on agent %s — skipping instrumentation", type(agent))
            return agent
    else:
        tools_attr = "_function_tools"

    tools = getattr(agent, tools_attr)

    if isinstance(tools, dict):
        for tool_name, tool_obj in tools.items():
            if hasattr(tool_obj, "function") and callable(tool_obj.function):
                original_fn = tool_obj.function
                tool_obj.function = _wrap_tool_fn(
                    tool_name, original_fn, primust_dep
                )
    elif isinstance(tools, (list, tuple)):
        for i, tool_obj in enumerate(tools):
            if callable(tool_obj):
                name = getattr(tool_obj, "__name__", f"tool_{i}")
                tools[i] = _wrap_tool_fn(name, tool_obj, primust_dep)

    return agent


def _wrap_tool_fn(
    tool_name: str,
    tool_fn: Callable[..., Any],
    dep: PrimustPydanticAIDep,
) -> Callable[..., Any]:
    """Wrap a tool function with Primust record instrumentation."""

    @functools.wraps(tool_fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        manifest_id = dep.manifest_map.get(tool_name, f"auto:{tool_name}")
        session: CheckSession | None = None
        try:
            session = dep.pipeline.open_check(tool_name, manifest_id)
        except Exception:
            logger.exception("Failed to open check for %s", tool_name)

        try:
            result = tool_fn(*args, **kwargs)
        except Exception as exc:
            if session:
                try:
                    dep.pipeline.record(
                        session,
                        input=_extract_input(args, kwargs),
                        check_result="error",
                    )
                except Exception:
                    logger.exception("Failed to record error for %s", tool_name)
            raise exc

        if session:
            try:
                dep.pipeline.record(
                    session,
                    input=_extract_input(args, kwargs),
                    check_result="pass",
                    output=result,
                )
            except Exception:
                logger.exception("Failed to record result for %s", tool_name)

        return result

    return wrapper


def _extract_input(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    if kwargs:
        return kwargs
    if len(args) == 1:
        return args[0]
    return list(args)
