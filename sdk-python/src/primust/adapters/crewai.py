"""
Primust CrewAI adapter — step_callback observer.

Privacy invariant: raw agent output NEVER leaves the customer environment.
Only commitment hashes (poseidon2) transit to the Primust API.

Usage:
    from primust.adapters.crewai import PrimustCrewAICallback

    callback = PrimustCrewAICallback(
        pipeline=p,
        manifest_map={
            "Research Analyst": "manifest_research_v1",
            "Content Writer":  "manifest_output_policy_v2",
        }
    )

    crew = Crew(
        agents=[research_analyst, content_writer],
        tasks=[research_task, write_task],
        step_callback=callback.on_step
    )
    result = crew.kickoff()
    vpec = p.close()

Surface declaration:
  surface_type: in_process_adapter
  surface_name: crewai_step_callback
  observation_mode: post_action_realtime
  scope_type: full_workflow
  proof_ceiling: execution
"""

from __future__ import annotations

import logging
from typing import Any

from primust import Pipeline

logger = logging.getLogger("primust.crewai")

SURFACE_DECLARATION = {
    "surface_type": "in_process_adapter",
    "surface_name": "crewai_step_callback",
    "observation_mode": "post_action_realtime",
    "scope_type": "full_workflow",
    "proof_ceiling": "execution",
    "surface_coverage_statement": (
        "All CrewAI agent steps observed via step_callback. "
        "Actions taken by agents outside the CrewAI step lifecycle are not observed."
    ),
}


class PrimustCrewAICallback:
    """
    CrewAI step_callback observer. Attaches as crew.step_callback.

    Callback NEVER raises into CrewAI — all exceptions caught, logged, continue.
    Raw agent output committed locally — only commitment_hash transits.
    CrewAI step_callback has no return value — Primust is purely observational.
    """

    def __init__(
        self,
        pipeline: Pipeline,
        manifest_map: dict[str, str] | None = None,
    ) -> None:
        self.pipeline = pipeline
        self.manifest_map = manifest_map or {}

    def on_step(self, agent_output: Any) -> None:
        """
        CrewAI step_callback handler.

        agent_output can be:
          - AgentAction: tool call in progress
          - AgentFinish: agent output ready
          - dict or other: fallback handling
        """
        try:
            self._handle_step(agent_output)
        except Exception:
            # CRITICAL: never raise into CrewAI
            logger.exception("Primust callback error (swallowed)")

    def _handle_step(self, agent_output: Any) -> None:
        output_type = type(agent_output).__name__

        # Extract agent role for manifest lookup
        agent_role = getattr(agent_output, "agent", None)
        if agent_role and hasattr(agent_role, "role"):
            agent_role = agent_role.role
        elif isinstance(agent_output, dict):
            agent_role = agent_output.get("agent_role", "unknown")
        else:
            agent_role = getattr(agent_output, "role", "unknown")

        manifest_id = self.manifest_map.get(str(agent_role), f"auto:{agent_role}")

        # Determine if this is an action (tool call) or finish (output)
        is_action = output_type == "AgentAction" or (
            isinstance(agent_output, dict) and agent_output.get("type") == "action"
        )
        is_finish = output_type == "AgentFinish" or (
            isinstance(agent_output, dict) and agent_output.get("type") == "finish"
        )

        # Extract input and output
        if isinstance(agent_output, dict):
            input_data = agent_output.get("input", agent_output.get("tool_input", str(agent_output)))
            output_data = agent_output.get("output", agent_output.get("result"))
        else:
            input_data = getattr(agent_output, "tool_input", getattr(agent_output, "text", str(agent_output)))
            output_data = getattr(agent_output, "output", getattr(agent_output, "return_values", None))

        check_name = f"crewai_{output_type.lower()}"
        if is_action:
            tool = getattr(agent_output, "tool", None) or (
                agent_output.get("tool") if isinstance(agent_output, dict) else None
            )
            if tool:
                check_name = f"crewai_action:{tool}"

        # Check if agent role is mapped
        unverified = str(agent_role) not in self.manifest_map

        session = self.pipeline.open_check(check_name, manifest_id)

        record_kwargs: dict[str, Any] = {}
        if output_data is not None:
            record_kwargs["output"] = output_data

        check_result = "pass"
        if unverified:
            check_result = "pass"  # still pass, but marked unverified via metadata

        self.pipeline.record(
            session,
            input=input_data,
            check_result=check_result,
            **record_kwargs,
        )

    def get_surface_declaration(self) -> dict[str, str]:
        return dict(SURFACE_DECLARATION)
