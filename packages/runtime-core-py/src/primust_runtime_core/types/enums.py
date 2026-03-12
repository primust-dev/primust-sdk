"""Primust Runtime Core — Enum types for domain-neutral object schemas v4.

Enums already defined in primust_artifact_core (reuse, do not redefine):
  ProofLevel, GapType, GapSeverity, SurfaceType, ObservationMode,
  ScopeType, CommitmentAlgorithm, PolicyBasis, TsaProvider
"""

from __future__ import annotations

from typing import Literal

ManifestDomain = Literal[
    "ai_agent", "cicd", "financial", "pharma", "generic"
]

ImplementationType = Literal[
    "ml_model", "rule", "threshold", "approval_chain", "zkml_model", "custom"
]

StageType = Literal[
    "deterministic_rule",
    "ml_model",
    "zkml_model",
    "statistical_test",
    "custom_code",
    "witnessed",
    "policy_engine",
    "llm_api",
    "open_source_ml",
    "hardware_attested",
]

EvaluationScope = Literal[
    "per_run", "per_action_unit", "per_surface", "per_window"
]

AggregationMethod = Literal[
    "all_stages_must_pass", "worst_case", "threshold_vote", "sequential_gate"
]

CheckResult = Literal[
    "pass", "fail", "error", "skipped", "degraded", "override",
    "not_applicable", "timed_out",
]

GapState = Literal[
    "open", "investigating", "waived", "remediated", "resolved", "escalated"
]

RunState = Literal[
    "open", "closed", "partial", "cancelled", "auto_closed"
]

CommitmentType = Literal[
    "input_commitment", "metadata_commitment", "foreign_event_commitment"
]

KeyBinding = Literal["software", "hardware"]
