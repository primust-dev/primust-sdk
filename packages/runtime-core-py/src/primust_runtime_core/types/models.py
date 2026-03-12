"""Primust Runtime Core — Frozen dataclasses for all 10 canonical objects v4."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from primust_artifact_core.types.artifact import (
    CommitmentAlgorithm,
    GapSeverity,
    GapType,
    ObservationMode,
    PolicyBasis,
    ProofLevel,
    ScopeType,
    SurfaceType,
    TsaProvider,
)

from .enums import (
    AggregationMethod,
    CheckResult,
    CommitmentType,
    EvaluationScope,
    GapState,
    ImplementationType,
    KeyBinding,
    ManifestDomain,
    RunState,
    StageType,
)


# ── Signature envelope reference ──


@dataclass(frozen=True)
class SignatureEnvelopeRef:
    signer_id: str
    kid: str
    algorithm: str  # "Ed25519"
    signature: str  # base64url
    signed_at: str  # ISO 8601


# ── Object 1: ObservationSurface ──


@dataclass(frozen=True)
class ObservationSurface:
    surface_id: str
    org_id: str
    environment: str
    surface_type: SurfaceType
    surface_name: str
    surface_version: str
    observation_mode: ObservationMode
    scope_type: ScopeType
    scope_description: str
    surface_coverage_statement: str
    proof_ceiling: ProofLevel
    gaps_detectable: list[str]
    gaps_not_detectable: list[str]
    registered_at: str  # ISO 8601


# ── Object 2: CheckManifest ──


@dataclass(frozen=True)
class ManifestStage:
    stage: int
    name: str
    type: StageType
    proof_level: ProofLevel
    redacted: bool


@dataclass(frozen=True)
class ManifestAggregationConfig:
    method: AggregationMethod
    threshold: int | None


@dataclass(frozen=True)
class ManifestBenchmark:
    benchmark_id: str | None
    benchmark_hash: str | None
    precision: float | None
    recall: float | None
    f1: float | None
    test_dataset: str | None
    published_by: str | None


@dataclass(frozen=True)
class CheckManifest:
    manifest_id: str
    manifest_hash: str
    domain: ManifestDomain
    name: str
    semantic_version: str
    check_type: str
    implementation_type: ImplementationType
    supported_proof_level: ProofLevel
    evaluation_scope: EvaluationScope
    evaluation_window_seconds: int | None
    stages: list[ManifestStage]
    aggregation_config: ManifestAggregationConfig
    freshness_threshold_hours: int | None
    benchmark: ManifestBenchmark | None
    model_or_tool_hash: str | None
    publisher: str
    signer_id: str
    kid: str
    signed_at: str  # ISO 8601
    signature: SignatureEnvelopeRef
    prompt_version_id: str | None = None
    prompt_approved_by: str | None = None  # user_{uuid}
    prompt_approved_at: str | None = None  # ISO 8601


# ── P4-D: Compliance & SLA config ──


@dataclass(frozen=True)
class ExplanationCommitmentRequirement:
    on_check_result: list[str]  # ["fail", "override"]
    on_check_types: list[str]


@dataclass(frozen=True)
class BiasAuditRequirement:
    on_check_types: list[str]
    protected_categories: list[str]


@dataclass(frozen=True)
class ComplianceRequirements:
    require_actor_id: bool
    require_explanation_commitment: ExplanationCommitmentRequirement | None
    require_bias_audit: BiasAuditRequirement | None
    require_retention_policy: bool
    require_risk_classification: bool


@dataclass(frozen=True)
class SlaPolicyConfig:
    proof_level_floor_minimum: ProofLevel
    provable_surface_minimum: float  # 0.0-1.0
    max_open_critical_gaps: int
    max_open_high_gaps: int | None
    retention_policy_required: str | None


# ── Object 3: PolicyPack ──


@dataclass(frozen=True)
class PolicyPackCheck:
    check_id: str
    manifest_id: str
    required: bool
    evaluation_scope: EvaluationScope
    action_unit_count: int | None


@dataclass(frozen=True)
class PolicyPack:
    policy_pack_id: str
    org_id: str
    name: str
    version: str
    checks: list[PolicyPackCheck]
    created_at: str  # ISO 8601
    signer_id: str
    kid: str
    signature: SignatureEnvelopeRef
    compliance_requirements: ComplianceRequirements | None = None
    sla_policy: SlaPolicyConfig | None = None


# ── Object 4: PolicySnapshot ──


@dataclass(frozen=True)
class EffectiveCheck:
    check_id: str
    manifest_id: str
    manifest_hash: str
    required: bool
    evaluation_scope: EvaluationScope
    action_unit_count: int | None


@dataclass(frozen=True)
class PolicySnapshot:
    snapshot_id: str
    policy_pack_id: str
    policy_pack_version: str
    effective_checks: list[EffectiveCheck]
    snapshotted_at: str  # ISO 8601
    policy_basis: PolicyBasis
    retention_policy: str | None = None
    risk_classification: str | None = None
    regulatory_context: list[str] | None = None


# ── Object 5: ProcessRun ──


@dataclass(frozen=True)
class ProcessRun:
    run_id: str
    workflow_id: str
    org_id: str
    surface_id: str
    policy_snapshot_hash: str
    process_context_hash: str | None
    state: RunState
    action_unit_count: int
    started_at: str  # ISO 8601
    closed_at: str | None
    ttl_seconds: int  # default 3600


# ── Object 6: ActionUnit ──


@dataclass(frozen=True)
class ActionUnit:
    action_unit_id: str
    run_id: str
    surface_id: str
    action_type: str
    recorded_at: str  # ISO 8601


# ── P4-D: BiasAudit ──


@dataclass(frozen=True)
class BiasAudit:
    protected_categories: list[str]
    disparity_metric: str  # "demographic_parity" | "equalized_odds"
    disparity_threshold: float
    disparity_result_commitment: str  # poseidon2:hex
    result: str  # "pass" | "fail" | "not_applicable"


# ── Object 7: CheckExecutionRecord ──


@dataclass(frozen=True)
class ReviewerCredential:
    reviewer_key_id: str
    key_binding: KeyBinding
    role: str
    org_credential_ref: str | None
    reviewer_signature: str  # ed25519:base64url
    display_hash: str  # poseidon2:hex
    rationale_hash: str  # poseidon2:hex
    signed_content_hash: str  # poseidon2:hex
    open_tst: str  # base64:rfc3161_token
    close_tst: str  # base64:rfc3161_token


@dataclass(frozen=True)
class CheckExecutionRecord:
    record_id: str
    run_id: str
    action_unit_id: str
    manifest_id: str
    manifest_hash: str
    surface_id: str
    commitment_hash: str  # poseidon2:hex | sha256:hex
    output_commitment: str | None  # poseidon2:hex only when present
    commitment_algorithm: CommitmentAlgorithm
    commitment_type: CommitmentType
    check_result: CheckResult
    proof_level_achieved: ProofLevel
    proof_pending: bool
    zkml_proof_pending: bool
    check_open_tst: str | None  # base64:rfc3161_token
    check_close_tst: str | None  # base64:rfc3161_token
    skip_rationale_hash: str | None  # poseidon2:hex
    reviewer_credential: ReviewerCredential | None
    unverified_provenance: bool
    freshness_warning: bool
    chain_hash: str
    idempotency_key: str
    recorded_at: str  # ISO 8601
    # P4-D compliance fields
    actor_id: str | None = None  # user_{uuid}
    explanation_commitment: str | None = None  # poseidon2:hex
    bias_audit: BiasAudit | None = None


# ── Object 8: Gap ──


@dataclass(frozen=True)
class Gap:
    gap_id: str
    run_id: str
    gap_type: GapType
    severity: GapSeverity
    state: GapState
    details: dict[str, Any]
    detected_at: str  # ISO 8601
    resolved_at: str | None
    incident_report_ref: str | None = None


# ── Object 9: Waiver ──


@dataclass(frozen=True)
class Waiver:
    waiver_id: str
    gap_id: str
    org_id: str
    requestor_user_id: str
    approver_user_id: str
    reason: str  # min 50 chars
    compensating_control: str | None
    risk_treatment: str  # "accept" | "mitigate" | "transfer" | "avoid"
    expires_at: str  # REQUIRED, max 90 days
    signature: SignatureEnvelopeRef
    approved_at: str  # ISO 8601


# ── Object 10: EvidencePack ──


@dataclass(frozen=True)
class ObservationSummaryEntry:
    surface_id: str
    surface_coverage_statement: str


@dataclass(frozen=True)
class GapSummary:
    Critical: int
    High: int
    Medium: int
    Low: int
    Informational: int


@dataclass(frozen=True)
class TimestampAnchorRef:
    type: str  # "rfc3161" | "none"
    tsa: TsaProvider
    value: str | None


@dataclass(frozen=True)
class ProofDistribution:
    mathematical: int
    verifiable_inference: int
    execution: int
    witnessed: int
    attestation: int


@dataclass(frozen=True)
class EvidencePack:
    pack_id: str
    org_id: str
    period_start: str  # ISO 8601
    period_end: str  # ISO 8601
    artifact_ids: list[str]
    merkle_root: str
    proof_distribution: ProofDistribution
    coverage_verified_pct: float
    coverage_pending_pct: float
    coverage_ungoverned_pct: float
    observation_summary: list[ObservationSummaryEntry]
    gap_summary: GapSummary
    report_hash: str  # sha256:hex
    signature: SignatureEnvelopeRef
    timestamp_anchor: TimestampAnchorRef
    generated_at: str  # ISO 8601
