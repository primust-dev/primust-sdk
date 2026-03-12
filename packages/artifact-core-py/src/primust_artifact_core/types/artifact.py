"""Primust VPEC Artifact Schema — Python types.

Provisional-frozen at schema_version 4.0.0
Canonical source: schemas/json/artifact.schema.json

INVARIANTS (enforced in validate_artifact):
1. proof_level MUST equal proof_distribution.weakest_link
2. reliance_mode field ANYWHERE → validation error
3. manifest_hashes MUST be dict (map), not list
4. gaps[] entries MUST have gap_type + severity (not bare strings)
5. partial: true → policy_coverage_pct must be 0
6. instrumentation_surface_pct and policy_coverage_pct never collapsed
7. issuer.public_key_url must match primust.com/.well-known/ pattern
8. test_mode: true rejected by primust-verify in --production mode
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional

# ---------- Type aliases ----------

ProofLevel = Literal[
    "mathematical",
    "verifiable_inference",
    "execution",
    "witnessed",
    "attestation",
]

SurfaceType = Literal[
    "in_process_adapter",
    "middleware_interceptor",
    "platform_event_feed",
    "audit_log_ingest",
    "manual_assertion",
]

ObservationMode = Literal[
    "pre_action",
    "in_flight",
    "post_action_realtime",
    "post_action_batch",
]

ScopeType = Literal[
    "full_workflow",
    "orchestration_boundary",
    "platform_logged_events",
    "component_scope",
    "partial_unknown",
]

PolicyBasis = Literal[
    "P1_self_declared",
    "P2_baseline_aligned",
    "P3_baseline_plus_deviations",
]

ArtifactState = Literal["provisional", "signed", "final"]

CommitmentAlgorithm = Literal["poseidon2", "sha256"]

Prover = Literal["local", "modal_cpu", "modal_gpu"]

ProverSystem = Literal["ultrahonk", "ezkl", "groth16_bionetta"]

TsaProvider = Literal["digicert_us", "digicert_eu", "none"]

OrgRegion = Literal["us", "eu"]

GapSeverity = Literal["Critical", "High", "Medium", "Low", "Informational"]

GapType = Literal[
    "check_not_executed",
    "enforcement_override",
    "engine_error",
    "check_degraded",
    "external_boundary_traversal",
    "lineage_token_missing",
    "admission_gate_override",
    "check_timing_suspect",
    "reviewer_credential_invalid",
    "witnessed_display_missing",
    "witnessed_rationale_missing",
    "deterministic_consistency_violation",
    "skip_rationale_missing",
    "policy_config_drift",
    "zkml_proof_pending_timeout",
    "zkml_proof_failed",
    "explanation_missing",
    "bias_audit_missing",
]


# ---------- Sub-structures ----------


@dataclass(frozen=True)
class SurfaceEntry:
    surface_id: str
    surface_type: SurfaceType
    observation_mode: ObservationMode
    proof_ceiling: ProofLevel
    scope_type: ScopeType
    scope_description: str
    surface_coverage_statement: str


@dataclass(frozen=True)
class ProofDistribution:
    mathematical: int
    verifiable_inference: int
    execution: int
    witnessed: int
    attestation: int
    weakest_link: ProofLevel
    weakest_link_explanation: str


@dataclass(frozen=True)
class Coverage:
    records_total: int
    records_pass: int
    records_fail: int
    records_degraded: int
    records_not_applicable: int
    policy_coverage_pct: float
    instrumentation_surface_pct: Optional[float]
    instrumentation_surface_basis: str


@dataclass(frozen=True)
class GapEntry:
    gap_id: str
    gap_type: GapType
    severity: GapSeverity


@dataclass(frozen=True)
class ZkProof:
    circuit: str
    proof_bytes: str  # base64url
    public_inputs: list[str]
    verified_at: str  # ISO 8601
    prover: Prover
    prover_system: ProverSystem
    nargo_version: Optional[str]


@dataclass(frozen=True)
class ArtifactIssuer:
    signer_id: str
    kid: str
    algorithm: Literal["Ed25519"]
    public_key_url: str
    org_region: OrgRegion


@dataclass(frozen=True)
class ArtifactSignature:
    signer_id: str
    kid: str
    algorithm: Literal["Ed25519"]
    signature: str  # base64url
    signed_at: str  # ISO 8601


@dataclass(frozen=True)
class TimestampAnchor:
    type: Literal["rfc3161", "none"]
    tsa: TsaProvider
    value: Optional[str]


@dataclass(frozen=True)
class TransparencyLog:
    rekor_log_id: Optional[str]
    rekor_entry_url: Optional[str]
    published_at: Optional[str]


@dataclass(frozen=True)
class PendingFlags:
    signature_pending: bool
    proof_pending: bool
    zkml_proof_pending: bool
    submission_pending: bool
    rekor_pending: bool


# ---------- Top-level artifact ----------


@dataclass(frozen=True)
class VPECArtifact:
    vpec_id: str
    schema_version: Literal["4.0.0"]

    org_id: str
    run_id: str
    workflow_id: str

    process_context_hash: Optional[str]

    policy_snapshot_hash: str
    policy_basis: PolicyBasis

    partial: bool

    surface_summary: list[SurfaceEntry]

    proof_level: ProofLevel
    proof_distribution: ProofDistribution

    state: ArtifactState

    coverage: Coverage
    gaps: list[GapEntry]

    manifest_hashes: dict[str, str]

    commitment_root: Optional[str]
    commitment_algorithm: CommitmentAlgorithm

    zk_proof: Optional[ZkProof]

    issuer: ArtifactIssuer
    signature: ArtifactSignature
    timestamp_anchor: TimestampAnchor
    transparency_log: TransparencyLog

    issued_at: str
    pending_flags: PendingFlags

    test_mode: bool
