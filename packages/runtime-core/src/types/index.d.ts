/**
 * Primust Runtime Core — Domain-neutral object schemas v4.
 *
 * Provisional-frozen at schema_version 4.0.0.
 *
 * BANNED FIELD NAMES (enforced in validate-schemas.ts):
 *   agent_id, pipeline_id, tool_name, session_id, trace_id,
 *   reliance_mode, PGC, attestation (as a field name)
 *
 * INVARIANTS:
 *   1. No banned field names anywhere
 *   2. witnessed stage type → witnessed proof level (NEVER attestation)
 *   3. manifest_hash captured per CheckExecutionRecord at record time
 *   4. reviewer_credential required when proof_level_achieved = witnessed
 *   5. skip_rationale_hash required when check_result = not_applicable
 *   6. CheckExecutionRecord is append-only (no UPDATE after commit)
 *   7. Waiver expires_at REQUIRED — no permanent waivers (max 90 days)
 *   8. EvidencePack: coverage_verified + coverage_pending + coverage_ungoverned = 100
 */
import type { ProofLevel, GapType, GapSeverity, SurfaceType, ObservationMode, ScopeType, CommitmentAlgorithm, PolicyBasis, TsaProvider } from '@primust/artifact-core';
import type { ManifestDomain, ImplementationType, StageType, EvaluationScope, AggregationMethod, CheckResult, GapState, RunState, CommitmentType, KeyBinding } from './enums.js';
export type { ManifestDomain, ImplementationType, StageType, EvaluationScope, AggregationMethod, CheckResult, GapState, RunState, CommitmentType, KeyBinding, } from './enums.js';
export interface ObservationSurface {
    surface_id: string;
    org_id: string;
    environment: string;
    surface_type: SurfaceType;
    surface_name: string;
    surface_version: string;
    observation_mode: ObservationMode;
    scope_type: ScopeType;
    scope_description: string;
    surface_coverage_statement: string;
    proof_ceiling: ProofLevel;
    gaps_detectable: string[];
    gaps_not_detectable: string[];
    registered_at: string;
}
export interface ManifestStage {
    stage: number;
    name: string;
    type: StageType;
    proof_level: ProofLevel;
    redacted: boolean;
}
export interface ManifestAggregationConfig {
    method: AggregationMethod;
    threshold: number | null;
}
export interface ManifestBenchmark {
    benchmark_id: string | null;
    benchmark_hash: string | null;
    precision: number | null;
    recall: number | null;
    f1: number | null;
    test_dataset: string | null;
    published_by: string | null;
}
export interface CheckManifest {
    manifest_id: string;
    manifest_hash: string;
    domain: ManifestDomain;
    name: string;
    semantic_version: string;
    check_type: string;
    implementation_type: ImplementationType;
    /** DERIVED = weakest stage.proof_level. Never set manually. */
    supported_proof_level: ProofLevel;
    evaluation_scope: EvaluationScope;
    evaluation_window_seconds: number | null;
    stages: ManifestStage[];
    aggregation_config: ManifestAggregationConfig;
    freshness_threshold_hours: number | null;
    benchmark: ManifestBenchmark | null;
    model_or_tool_hash: string | null;
    prompt_version_id: string | null;
    prompt_approved_by: string | null;
    prompt_approved_at: string | null;
    publisher: string;
    signer_id: string;
    kid: string;
    signed_at: string;
    signature: SignatureEnvelopeRef;
}
export interface ExplanationCommitmentRequirement {
    on_check_result: Array<'fail' | 'override'>;
    on_check_types: string[];
}
export interface BiasAuditRequirement {
    on_check_types: string[];
    protected_categories: string[];
}
export interface ComplianceRequirements {
    require_actor_id: boolean;
    require_explanation_commitment: ExplanationCommitmentRequirement | null;
    require_bias_audit: BiasAuditRequirement | null;
    require_retention_policy: boolean;
    require_risk_classification: boolean;
}
export interface SlaPolicyConfig {
    proof_level_floor_minimum: ProofLevel;
    provable_surface_minimum: number;
    max_open_critical_gaps: number;
    max_open_high_gaps: number | null;
    retention_policy_required: string | null;
}
export interface PolicyPackCheck {
    check_id: string;
    manifest_id: string;
    required: boolean;
    evaluation_scope: EvaluationScope;
    action_unit_count: number | null;
}
export interface PolicyPack {
    policy_pack_id: string;
    org_id: string;
    name: string;
    version: string;
    checks: PolicyPackCheck[];
    compliance_requirements: ComplianceRequirements | null;
    sla_policy: SlaPolicyConfig | null;
    created_at: string;
    signer_id: string;
    kid: string;
    signature: SignatureEnvelopeRef;
}
export interface EffectiveCheck {
    check_id: string;
    manifest_id: string;
    manifest_hash: string;
    required: boolean;
    evaluation_scope: EvaluationScope;
    action_unit_count: number | null;
}
export interface PolicySnapshot {
    snapshot_id: string;
    policy_pack_id: string;
    policy_pack_version: string;
    effective_checks: EffectiveCheck[];
    snapshotted_at: string;
    policy_basis: PolicyBasis;
    retention_policy: string | null;
    risk_classification: string | null;
    regulatory_context: string[] | null;
}
export interface ProcessRun {
    run_id: string;
    workflow_id: string;
    org_id: string;
    surface_id: string;
    policy_snapshot_hash: string;
    process_context_hash: string | null;
    state: RunState;
    action_unit_count: number;
    started_at: string;
    closed_at: string | null;
    ttl_seconds: number;
}
export interface ActionUnit {
    action_unit_id: string;
    run_id: string;
    surface_id: string;
    action_type: string;
    recorded_at: string;
}
export interface BiasAudit {
    protected_categories: string[];
    disparity_metric: 'demographic_parity' | 'equalized_odds';
    disparity_threshold: number;
    disparity_result_commitment: string;
    result: 'pass' | 'fail' | 'not_applicable';
}
export interface ReviewerCredential {
    reviewer_key_id: string;
    key_binding: KeyBinding;
    role: string;
    org_credential_ref: string | null;
    reviewer_signature: string;
    display_hash: string;
    rationale_hash: string;
    signed_content_hash: string;
    open_tst: string;
    close_tst: string;
}
export interface CheckExecutionRecord {
    record_id: string;
    run_id: string;
    action_unit_id: string;
    manifest_id: string;
    manifest_hash: string;
    surface_id: string;
    commitment_hash: string;
    output_commitment: string | null;
    commitment_algorithm: CommitmentAlgorithm;
    commitment_type: CommitmentType;
    check_result: CheckResult;
    proof_level_achieved: ProofLevel;
    proof_pending: boolean;
    zkml_proof_pending: boolean;
    check_open_tst: string | null;
    check_close_tst: string | null;
    skip_rationale_hash: string | null;
    reviewer_credential: ReviewerCredential | null;
    unverified_provenance: boolean;
    freshness_warning: boolean;
    chain_hash: string;
    idempotency_key: string;
    recorded_at: string;
    actor_id: string | null;
    explanation_commitment: string | null;
    bias_audit: BiasAudit | null;
}
export interface Gap {
    gap_id: string;
    run_id: string;
    gap_type: GapType;
    severity: GapSeverity;
    state: GapState;
    details: Record<string, unknown>;
    detected_at: string;
    resolved_at: string | null;
    incident_report_ref: string | null;
}
export interface Waiver {
    waiver_id: string;
    gap_id: string;
    org_id: string;
    requestor_user_id: string;
    approver_user_id: string;
    reason: string;
    compensating_control: string | null;
    risk_treatment: 'accept' | 'mitigate' | 'transfer' | 'avoid';
    expires_at: string;
    signature: SignatureEnvelopeRef;
    approved_at: string;
}
export interface ObservationSummaryEntry {
    surface_id: string;
    surface_coverage_statement: string;
}
export interface GapSummary {
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
    Informational: number;
}
export interface TimestampAnchorRef {
    type: 'rfc3161' | 'none';
    tsa: TsaProvider;
    value: string | null;
}
export interface EvidencePack {
    pack_id: string;
    org_id: string;
    period_start: string;
    period_end: string;
    artifact_ids: string[];
    merkle_root: string;
    proof_distribution: {
        mathematical: number;
        verifiable_inference: number;
        execution: number;
        witnessed: number;
        attestation: number;
    };
    /** DENOMINATOR 1: coverage_verified + coverage_pending + coverage_ungoverned MUST = 100 */
    coverage_verified_pct: number;
    coverage_pending_pct: number;
    coverage_ungoverned_pct: number;
    observation_summary: ObservationSummaryEntry[];
    gap_summary: GapSummary;
    report_hash: string;
    signature: SignatureEnvelopeRef;
    timestamp_anchor: TimestampAnchorRef;
    generated_at: string;
}
export interface SignatureEnvelopeRef {
    signer_id: string;
    kid: string;
    algorithm: 'Ed25519';
    signature: string;
    signed_at: string;
}
//# sourceMappingURL=index.d.ts.map