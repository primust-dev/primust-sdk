/**
 * VPEC and related types for the dashboard.
 * Mirrors @primust/artifact-core types for UI consumption.
 */
export type ProofLevel = "mathematical" | "verifiable_inference" | "execution" | "witnessed" | "attestation";
export type CheckResult = "pass" | "fail" | "degraded" | "not_applicable" | "error" | "override";
export type GapType = "check_not_executed" | "enforcement_override" | "engine_error" | "check_degraded" | "external_boundary_traversal" | "lineage_token_missing" | "admission_gate_override" | "check_timing_suspect" | "reviewer_credential_invalid" | "witnessed_display_missing" | "witnessed_rationale_missing" | "deterministic_consistency_violation" | "skip_rationale_missing" | "policy_config_drift" | "zkml_proof_pending_timeout" | "zkml_proof_failed";
export type GapSeverity = "Critical" | "High" | "Medium" | "Low" | "Informational";
export interface ProofDistribution {
    mathematical: number;
    verifiable_inference: number;
    execution: number;
    witnessed: number;
    attestation: number;
    weakest_link: ProofLevel;
    weakest_link_explanation: string;
}
export interface GapEntry {
    gap_id: string;
    gap_type: GapType;
    severity: GapSeverity;
    state: "open" | "waived" | "resolved";
    details: Record<string, unknown>;
    detected_at: string;
    resolved_at: string | null;
}
export interface SurfaceSummaryEntry {
    surface_id: string;
    surface_type: string;
    observation_mode: string;
    proof_ceiling: ProofLevel;
    scope_type: string;
    surface_coverage_statement: string;
}
export interface Signature {
    signer_id: string;
    kid: string;
    algorithm: string;
    signature: string;
    signed_at: string;
}
export interface TimestampAnchor {
    type: "rfc3161" | "none";
    tsa: string;
    value: string | null;
}
export interface TransparencyLog {
    rekor_log_id: string | null;
    rekor_pending: boolean;
}
export interface ZkProof {
    status: "verified" | "pending" | "failed" | "none";
    proof_hash: string | null;
}
export interface VPECArtifact {
    vpec_id: string;
    schema_version: string;
    run_id: string;
    workflow_id: string;
    org_id: string;
    state: "signed" | "provisional";
    partial: boolean;
    test_mode: boolean;
    proof_level: ProofLevel;
    proof_distribution: ProofDistribution;
    policy_coverage_pct: number;
    instrumentation_surface_pct: number | null;
    instrumentation_surface_basis: string | null;
    coverage_verified_pct: number;
    coverage_pending_pct: number;
    coverage_ungoverned_pct: number;
    records_total: number;
    records_pass: number;
    records_fail: number;
    records_degraded: number;
    records_not_applicable: number;
    commitment_root: string;
    manifest_hashes: Record<string, string>;
    gaps: GapEntry[];
    surface_summary: SurfaceSummaryEntry[];
    process_context_hash: string | null;
    signature: Signature;
    timestamp_anchor: TimestampAnchor;
    transparency_log?: TransparencyLog;
    zk_proof?: ZkProof;
    started_at: string;
    closed_at: string;
}
export interface ProcessRun {
    run_id: string;
    workflow_id: string;
    org_id: string;
    state: "open" | "closed";
    proof_level?: ProofLevel;
    policy_coverage_pct?: number;
    gap_count: number;
    started_at: string;
    closed_at: string | null;
    process_context_hash: string | null;
    partial?: boolean;
    vpec?: VPECArtifact;
}
export interface CheckExecutionRecord {
    record_id: string;
    run_id: string;
    manifest_id: string;
    check_result: CheckResult;
    proof_level_achieved: ProofLevel;
    recorded_at: string;
    output_commitment: string | null;
    check_open_tst: string | null;
    check_close_tst: string | null;
    reviewer_credential: string | null;
}
export interface Waiver {
    waiver_id: string;
    gap_id: string;
    reason: string;
    compensating_control: string | null;
    expires_at: string;
    approved_at: string;
}
export interface PolicyPack {
    policy_pack_id: string;
    name: string;
    version: string;
    policy_basis: string;
    check_count: number;
    effective_checks: PolicyCheck[];
    created_at: string;
}
export interface PolicyCheck {
    check_id: string;
    manifest_id: string;
    required: boolean;
    evaluation_scope: string;
}
export interface EvidencePack {
    pack_id: string;
    period_start: string;
    period_end: string;
    artifact_ids: string[];
    proof_distribution: ProofDistribution;
    coverage_verified_pct: number;
    coverage_pending_pct: number;
    coverage_ungoverned_pct: number;
    observation_summary: SurfaceSummaryEntry[];
    gap_summary: Record<GapSeverity, number>;
    report_hash: string;
    signature: Signature;
    generated_at: string;
}
//# sourceMappingURL=vpec.d.ts.map