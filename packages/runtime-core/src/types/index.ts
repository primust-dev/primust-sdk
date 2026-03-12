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

import type {
  ProofLevel,
  GapType,
  GapSeverity,
  SurfaceType,
  ObservationMode,
  ScopeType,
  CommitmentAlgorithm,
  PolicyBasis,
  TsaProvider,
} from '@primust/artifact-core';

import type {
  ManifestDomain,
  ImplementationType,
  StageType,
  EvaluationScope,
  AggregationMethod,
  CheckResult,
  GapState,
  RunState,
  CommitmentType,
  KeyBinding,
} from './enums.js';

// Re-export all enums for consumer convenience
export type {
  ManifestDomain,
  ImplementationType,
  StageType,
  EvaluationScope,
  AggregationMethod,
  CheckResult,
  GapState,
  RunState,
  CommitmentType,
  KeyBinding,
} from './enums.js';

// ── Object 1: ObservationSurface ──

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
  registered_at: string; // ISO 8601
}

// ── Object 2: CheckManifest ──

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
  manifest_id: string; // SHA-256 of canonical manifest content (deterministic)
  manifest_hash: string; // same as manifest_id; stored separately for drift detection
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
  prompt_approved_by: string | null; // user_{uuid}
  prompt_approved_at: string | null; // ISO 8601
  publisher: string;
  signer_id: string;
  kid: string;
  signed_at: string; // ISO 8601
  signature: SignatureEnvelopeRef;
}

// ── Object 3: PolicyPack ──

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
  provable_surface_minimum: number; // 0.0–1.0
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
  created_at: string; // ISO 8601
  signer_id: string;
  kid: string;
  signature: SignatureEnvelopeRef;
}

// ── Object 4: PolicySnapshot ──

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
  snapshotted_at: string; // ISO 8601
  policy_basis: PolicyBasis;
  retention_policy: string | null; // FDA_PART11_7Y | EU_AI_ACT_10Y | HIPAA_6Y | SOC2_1Y | GDPR_3Y | null
  risk_classification: string | null; // EU_HIGH_RISK | EU_LIMITED_RISK | EU_MINIMAL_RISK | US_FEDERAL | null
  regulatory_context: string[] | null; // e.g. ["EU_AI_ACT_ART13", "AIUC1_E015"]
}

// ── Object 5: ProcessRun ──

export interface ProcessRun {
  run_id: string; // run_{uuid}
  workflow_id: string;
  org_id: string;
  surface_id: string;
  policy_snapshot_hash: string;
  process_context_hash: string | null;
  state: RunState;
  action_unit_count: number;
  started_at: string; // ISO 8601
  closed_at: string | null;
  ttl_seconds: number; // default 3600
}

// ── Object 6: ActionUnit ──

export interface ActionUnit {
  action_unit_id: string;
  run_id: string;
  surface_id: string;
  action_type: string;
  recorded_at: string; // ISO 8601
}

// ── Object 7: CheckExecutionRecord ──

export interface BiasAudit {
  protected_categories: string[];
  disparity_metric: 'demographic_parity' | 'equalized_odds';
  disparity_threshold: number;
  disparity_result_commitment: string; // poseidon2:hex
  result: 'pass' | 'fail' | 'not_applicable';
}

export interface ReviewerCredential {
  reviewer_key_id: string;
  key_binding: KeyBinding;
  role: string;
  org_credential_ref: string | null;
  reviewer_signature: string; // ed25519:base64url
  display_hash: string; // poseidon2:hex
  rationale_hash: string; // poseidon2:hex
  signed_content_hash: string; // poseidon2:hex
  open_tst: string; // base64:rfc3161_token
  close_tst: string; // base64:rfc3161_token
}

export interface CheckExecutionRecord {
  record_id: string;
  run_id: string;
  action_unit_id: string;
  manifest_id: string;
  manifest_hash: string; // captured at record time — invariant 3, drift detection
  surface_id: string;
  commitment_hash: string; // poseidon2:hex | sha256:hex
  output_commitment: string | null; // poseidon2:hex only when present
  commitment_algorithm: CommitmentAlgorithm;
  commitment_type: CommitmentType;
  check_result: CheckResult;
  proof_level_achieved: ProofLevel;
  proof_pending: boolean;
  zkml_proof_pending: boolean;
  check_open_tst: string | null; // base64:rfc3161_token
  check_close_tst: string | null; // base64:rfc3161_token
  skip_rationale_hash: string | null; // poseidon2:hex — required when not_applicable
  reviewer_credential: ReviewerCredential | null; // required when witnessed
  unverified_provenance: boolean;
  freshness_warning: boolean;
  chain_hash: string;
  idempotency_key: string;
  recorded_at: string; // ISO 8601
  // ── P4-D compliance fields ──
  actor_id: string | null; // user_{uuid} — identity of triggering user/service account
  explanation_commitment: string | null; // poseidon2:hex — computed locally, plaintext NEVER sent
  bias_audit: BiasAudit | null;
}

// ── Object 8: Gap ──

export interface Gap {
  gap_id: string;
  run_id: string;
  gap_type: GapType;
  severity: GapSeverity;
  state: GapState;
  details: Record<string, unknown>;
  detected_at: string; // ISO 8601
  resolved_at: string | null;
  incident_report_ref: string | null; // e.g. FDA_MDR_2026_00123
}

// ── Object 9: Waiver ──

export interface Waiver {
  waiver_id: string;
  gap_id: string;
  org_id: string;
  requestor_user_id: string;
  approver_user_id: string;
  reason: string; // min 50 chars enforced client and server
  compensating_control: string | null;
  risk_treatment: 'accept' | 'mitigate' | 'transfer' | 'avoid';
  expires_at: string; // REQUIRED. Max 90 days from approval. No permanent waivers.
  signature: SignatureEnvelopeRef;
  approved_at: string; // ISO 8601
}

// ── Object 10: EvidencePack ──

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
  period_start: string; // ISO 8601
  period_end: string; // ISO 8601
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
  report_hash: string; // sha256:hex
  signature: SignatureEnvelopeRef;
  timestamp_anchor: TimestampAnchorRef;
  generated_at: string; // ISO 8601
}

// ── Signature envelope reference ──
// Inline type that matches the SignatureEnvelope from artifact-core.
// We use a local interface to avoid forcing consumers to import artifact-core.

export interface SignatureEnvelopeRef {
  signer_id: string;
  kid: string;
  algorithm: 'Ed25519';
  signature: string; // base64url
  signed_at: string; // ISO 8601
}
