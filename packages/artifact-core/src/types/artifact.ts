/**
 * Primust VPEC Artifact Schema — TypeScript types
 *
 * Provisional-frozen at schema_version 4.0.0
 * Canonical source: schemas/json/artifact.schema.json
 *
 * INVARIANTS (enforced in validateArtifact):
 * 1. proof_level MUST equal proof_distribution.weakest_link
 * 2. reliance_mode field ANYWHERE → validation error
 * 3. manifest_hashes MUST be object (map), not array
 * 4. gaps[] entries MUST have gap_type + severity (not bare strings)
 * 5. partial: true → policy_coverage_pct must be 0
 * 6. instrumentation_surface_pct and policy_coverage_pct never collapsed
 * 7. issuer.public_key_url must match primust.com/.well-known/ pattern
 * 8. test_mode: true rejected by primust-verify in --production mode
 */

// ---------- Enums ----------

export type ProofLevel =
  | 'mathematical'
  | 'verifiable_inference'
  | 'execution'
  | 'witnessed'
  | 'attestation';

export type SurfaceType =
  | 'in_process_adapter'
  | 'middleware_interceptor'
  | 'platform_event_feed'
  | 'audit_log_ingest'
  | 'manual_assertion';

export type ObservationMode =
  | 'pre_action'
  | 'in_flight'
  | 'post_action_realtime'
  | 'post_action_batch';

export type ScopeType =
  | 'full_workflow'
  | 'orchestration_boundary'
  | 'platform_logged_events'
  | 'component_scope'
  | 'partial_unknown';

export type PolicyBasis =
  | 'P1_self_declared'
  | 'P2_baseline_aligned'
  | 'P3_baseline_plus_deviations';

export type ArtifactState = 'provisional' | 'signed' | 'final';

export type CommitmentAlgorithm = 'poseidon2' | 'sha256';

export type Prover = 'local' | 'modal_cpu' | 'modal_gpu';

export type ProverSystem = 'ultrahonk' | 'ezkl' | 'groth16_bionetta';

export type TsaProvider = 'digicert_us' | 'digicert_eu' | 'none';

export type OrgRegion = 'us' | 'eu';

export type GapSeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export type GapType =
  | 'check_not_executed'
  | 'enforcement_override'
  | 'engine_error'
  | 'check_degraded'
  | 'external_boundary_traversal'
  | 'lineage_token_missing'
  | 'admission_gate_override'
  | 'check_timing_suspect'
  | 'reviewer_credential_invalid'
  | 'witnessed_display_missing'
  | 'witnessed_rationale_missing'
  | 'deterministic_consistency_violation'
  | 'skip_rationale_missing'
  | 'policy_config_drift'
  | 'zkml_proof_pending_timeout'
  | 'zkml_proof_failed'
  | 'explanation_missing'
  | 'bias_audit_missing';

// ---------- Sub-structures ----------

export interface SurfaceEntry {
  surface_id: string;
  surface_type: SurfaceType;
  observation_mode: ObservationMode;
  proof_ceiling: ProofLevel;
  scope_type: ScopeType;
  scope_description: string;
  surface_coverage_statement: string;
}

export interface ProofDistribution {
  mathematical: number;
  verifiable_inference: number;
  execution: number;
  witnessed: number;
  attestation: number;
  weakest_link: ProofLevel;
  weakest_link_explanation: string;
}

export interface Coverage {
  records_total: number;
  records_pass: number;
  records_fail: number;
  records_degraded: number;
  records_not_applicable: number;
  /** DENOMINATOR 1: % of required checks (per PolicySnapshot) that ran. */
  policy_coverage_pct: number;
  /** DENOMINATOR 2: % of total workflow universe in instrumentation scope. null when partial_unknown. NEVER collapse with policy_coverage_pct. */
  instrumentation_surface_pct: number | null;
  /** Plain-English statement of what the surface denominator represents. */
  instrumentation_surface_basis: string;
}

export interface GapEntry {
  gap_id: string;
  gap_type: GapType;
  severity: GapSeverity;
}

export interface ZkProof {
  circuit: string;
  proof_bytes: string; // base64url
  public_inputs: string[];
  verified_at: string; // ISO 8601
  prover: Prover;
  prover_system: ProverSystem;
  nargo_version: string | null;
}

export interface ArtifactIssuer {
  signer_id: string;
  kid: string;
  algorithm: 'Ed25519';
  public_key_url: string;
  org_region: OrgRegion;
}

export interface ArtifactSignature {
  signer_id: string;
  kid: string;
  algorithm: 'Ed25519';
  signature: string; // base64url
  signed_at: string; // ISO 8601
}

export interface TimestampAnchor {
  type: 'rfc3161' | 'none';
  tsa: TsaProvider;
  value: string | null;
}

export interface TransparencyLog {
  rekor_log_id: string | null;
  rekor_entry_url: string | null;
  published_at: string | null;
}

export interface PendingFlags {
  signature_pending: boolean;
  /** true when Noir/UltraHonk proof in-flight */
  proof_pending: boolean;
  /** true when EZKL/Bionetta proof in-flight (Tier 2) */
  zkml_proof_pending: boolean;
  submission_pending: boolean;
  /** true until transparency_log.rekor_log_id populated */
  rekor_pending: boolean;
}

// ---------- Top-level artifact ----------

export interface VPECArtifact {
  vpec_id: string;
  schema_version: '4.0.0';

  org_id: string;
  run_id: string;
  workflow_id: string;

  /** Customer-computed config epoch hash. null when not provided. */
  process_context_hash: string | null;

  policy_snapshot_hash: string;
  policy_basis: PolicyBasis;

  /** true when issued via p.close(partial=True). Coverage credit NOT awarded. */
  partial: boolean;

  surface_summary: SurfaceEntry[];

  /** MUST equal proof_distribution.weakest_link. Computed — never set manually. */
  proof_level: ProofLevel;
  proof_distribution: ProofDistribution;

  state: ArtifactState;

  coverage: Coverage;
  gaps: GapEntry[];

  /** Map of manifest_id → sha256:hex. Object, not array. */
  manifest_hashes: Record<string, string>;

  /** Merkle root over all CheckExecutionRecord commitment_hashes. null when zero records. */
  commitment_root: string | null;
  commitment_algorithm: CommitmentAlgorithm;

  zk_proof: ZkProof | null;

  issuer: ArtifactIssuer;
  signature: ArtifactSignature;
  timestamp_anchor: TimestampAnchor;
  transparency_log: TransparencyLog;

  issued_at: string;
  pending_flags: PendingFlags;

  /** true when issued with pk_test_xxx key. Rejected by primust-verify in --production. */
  test_mode: boolean;
}
