/**
 * Primust Runtime Core — Enum types for domain-neutral object schemas v3.
 *
 * Enums already defined in @primust/artifact-core (reuse, do not redefine):
 *   ProofLevel, GapType, GapSeverity, SurfaceType, ObservationMode,
 *   ScopeType, CommitmentAlgorithm, PolicyBasis, Prover, ProverSystem,
 *   TsaProvider, OrgRegion
 */

export type ManifestDomain =
  | 'ai_agent'
  | 'cicd'
  | 'financial'
  | 'pharma'
  | 'generic';

export type ImplementationType =
  | 'ml_model'
  | 'rule'
  | 'threshold'
  | 'approval_chain'
  | 'zkml_model'
  | 'custom';

/** Stage type → default proof_level mapping:
 *   deterministic_rule → mathematical
 *   zkml_model         → execution_zkml
 *   ml_model           → execution
 *   statistical_test   → mathematical (if deterministic given inputs+seed) or execution
 *   custom_code        → execution (if code_hash) or attestation
 *   human_review       → witnessed (NEVER attestation — invariant 13)
 *   policy_engine      → mathematical
 *   byollm             → attestation (opaque hosted API — hard ceiling, no upgrade path)
 *   open_source_ml     → execution (self-hosted, weights hashable, model_version_hash required)
 *   hardware_attested  → mathematical (TEE attestation quote verifiable against HW root of trust)
 */
export type StageType =
  | 'deterministic_rule'
  | 'ml_model'
  | 'zkml_model'
  | 'statistical_test'
  | 'custom_code'
  | 'human_review'
  | 'policy_engine'
  | 'byollm'
  | 'open_source_ml'
  | 'hardware_attested';

export type EvaluationScope =
  | 'per_run'
  | 'per_action_unit'
  | 'per_surface'
  | 'per_window';

export type AggregationMethod =
  | 'all_stages_must_pass'
  | 'worst_case'
  | 'threshold_vote'
  | 'sequential_gate';

export type CheckResult =
  | 'pass'
  | 'fail'
  | 'error'
  | 'skipped'
  | 'degraded'
  | 'override'
  | 'not_applicable'
  | 'timed_out';

export type GapState =
  | 'open'
  | 'investigating'
  | 'waived'
  | 'remediated'
  | 'resolved'
  | 'escalated';

export type RunState =
  | 'open'
  | 'closed'
  | 'partial'
  | 'cancelled'
  | 'auto_closed';

export type CommitmentType =
  | 'input_commitment'
  | 'metadata_commitment'
  | 'foreign_event_commitment';

export type KeyBinding = 'software' | 'hardware';
