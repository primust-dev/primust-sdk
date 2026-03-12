import type { GapType, GapSeverity, ProofLevel } from "../types/vpec";

/** Proof level color mapping — all 5 levels, never abbreviate or combine. */
export const PROOF_LEVEL_COLORS: Record<ProofLevel, string> = {
  mathematical: "bg-green-600 text-white",
  verifiable_inference: "bg-blue-600 text-white",
  execution: "bg-yellow-500 text-black",
  witnessed: "bg-orange-500 text-white",
  attestation: "bg-gray-500 text-white",
};

export const PROOF_LEVEL_LABELS: Record<ProofLevel, string> = {
  mathematical: "Mathematical",
  verifiable_inference: "Execution+ZKML",
  execution: "Execution",
  witnessed: "Witnessed",
  attestation: "Attestation",
};

/** All 5 proof levels in order from strongest to weakest. */
export const PROOF_LEVELS: ProofLevel[] = [
  "mathematical",
  "verifiable_inference",
  "execution",
  "witnessed",
  "attestation",
];

/** All 15 canonical gap types with display labels. */
export const GAP_TYPE_LABELS: Record<GapType, string> = {
  check_not_executed: "Required check not run",
  enforcement_override: "Enforcement override",
  engine_error: "Check engine error",
  check_degraded: "Check degraded",
  external_boundary_traversal: "Cross-boundary traversal",
  lineage_token_missing: "Lineage token missing",
  admission_gate_override: "Admission gate override",
  check_timing_suspect: "Timing anomaly",
  reviewer_credential_invalid: "Invalid reviewer credential",
  witnessed_display_missing: "Witnessed display missing",
  witnessed_rationale_missing: "Witnessed rationale missing",
  deterministic_consistency_violation: "Consistency violation",
  skip_rationale_missing: "Skip rationale missing",
  policy_config_drift: "Policy configuration drift",
  zkml_proof_pending_timeout: "ZK proof timeout",
  zkml_proof_failed: "ZK proof failed",
};

/** Gap severity color mapping. */
export const GAP_SEVERITY_COLORS: Record<GapSeverity, string> = {
  Critical: "bg-red-600 text-white",
  High: "bg-orange-600 text-white",
  Medium: "bg-yellow-500 text-black",
  Low: "bg-blue-400 text-white",
  Informational: "bg-gray-400 text-white",
};

/** All 5 gap severities in order. */
export const GAP_SEVERITIES: GapSeverity[] = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "Informational",
];
