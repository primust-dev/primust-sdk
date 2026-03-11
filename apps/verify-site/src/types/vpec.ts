export type ProofLevel =
  | "mathematical"
  | "execution_zkml"
  | "execution"
  | "witnessed"
  | "attestation";

export interface VerificationResult {
  vpec_id: string;
  valid: boolean;
  schema_version: string;
  proof_level: ProofLevel;
  proof_distribution: Record<string, number> & {
    weakest_link: ProofLevel;
    weakest_link_explanation: string;
  };
  org_id: string;
  workflow_id: string;
  process_context_hash: string | null;
  partial: boolean;
  test_mode: boolean;
  signer_id: string;
  kid: string;
  signed_at: string;
  timestamp_anchor_valid: boolean | null;
  rekor_status: string;
  zk_proof_valid: boolean | null;
  manifest_hashes: Record<string, string>;
  gaps: Array<{ gap_id: string; gap_type: string; severity: string }>;
  coverage: Record<string, unknown>;
  errors: string[];
  warnings: string[];
}
