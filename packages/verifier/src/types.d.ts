/**
 * primust-verify — Types for offline verifier.
 */
import type { ProofLevel, ProofDistribution, Coverage } from '@primust/artifact-core';
export type RekorStatus = 'active' | 'not_found' | 'revoked' | 'unavailable' | 'skipped';
export interface VerifyOptions {
    /** Reject test_mode: true artifacts. */
    production?: boolean;
    /** Skip Rekor check — fully offline mode. */
    skip_network?: boolean;
    /** Path to custom public key PEM (for enterprise self-hosting). */
    trust_root?: string;
}
export interface VerificationResult {
    vpec_id: string;
    valid: boolean;
    schema_version: string;
    proof_level: ProofLevel | string;
    proof_distribution: ProofDistribution | Record<string, unknown>;
    org_id: string;
    workflow_id: string;
    process_context_hash: string | null;
    partial: boolean;
    test_mode: boolean;
    signer_id: string;
    kid: string;
    signed_at: string;
    timestamp_anchor_valid: boolean | null;
    rekor_status: RekorStatus;
    zk_proof_valid: boolean | null;
    manifest_hashes: Record<string, string>;
    gaps: Array<{
        gap_id: string;
        gap_type: string;
        severity: string;
    }>;
    coverage: Coverage | Record<string, unknown>;
    errors: string[];
    warnings: string[];
}
//# sourceMappingURL=types.d.ts.map