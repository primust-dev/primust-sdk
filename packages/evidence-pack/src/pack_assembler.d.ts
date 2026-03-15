/**
 * Primust Evidence Pack — Pack Assembly (P8-A)
 *
 * assemblePack(artifacts, period, org_id, signerRecord, privateKey) → EvidencePack
 *
 * Steps:
 *   1. Load/validate each VPEC via P2-A offline verifier
 *   2. Compute Merkle root over artifact commitment_roots (poseidon2)
 *   3. Compute coverage buckets (must sum to 100)
 *   4. Aggregate proof_distribution across all 5 levels
 *   5. Aggregate gaps by severity
 *   6. Build observation_summary
 *   7. Build EvidencePack — no reliance_mode
 *   8. report_hash = SHA256(canonical(pack_without_signature))
 *   9. Sign with artifact_signer
 *  10. Timestamp stub
 */
import type { VPECArtifact, SignerRecord } from '@primust/artifact-core';
import type { EvidencePack } from '@primust/runtime-core';
export interface AssemblePackOptions {
    /** Coverage buckets — must sum to 100. */
    coverage_verified_pct: number;
    coverage_pending_pct: number;
    coverage_ungoverned_pct: number;
}
export interface VerificationInstructions {
    cli_command: string;
    offline_command: string;
    trust_root_url: string;
    what_this_proves: string;
    what_this_does_not_prove: string;
    coverage_basis_explanation: string;
}
export interface EvidencePackWithInstructions extends EvidencePack {
    verification_instructions: VerificationInstructions;
}
/**
 * Assemble an Evidence Pack from multiple VPEC artifacts.
 *
 * @param artifacts - Array of VPECArtifact objects to include
 * @param periodStart - Period start (ISO 8601)
 * @param periodEnd - Period end (ISO 8601)
 * @param orgId - Organization ID
 * @param signerRecord - Active SignerRecord for signing
 * @param privateKey - Ed25519 private key bytes
 * @param coverageOptions - Coverage bucket percentages (must sum to 100)
 * @returns Signed EvidencePackWithInstructions
 */
export declare function assemblePack(artifacts: VPECArtifact[], periodStart: string, periodEnd: string, orgId: string, signerRecord: SignerRecord, privateKey: Uint8Array, coverageOptions: AssemblePackOptions): Promise<EvidencePackWithInstructions>;
/**
 * Pure function — produces a human-readable dry-run summary.
 * Zero API calls, zero side effects.
 */
export declare function dryRunOutput(artifactIds: string[], periodStart: string, periodEnd: string, coverageVerifiedPct: number, coveragePendingPct: number, coverageUngovernedPct: number, surfaceSummaryLine: string, totalRecords: number): string;
//# sourceMappingURL=pack_assembler.d.ts.map