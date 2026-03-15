/**
 * Primust Policy Engine — VPEC Issuance from Closed Run (P7-A)
 *
 * close_run(run_id, options?) → VPECArtifact
 *
 * 17 issuance steps:
 *   1. Load ProcessRun — validate state
 *   2. Load PolicySnapshot
 *   3. Load CheckExecutionRecords
 *   4. Compute proof_level (weakest)
 *   5. Build proof_distribution
 *   6. Load gaps
 *   7. Compute coverage (two denominators — never collapse)
 *   8. Build surface_summary
 *   9. Build manifest_hashes map
 *  10. Compute commitment_root
 *  11. Build VPEC document
 *  12. Sign
 *  13. Timestamp (DigiCert RFC 3161)
 *  14. ZK proof queuing (non-blocking)
 *  15. Rekor stub
 *  16. Close run
 *  17. Return VPEC
 *
 * ZK_IS_BLOCKING = false — VPEC is issued BEFORE proof completes.
 */
import type { ProverClient } from '@primust/zk-core';
import type { VPECArtifact, SignerRecord, OrgRegion } from '@primust/artifact-core';
import type { SqliteStore } from '@primust/runtime-core';
export interface CloseRunOptions {
    partial?: boolean;
    request_zk?: boolean;
    test_mode?: boolean;
    org_region?: OrgRegion;
    public_key_url?: string;
    /** ProverClient for ZK proof generation. Defaults to StubProverClient. */
    prover_client?: ProverClient;
}
/**
 * Issue a VPEC artifact from a closed ProcessRun.
 *
 * @param runId - The run to close and issue from
 * @param store - SqliteStore instance
 * @param signerRecord - Active SignerRecord for signing
 * @param privateKey - Ed25519 private key bytes
 * @param options - Issuance options (partial, request_zk, test_mode)
 * @returns Signed VPECArtifact
 */
export declare function closeRun(runId: string, store: SqliteStore, signerRecord: SignerRecord, privateKey: Uint8Array, options?: CloseRunOptions): VPECArtifact;
//# sourceMappingURL=issuer.d.ts.map