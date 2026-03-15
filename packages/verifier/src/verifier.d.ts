/**
 * primust-verify — Offline VPEC artifact verifier.
 *
 * ZERO runtime dependencies on Primust infrastructure after initial
 * public key fetch. Must verify a VPEC produced today in 10 years.
 *
 * Verification steps (in order):
 * 1. Schema validation
 * 2. SHA-256 integrity + Ed25519 signature (combined)
 * 3. Kid resolution
 * 4. Signer status check (Rekor — stubbed in v1)
 * 5. RFC 3161 timestamp verification (stubbed in v1)
 * 6. Proof level integrity
 * 7. Manifest hash audit
 * 8. ZK proof verification (stubbed in v1)
 * 9. test_mode check
 */
import type { VerifyOptions, VerificationResult } from './types.js';
/**
 * Verify a VPEC artifact.
 *
 * @param artifact - Parsed artifact JSON (Record<string, unknown>)
 * @param options  - Verification options
 * @returns VerificationResult with errors/warnings
 */
export declare function verify(artifact: Record<string, unknown>, options?: VerifyOptions): Promise<VerificationResult>;
//# sourceMappingURL=verifier.d.ts.map