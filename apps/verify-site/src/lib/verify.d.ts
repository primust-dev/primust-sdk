/**
 * Client-side VPEC verification logic.
 * In production this calls @primust/verifier. For the UI layer
 * we implement the core checks inline to avoid WASM dependency in tests.
 */
import type { VerificationResult } from "../types/vpec";
export declare function verifyArtifact(artifact: Record<string, unknown>): VerificationResult;
//# sourceMappingURL=verify.d.ts.map