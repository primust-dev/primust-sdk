/**
 * Primust Artifact Core — Commitment Layer (P6-A)
 *
 * SHA-256 (default) and Poseidon2 (opt-in via PRIMUST_COMMITMENT_ALGORITHM=poseidon2) commitments.
 * Poseidon2 uses a pure implementation — opt-in only until an audited reference
 * (e.g. Barretenberg) is validated.
 *
 * PRIVACY INVARIANT: Raw content NEVER leaves the customer environment.
 * Only the commitment hash transits to Primust API.
 */
import type { CommitmentAlgorithm, ProofLevel } from './types/artifact.js';
/** ZK proof generation is always non-blocking. Non-negotiable. */
export declare const ZK_IS_BLOCKING: false;
export interface CommitmentResult {
    hash: string;
    algorithm: CommitmentAlgorithm;
}
/**
 * Compute a commitment hash over input bytes.
 *
 * @param input - Raw content bytes (NEVER transmitted — only the hash leaves the environment)
 * @param algorithm - 'sha256' (default) or 'poseidon2' (opt-in). If not specified, uses
 *                    PRIMUST_COMMITMENT_ALGORITHM env var or defaults to 'sha256'.
 */
export declare function commit(input: Uint8Array, algorithm?: CommitmentAlgorithm): CommitmentResult;
/**
 * Compute a commitment hash for check output. Uses resolved algorithm.
 */
export declare function commitOutput(output: Uint8Array): CommitmentResult;
/**
 * Build a Merkle root over an array of commitment hashes.
 * Uses the resolved algorithm (SHA-256 default, Poseidon2 opt-in) for intermediate nodes.
 *
 * @returns Merkle root, or null for empty array.
 *          Single hash → returns that hash unchanged.
 */
export declare function buildCommitmentRoot(hashes: string[], algorithm?: CommitmentAlgorithm): string | null;
/** Stage types that map to proof levels. */
type StageType = 'deterministic_rule' | 'ml_model' | 'zkml_model' | 'statistical_test' | 'custom_code' | 'witnessed' | 'policy_engine';
/**
 * Select the proof level for a given stage type.
 *
 * Mapping:
 *   deterministic_rule → mathematical
 *   zkml_model         → verifiable_inference
 *   ml_model           → execution
 *   statistical_test   → execution (default; non-deterministic sampling/bootstrapping)
 *   custom_code        → execution
 *   witnessed          → witnessed
 *
 * Note: attestation is the weakest level and only applies from explicit manifest
 * declaration, not from stage type mapping.
 */
export declare function selectProofLevel(stageType: StageType): ProofLevel;
export {};
//# sourceMappingURL=commitment.d.ts.map