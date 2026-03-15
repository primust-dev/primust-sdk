/**
 * Primust ZK Core — Prover Routing and Async Proving (P6-B)
 *
 * Routes proof levels to prover systems and submits non-blocking proof jobs.
 * ZK_IS_BLOCKING = false — proofs NEVER block VPEC issuance.
 */
import type { ProofLevel, ZkProof } from '@primust/artifact-core';
import type { ProofJobHandle, ProverClient, ProverConfig, ProverRouting, WitnessInput } from './types.js';
/** Proof generation timeout: 5 minutes. */
export declare const PROOF_TIMEOUT_MS = 300000;
/**
 * Route a proof level to the appropriate prover system.
 *
 * mathematical   → UltraHonk → Modal CPU
 * verifiable_inference → EZKL      → Modal GPU (Tier 2)
 * execution      → no ZK proof needed (returns null)
 * witnessed      → no ZK proof needed (returns null)
 * attestation    → no ZK proof needed (returns null)
 */
export declare function routeProver(proofLevel: ProofLevel): ProverRouting | null;
/**
 * Submit a proof asynchronously. Non-blocking per ZK_IS_BLOCKING = false.
 * Returns a handle; the caller polls or receives a webhook.
 *
 * Returns null if the proof level does not require ZK proof generation.
 */
export declare function proveAsync(witness: WitnessInput, runId: string, proofLevel: ProofLevel, client: ProverClient, circuit?: string): Promise<ProofJobHandle | null>;
/**
 * Stub ProverClient for testing and development.
 * Resolves immediately with a mock job handle.
 */
export declare class StubProverClient implements ProverClient {
    private jobs;
    submitProof(_witness: WitnessInput, _config: ProverConfig): Promise<ProofJobHandle>;
    getStatus(jobId: string): Promise<ProofJobHandle>;
    getProof(_jobId: string): Promise<ZkProof | null>;
    /** Test helper: simulate job completion. */
    completeJob(jobId: string): void;
    /** Test helper: simulate job timeout. */
    timeoutJob(jobId: string): void;
}
/**
 * Registry mapping circuit names to their prover routing.
 * All current circuits use UltraHonk on Modal CPU.
 */
export declare const CIRCUIT_REGISTRY: Record<string, ProverRouting>;
/**
 * Maps stage types to the circuits that should be proven.
 * Used by multi-circuit proving to determine which circuits
 * to run for a given pipeline close.
 */
export declare const STAGE_CIRCUIT_MAP: Record<string, string[]>;
/**
 * Look up prover routing for a named circuit.
 * Returns null if the circuit is not registered.
 */
export declare function getCircuitRouting(circuitName: string): ProverRouting | null;
//# sourceMappingURL=prover.d.ts.map