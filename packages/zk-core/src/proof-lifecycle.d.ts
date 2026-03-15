/**
 * Primust ZK Core — Proof Lifecycle Manager (P6-C)
 *
 * Manages the ZK proof state machine for VPEC issuance:
 *   pending → complete | timeout | failed
 *
 * ZK_IS_BLOCKING = false — VPEC is issued BEFORE proof completes.
 * This module handles the async proof completion workflow.
 */
import type { ProofLevel, ZkProof } from '@primust/artifact-core';
import type { Gap } from '@primust/runtime-core';
import type { ProverClient, WitnessInput } from './types.js';
export type ProofState = 'pending' | 'complete' | 'timeout' | 'failed';
export interface ProofLifecycleCallbacks {
    onProofComplete?: (proof: ZkProof, runId: string) => Promise<void>;
    onProofTimeout?: (gap: Gap, runId: string) => Promise<void>;
    onProofFailed?: (gap: Gap, runId: string) => Promise<void>;
    onR2WriteAttempt?: (runId: string, proof: ZkProof) => Promise<boolean>;
}
export interface VPECProofStatus {
    run_id: string;
    state: ProofState;
    proof: ZkProof | null;
    gap: Gap | null;
}
export declare class ProofLifecycleManager {
    private proofs;
    private timers;
    private client;
    private callbacks;
    constructor(client: ProverClient, callbacks?: ProofLifecycleCallbacks);
    /**
     * Initiate proof generation for a run.
     * VPEC is already issued at this point with proof_pending: true.
     * This call is NON-BLOCKING — returns immediately with pending state.
     */
    initiateProof(witness: WitnessInput, runId: string, proofLevel: ProofLevel): Promise<VPECProofStatus>;
    /**
     * Handle webhook callback when proof completes.
     * Transitions pending → complete.
     * Attempts R2 write; failure emits gap but proof remains valid.
     */
    handleWebhook(runId: string, proof: ZkProof): Promise<VPECProofStatus>;
    /**
     * Handle proof generation timeout.
     * Transitions pending → timeout with High severity gap.
     */
    private handleTimeout;
    /** Get current proof status for a run. */
    getStatus(runId: string): VPECProofStatus | undefined;
}
//# sourceMappingURL=proof-lifecycle.d.ts.map