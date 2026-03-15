/**
 * Primust ZK Core — Modal Prover Client
 *
 * ProverClient implementation that submits proof jobs to a Modal
 * serverless function via HTTP. Non-blocking: submitProof() returns
 * immediately with a job handle; proof completes asynchronously.
 *
 * Environment variables:
 *   PRIMUST_MODAL_ENDPOINT  — Base URL of the Modal proof worker
 *   PRIMUST_MODAL_AUTH_TOKEN — Bearer token for Modal webhook auth
 */
import type { ZkProof } from '@primust/artifact-core';
import type { ProofJobHandle, ProverClient, ProverConfig, WitnessInput } from './types.js';
export interface ModalProverClientOptions {
    /** Base URL of the Modal proof worker (e.g., https://primust--zk-worker-prove-ultrahonk.modal.run) */
    endpoint?: string;
    /** Bearer token for authentication */
    authToken?: string;
    /** Timeout for HTTP requests in ms (default: 30_000) */
    requestTimeoutMs?: number;
}
export declare class ModalProverClient implements ProverClient {
    private endpoint;
    private authToken;
    private requestTimeoutMs;
    constructor(options?: ModalProverClientOptions);
    submitProof(witness: WitnessInput, config: ProverConfig): Promise<ProofJobHandle>;
    getStatus(jobId: string): Promise<ProofJobHandle>;
    getProof(jobId: string): Promise<ZkProof | null>;
}
//# sourceMappingURL=modal-prover-client.d.ts.map