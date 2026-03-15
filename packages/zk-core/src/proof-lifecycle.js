/**
 * Primust ZK Core — Proof Lifecycle Manager (P6-C)
 *
 * Manages the ZK proof state machine for VPEC issuance:
 *   pending → complete | timeout | failed
 *
 * ZK_IS_BLOCKING = false — VPEC is issued BEFORE proof completes.
 * This module handles the async proof completion workflow.
 */
import { PROOF_TIMEOUT_MS, proveAsync } from './prover.js';
// ── Manager ──
export class ProofLifecycleManager {
    proofs = new Map();
    timers = new Map();
    client;
    callbacks;
    constructor(client, callbacks = {}) {
        this.client = client;
        this.callbacks = callbacks;
    }
    /**
     * Initiate proof generation for a run.
     * VPEC is already issued at this point with proof_pending: true.
     * This call is NON-BLOCKING — returns immediately with pending state.
     */
    async initiateProof(witness, runId, proofLevel) {
        await proveAsync(witness, runId, proofLevel, this.client);
        const status = {
            run_id: runId,
            state: 'pending',
            proof: null,
            gap: null,
        };
        this.proofs.set(runId, status);
        // Set timeout timer
        const timer = setTimeout(() => this.handleTimeout(runId), PROOF_TIMEOUT_MS);
        this.timers.set(runId, timer);
        return status;
    }
    /**
     * Handle webhook callback when proof completes.
     * Transitions pending → complete.
     * Attempts R2 write; failure emits gap but proof remains valid.
     */
    async handleWebhook(runId, proof) {
        const status = this.proofs.get(runId);
        if (!status || status.state !== 'pending') {
            throw new Error(`No pending proof for run ${runId}`);
        }
        // Cancel timeout
        const timer = this.timers.get(runId);
        if (timer) {
            clearTimeout(timer);
            this.timers.delete(runId);
        }
        status.state = 'complete';
        status.proof = proof;
        // Attempt R2 write
        if (this.callbacks.onR2WriteAttempt) {
            const success = await this.callbacks.onR2WriteAttempt(runId, proof);
            if (!success) {
                // R2 failure → gap emitted, but VPEC remains valid and signed
                status.gap = {
                    gap_id: `gap_r2_${runId}`,
                    run_id: runId,
                    gap_type: 'engine_error',
                    severity: 'Medium',
                    state: 'open',
                    details: { reason: 'proof_storage_failure: R2 write failed' },
                    detected_at: new Date().toISOString(),
                    resolved_at: null,
                    incident_report_ref: null,
                };
            }
        }
        await this.callbacks.onProofComplete?.(proof, runId);
        return status;
    }
    /**
     * Handle proof generation timeout.
     * Transitions pending → timeout with High severity gap.
     */
    handleTimeout(runId) {
        const status = this.proofs.get(runId);
        if (!status || status.state !== 'pending')
            return;
        this.timers.delete(runId);
        status.state = 'timeout';
        const gap = {
            gap_id: `gap_proof_timeout_${runId}`,
            run_id: runId,
            gap_type: 'zkml_proof_pending_timeout',
            severity: 'High',
            state: 'open',
            details: {
                reason: `Proof generation timed out after ${PROOF_TIMEOUT_MS}ms`,
            },
            detected_at: new Date().toISOString(),
            resolved_at: null,
            incident_report_ref: null,
        };
        status.gap = gap;
        this.callbacks.onProofTimeout?.(gap, runId);
    }
    /** Get current proof status for a run. */
    getStatus(runId) {
        return this.proofs.get(runId);
    }
}
//# sourceMappingURL=proof-lifecycle.js.map