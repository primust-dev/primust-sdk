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

import { PROOF_TIMEOUT_MS, proveAsync } from './prover.js';
import type { ProverClient, WitnessInput } from './types.js';

// ── Types ──

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

// ── Manager ──

export class ProofLifecycleManager {
  private proofs = new Map<string, VPECProofStatus>();
  private timers = new Map<string, ReturnType<typeof setTimeout>>();
  private client: ProverClient;
  private callbacks: ProofLifecycleCallbacks;

  constructor(
    client: ProverClient,
    callbacks: ProofLifecycleCallbacks = {},
  ) {
    this.client = client;
    this.callbacks = callbacks;
  }

  /**
   * Initiate proof generation for a run.
   * VPEC is already issued at this point with proof_pending: true.
   * This call is NON-BLOCKING — returns immediately with pending state.
   */
  async initiateProof(
    witness: WitnessInput,
    runId: string,
    proofLevel: ProofLevel,
  ): Promise<VPECProofStatus> {
    await proveAsync(witness, runId, proofLevel, this.client);

    const status: VPECProofStatus = {
      run_id: runId,
      state: 'pending',
      proof: null,
      gap: null,
    };

    this.proofs.set(runId, status);

    // Set timeout timer
    const timer = setTimeout(
      () => this.handleTimeout(runId),
      PROOF_TIMEOUT_MS,
    );
    this.timers.set(runId, timer);

    return status;
  }

  /**
   * Handle webhook callback when proof completes.
   * Transitions pending → complete.
   * Attempts R2 write; failure emits gap but proof remains valid.
   */
  async handleWebhook(
    runId: string,
    proof: ZkProof,
  ): Promise<VPECProofStatus> {
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
  private handleTimeout(runId: string): void {
    const status = this.proofs.get(runId);
    if (!status || status.state !== 'pending') return;

    this.timers.delete(runId);
    status.state = 'timeout';

    const gap: Gap = {
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
  getStatus(runId: string): VPECProofStatus | undefined {
    return this.proofs.get(runId);
  }
}
