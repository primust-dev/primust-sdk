/**
 * Primust ZK Core — Prover Routing and Async Proving (P6-B)
 *
 * Routes proof levels to prover systems and submits non-blocking proof jobs.
 * ZK_IS_BLOCKING = false — proofs NEVER block VPEC issuance.
 */

import type { ProofLevel, ZkProof } from '@primust/artifact-core';

import type {
  ProofJobHandle,
  ProverClient,
  ProverConfig,
  ProverRouting,
  WitnessInput,
} from './types.js';

/** Proof generation timeout: 5 minutes. */
export const PROOF_TIMEOUT_MS = 300_000;

/**
 * Route a proof level to the appropriate prover system.
 *
 * mathematical   → UltraHonk → Modal CPU
 * execution_zkml → EZKL      → Modal GPU (Tier 2)
 * execution      → no ZK proof needed (returns null)
 * witnessed      → no ZK proof needed (returns null)
 * attestation    → no ZK proof needed (returns null)
 */
export function routeProver(proofLevel: ProofLevel): ProverRouting | null {
  switch (proofLevel) {
    case 'mathematical':
      return { prover: 'modal_cpu', prover_system: 'ultrahonk' };
    case 'execution_zkml':
      return { prover: 'modal_gpu', prover_system: 'ezkl' };
    case 'execution':
    case 'witnessed':
    case 'attestation':
      return null;
  }
}

/**
 * Submit a proof asynchronously. Non-blocking per ZK_IS_BLOCKING = false.
 * Returns a handle; the caller polls or receives a webhook.
 *
 * Returns null if the proof level does not require ZK proof generation.
 */
export async function proveAsync(
  witness: WitnessInput,
  runId: string,
  proofLevel: ProofLevel,
  client: ProverClient,
): Promise<ProofJobHandle | null> {
  const routing = routeProver(proofLevel);
  if (routing === null) return null;

  const config: ProverConfig = {
    prover: routing.prover,
    prover_system: routing.prover_system,
    circuit: 'primust_governance_v1',
    timeout_ms: PROOF_TIMEOUT_MS,
  };

  return client.submitProof(witness, config);
}

/**
 * Stub ProverClient for testing and development.
 * Resolves immediately with a mock job handle.
 */
export class StubProverClient implements ProverClient {
  private jobs = new Map<string, ProofJobHandle>();

  async submitProof(
    _witness: WitnessInput,
    _config: ProverConfig,
  ): Promise<ProofJobHandle> {
    const handle: ProofJobHandle = {
      job_id: `job_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      submitted_at: new Date().toISOString(),
      status: 'pending',
    };
    this.jobs.set(handle.job_id, handle);
    return handle;
  }

  async getStatus(jobId: string): Promise<ProofJobHandle> {
    return (
      this.jobs.get(jobId) ?? {
        job_id: jobId,
        submitted_at: '',
        status: 'failed',
      }
    );
  }

  async getProof(_jobId: string): Promise<ZkProof | null> {
    return null;
  }

  /** Test helper: simulate job completion. */
  completeJob(jobId: string): void {
    const job = this.jobs.get(jobId);
    if (job) job.status = 'complete';
  }

  /** Test helper: simulate job timeout. */
  timeoutJob(jobId: string): void {
    const job = this.jobs.get(jobId);
    if (job) job.status = 'timed_out';
  }
}

// ── Circuit Registry ──

/**
 * Registry mapping circuit names to their prover routing.
 * All current circuits use UltraHonk on Modal CPU.
 */
export const CIRCUIT_REGISTRY: Record<string, ProverRouting> = {
  primust_governance_v1: { prover: 'modal_cpu', prover_system: 'ultrahonk' },
  skip_condition_proof: { prover: 'modal_cpu', prover_system: 'ultrahonk' },
  config_epoch_continuity: { prover: 'modal_cpu', prover_system: 'ultrahonk' },
};

/**
 * Look up prover routing for a named circuit.
 * Returns null if the circuit is not registered.
 */
export function getCircuitRouting(circuitName: string): ProverRouting | null {
  return CIRCUIT_REGISTRY[circuitName] ?? null;
}
