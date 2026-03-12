/**
 * Tests for ProofLifecycleManager — P6-C.
 * 8 MUST PASS tests.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

import type { ZkProof } from '@primust/artifact-core';
import type { Gap } from '@primust/runtime-core';

import { PROOF_TIMEOUT_MS, StubProverClient, routeProver } from './prover.js';
import { ProofLifecycleManager } from './proof-lifecycle.js';
import type { WitnessInput } from './types.js';

// ── Helpers ──

function makeWitness(): WitnessInput {
  return {
    commitment_root: 'poseidon2:' + 'aa'.repeat(32),
    policy_snapshot_hash: 'sha256:' + 'bb'.repeat(32),
    commitment_hashes: Array(64).fill('poseidon2:' + '00'.repeat(32)),
    check_results: Array(64).fill(0),
    manifest_hash_values: Array(64).fill('sha256:' + '00'.repeat(32)),
    record_count: 5,
  };
}

function makeMockProof(): ZkProof {
  return {
    circuit: 'primust_governance_v1',
    proof_bytes: 'dGVzdA==',
    public_inputs: ['poseidon2:' + 'aa'.repeat(32), 'sha256:' + 'bb'.repeat(32)],
    verified_at: '2026-03-10T00:00:00Z',
    prover: 'modal_cpu',
    prover_system: 'ultrahonk',
    nargo_version: '0.34.0',
  };
}

// ── Tests ──

describe('ProofLifecycleManager', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('MUST PASS: VPEC issued before proof completes (ZK_IS_BLOCKING = false)', async () => {
    const client = new StubProverClient();
    const manager = new ProofLifecycleManager(client);
    const witness = makeWitness();

    // initiateProof returns immediately with pending state
    // VPEC would already be issued at this point
    const status = await manager.initiateProof(witness, 'run_001', 'mathematical');
    expect(status.state).toBe('pending');
    expect(status.proof).toBeNull();
  });

  it('MUST PASS: mathematical records → proof_pending: true at issuance', async () => {
    const client = new StubProverClient();
    const manager = new ProofLifecycleManager(client);
    const witness = makeWitness();

    const status = await manager.initiateProof(witness, 'run_002', 'mathematical');
    // proof_pending: true is represented by state='pending'
    expect(status.state).toBe('pending');
    expect(status.proof).toBeNull();
  });

  it('MUST PASS: proof completion webhook → pending_flags.proof_pending = false', async () => {
    const client = new StubProverClient();
    const manager = new ProofLifecycleManager(client);
    const witness = makeWitness();
    const proof = makeMockProof();

    await manager.initiateProof(witness, 'run_003', 'mathematical');
    const result = await manager.handleWebhook('run_003', proof);

    // proof_pending: false is represented by state='complete'
    expect(result.state).toBe('complete');
    expect(result.proof).toBe(proof);
  });

  it('MUST PASS: proof completion → R2 write attempted', async () => {
    let r2Called = false;
    const client = new StubProverClient();
    const manager = new ProofLifecycleManager(client, {
      onR2WriteAttempt: async () => {
        r2Called = true;
        return true;
      },
    });
    const witness = makeWitness();
    const proof = makeMockProof();

    await manager.initiateProof(witness, 'run_004', 'mathematical');
    await manager.handleWebhook('run_004', proof);

    expect(r2Called).toBe(true);
  });

  it('MUST PASS: R2 write failure → proof_storage_failure gap, VPEC not invalidated', async () => {
    const client = new StubProverClient();
    const manager = new ProofLifecycleManager(client, {
      onR2WriteAttempt: async () => false, // simulate R2 failure
    });
    const witness = makeWitness();
    const proof = makeMockProof();

    await manager.initiateProof(witness, 'run_005', 'mathematical');
    const result = await manager.handleWebhook('run_005', proof);

    // VPEC still valid (state is complete, proof attached)
    expect(result.state).toBe('complete');
    expect(result.proof).toBe(proof);
    // But gap is emitted
    expect(result.gap).not.toBeNull();
    expect(result.gap!.severity).toBe('Medium');
    expect(result.gap!.details).toHaveProperty('reason');
    expect((result.gap!.details as Record<string, string>).reason).toContain(
      'proof_storage_failure',
    );
  });

  it('MUST PASS: UltraHonk routes to Modal CPU (not GPU)', () => {
    const routing = routeProver('mathematical');
    expect(routing).not.toBeNull();
    expect(routing!.prover).toBe('modal_cpu');
    expect(routing!.prover_system).toBe('ultrahonk');

    // GPU is for execution_zkml (EZKL)
    const zkmlRouting = routeProver('execution_zkml');
    expect(zkmlRouting).not.toBeNull();
    expect(zkmlRouting!.prover).toBe('modal_gpu');
  });

  it('MUST PASS: timeout → zkml_proof_pending_timeout gap (High)', async () => {
    vi.useFakeTimers();

    let gapReceived: Gap | null = null;
    const client = new StubProverClient();
    const manager = new ProofLifecycleManager(client, {
      onProofTimeout: async (gap) => {
        gapReceived = gap;
      },
    });
    const witness = makeWitness();

    await manager.initiateProof(witness, 'run_006', 'mathematical');

    // Advance past timeout
    vi.advanceTimersByTime(PROOF_TIMEOUT_MS + 1);

    expect(gapReceived).not.toBeNull();
    expect(gapReceived!.severity).toBe('High');
    expect(gapReceived!.gap_type).toBe('zkml_proof_pending_timeout');

    const status = manager.getStatus('run_006');
    expect(status!.state).toBe('timeout');
  });

  it('MUST PASS: all 5 proof levels handled in prover routing', () => {
    const levels = [
      'mathematical',
      'execution_zkml',
      'execution',
      'witnessed',
      'attestation',
    ] as const;

    for (const level of levels) {
      const routing = routeProver(level);
      if (level === 'mathematical' || level === 'execution_zkml') {
        expect(routing).not.toBeNull();
        expect(routing!.prover).toBeTypeOf('string');
        expect(routing!.prover_system).toBeTypeOf('string');
      } else {
        // No ZK proof for execution, witnessed, attestation
        expect(routing).toBeNull();
      }
    }
  });
});
