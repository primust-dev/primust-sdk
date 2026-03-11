/**
 * Tests for config_epoch_continuity witness builder.
 * 6 MUST PASS tests.
 */

import { describe, expect, it } from 'vitest';

import type { VPECArtifact } from '@primust/artifact-core';
import type { ProcessRun } from '@primust/runtime-core';

import { buildConfigEpochWitness } from './config_epoch_continuity.js';

// ── Helpers ──

function makeProcessRun(overrides?: Partial<ProcessRun>): ProcessRun {
  return {
    run_id: 'run_001',
    workflow_id: 'wf_001',
    org_id: 'org_001',
    surface_id: 'surf_001',
    policy_snapshot_hash: 'sha256:' + 'aa'.repeat(32),
    process_context_hash: 'poseidon2:' + 'bb'.repeat(32),
    state: 'open',
    action_unit_count: 10,
    started_at: '2026-03-10T00:00:00Z',
    closed_at: null,
    ttl_seconds: 3600,
    ...overrides,
  };
}

function makePriorVpec(processContextHash: string | null): VPECArtifact {
  return {
    vpec_id: 'vpec_prior',
    schema_version: '3.0.0',
    org_id: 'org_001',
    run_id: 'run_000',
    workflow_id: 'wf_001',
    process_context_hash: processContextHash,
    policy_snapshot_hash: 'sha256:' + 'aa'.repeat(32),
    policy_basis: 'P1_self_declared',
    partial: false,
    surface_summary: [],
    proof_level: 'mathematical',
    proof_distribution: {
      mathematical: 0,
      execution_zkml: 0,
      execution: 0,
      witnessed: 0,
      attestation: 0,
      weakest_link: 'mathematical',
    },
    state: 'final',
    coverage: {
      total_checks: 0,
      passed_checks: 0,
      governance_completeness_pct: 100,
    },
    gaps: [],
    manifest_hashes: {},
    commitment_root: null,
    commitment_algorithm: 'poseidon2',
    zk_proof: null,
    issuer: {
      issuer_id: 'issuer_001',
      kid: 'kid_001',
      algorithm: 'Ed25519',
    },
    signature: {
      algorithm: 'Ed25519',
      kid: 'kid_001',
      value: '',
      signed_at: '2026-03-10T00:00:00Z',
    },
    timestamp_anchor: {
      type: 'none',
      tsa: 'none',
      value: null,
    },
    transparency_log: {
      rekor_log_id: null,
      rekor_entry_url: null,
      published_at: null,
    },
    issued_at: '2026-03-10T00:00:00Z',
    pending_flags: {
      signature_pending: false,
      proof_pending: false,
      zkml_proof_pending: false,
      submission_pending: false,
      rekor_pending: false,
    },
    test_mode: false,
  };
}

const CONFIG_PARAMS = [1n, 2n, 3n];
const BLINDING = 42n;

// ── Tests ──

describe('config_epoch_continuity witness builder', () => {
  it('MUST PASS: proves when current == prior hash (priorVpec has matching hash)', () => {
    const run = makeProcessRun();

    // Build witness with matching config — get the current hash first
    const witness = buildConfigEpochWitness(run, null, CONFIG_PARAMS, BLINDING);
    const currentHash = witness.current_config_hash;

    // Now create prior with the same hash
    const prior = makePriorVpec(currentHash);
    const witness2 = buildConfigEpochWitness(run, prior, CONFIG_PARAMS, BLINDING);

    expect(witness2.epoch_transition_exists).toBe(false);
    expect(witness2.current_config_hash).toBe(witness2.prior_config_hash);
    expect(witness2.transition_gap_commitment).toBe(0n);
  });

  it('MUST PASS: proves when hashes differ AND transition_gap_commitment is non-zero', () => {
    const run = makeProcessRun();
    const prior = makePriorVpec('poseidon2:' + 'ff'.repeat(32)); // different hash
    const gapCommitment = 99999n;

    const witness = buildConfigEpochWitness(
      run,
      prior,
      CONFIG_PARAMS,
      BLINDING,
      gapCommitment,
    );

    expect(witness.epoch_transition_exists).toBe(true);
    expect(witness.current_config_hash).not.toBe(witness.prior_config_hash);
    expect(witness.transition_gap_commitment).toBe(gapCommitment);
  });

  it('MUST PASS: throws when hashes differ AND transition_gap_commitment is zero', () => {
    const run = makeProcessRun();
    const prior = makePriorVpec('poseidon2:' + 'ff'.repeat(32)); // different hash

    expect(() =>
      buildConfigEpochWitness(run, prior, CONFIG_PARAMS, BLINDING, 0n),
    ).toThrow('no transition_gap_commitment');
  });

  it('MUST PASS: priorVpec == null → witness builds without error, proof passes', () => {
    const run = makeProcessRun();

    const witness = buildConfigEpochWitness(run, null, CONFIG_PARAMS, BLINDING);

    expect(witness.epoch_transition_exists).toBe(false);
    expect(witness.current_config_hash).toBe(witness.prior_config_hash);
    expect(witness.current_config_hash).toMatch(/^poseidon2:/);
    expect(witness.config_params).toHaveLength(32);
    expect(witness.blinding_factor).toBe(BLINDING);
  });

  it('MUST PASS: transition_commitment_hash binds gap commitment (soundness)', () => {
    const run = makeProcessRun();
    const prior = makePriorVpec('poseidon2:' + 'ff'.repeat(32));
    const gapCommitment = 99999n;

    const witness = buildConfigEpochWitness(
      run,
      prior,
      CONFIG_PARAMS,
      BLINDING,
      gapCommitment,
    );

    // transition_commitment_hash must be non-zero when epoch transition exists
    expect(witness.epoch_transition_exists).toBe(true);
    expect(witness.transition_commitment_hash).toBeDefined();
    expect(witness.transition_commitment_hash).not.toBe('0');
    expect(witness.transition_commitment_hash).toMatch(/^poseidon2:/);

    // A different blinding factor produces a different commitment hash
    const witness2 = buildConfigEpochWitness(
      run,
      prior,
      CONFIG_PARAMS,
      43n,
      gapCommitment,
    );
    expect(witness2.transition_commitment_hash).not.toBe(
      witness.transition_commitment_hash,
    );
  });

  it('MUST PASS: transition_commitment_hash is zero when no epoch transition', () => {
    const run = makeProcessRun();
    const witness = buildConfigEpochWitness(run, null, CONFIG_PARAMS, BLINDING);

    expect(witness.epoch_transition_exists).toBe(false);
    expect(witness.transition_commitment_hash).toBe('0');
  });
});
