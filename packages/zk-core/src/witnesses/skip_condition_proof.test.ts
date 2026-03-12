/**
 * Tests for skip_condition_proof witness builder.
 * 3 MUST PASS tests.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

import { describe, expect, it } from 'vitest';

import type { CheckExecutionRecord, PolicySnapshot } from '@primust/runtime-core';

import { buildSkipConditionWitness } from './skip_condition_proof.js';

// ── Helpers ──

function makeSkipRecord(): CheckExecutionRecord {
  return {
    record_id: 'rec_001',
    run_id: 'run_001',
    action_unit_id: 'au_001',
    manifest_id: 'manifest_001',
    manifest_hash: 'sha256:' + 'ab'.repeat(32),
    surface_id: 'surf_001',
    commitment_hash: 'poseidon2:' + 'cc'.repeat(32),
    output_commitment: null,
    commitment_algorithm: 'poseidon2',
    commitment_type: 'output',
    check_result: 'not_applicable',
    proof_level_achieved: 'attestation',
    proof_pending: false,
    zkml_proof_pending: false,
    check_open_tst: null,
    check_close_tst: null,
    skip_rationale_hash: 'poseidon2:' + 'dd'.repeat(32),
    reviewer_credential: null,
    unverified_provenance: false,
    freshness_warning: false,
    chain_hash: 'sha256:' + 'ee'.repeat(32),
    idempotency_key: 'idem_001',
    recorded_at: '2026-03-10T00:00:00Z',
  };
}

function makeSnapshot(): PolicySnapshot {
  return {
    snapshot_id: 'snap_001',
    policy_pack_id: 'pack_001',
    policy_pack_version: '1.0.0',
    effective_checks: [],
    snapshotted_at: '2026-03-10T00:00:00Z',
    policy_basis: 'P1_self_declared',
  };
}

// ── Tests ──

describe('skip_condition_proof witness builder', () => {
  it('MUST PASS: builds witness for valid skip record with non-vacuous condition values', () => {
    const record = makeSkipRecord();
    const snapshot = makeSnapshot();
    const conditionValues = [1n, 0n, 42n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
    const blindingFactor = 12345n;

    const witness = buildSkipConditionWitness(record, snapshot, conditionValues, blindingFactor);

    expect(witness.skip_condition_hash).toMatch(/^poseidon2:/);
    expect(witness.commitment_root).toBe(record.commitment_hash);
    expect(witness.condition_values).toHaveLength(16);
    expect(witness.blinding_factor).toBe(blindingFactor);
    expect(witness.merkle_path).toHaveLength(20);
    expect(witness.run_id).toBe('run_001');
    expect(witness.manifest_id).toBe('manifest_001');
    expect(witness.policy_snapshot_hash).toBeTypeOf('string');
  });

  it('MUST PASS: throws if condition_values are all zero', () => {
    const record = makeSkipRecord();
    const snapshot = makeSnapshot();
    const allZeros = Array(16).fill(0n);

    expect(() =>
      buildSkipConditionWitness(record, snapshot, allZeros, 99n),
    ).toThrow('vacuous skip');
  });

  it('MUST PASS: neither witness builder contains TrustScope field names', () => {
    const bannedNames = ['agent_id', 'session_id', 'trace_id', 'pipeline_id'];
    const witnessesDir = path.resolve(__dirname);

    // Read all .ts files in the witnesses directory (excluding test files)
    const files = fs.readdirSync(witnessesDir).filter(
      (f) => f.endsWith('.ts') && !f.endsWith('.test.ts'),
    );
    expect(files.length).toBeGreaterThanOrEqual(2);

    for (const file of files) {
      const content = fs.readFileSync(path.join(witnessesDir, file), 'utf-8');
      for (const banned of bannedNames) {
        expect(content).not.toContain(banned);
      }
    }
  });
});
