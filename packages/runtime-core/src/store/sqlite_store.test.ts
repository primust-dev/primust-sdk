import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SqliteStore, CHAIN_GENESIS_PREFIX } from './sqlite_store.js';
import type { CheckExecutionRecord } from '../types/index.js';

// ── Helpers ──

const BANNED_COLUMNS = ['agent_id', 'pipeline_id', 'tool_name', 'session_id', 'trace_id'];

function makeRecord(
  index: number,
  runId: string = 'run_001',
  overrides: Partial<Omit<CheckExecutionRecord, 'chain_hash'>> = {},
): Omit<CheckExecutionRecord, 'chain_hash'> {
  return {
    record_id: `rec_${String(index).padStart(3, '0')}`,
    run_id: runId,
    action_unit_id: `au_${index}`,
    manifest_id: 'manifest_001',
    manifest_hash: 'sha256:' + 'a'.repeat(64),
    surface_id: 'surf_001',
    commitment_hash: 'poseidon2:' + 'b'.repeat(64),
    output_commitment: null,
    commitment_algorithm: 'poseidon2',
    commitment_type: 'input_commitment',
    check_result: 'pass',
    proof_level_achieved: 'execution',
    proof_pending: false,
    zkml_proof_pending: false,
    check_open_tst: null,
    check_close_tst: null,
    skip_rationale_hash: null,
    reviewer_credential: null,
    unverified_provenance: false,
    freshness_warning: false,
    idempotency_key: `idem_${index}`,
    recorded_at: `2026-03-10T00:00:${String(index).padStart(2, '0')}Z`,
    actor_id: null,
    explanation_commitment: null,
    bias_audit: null,
    ...overrides,
  };
}

describe('SqliteStore', () => {
  let store: SqliteStore;

  beforeEach(() => {
    store = new SqliteStore(':memory:');
  });

  afterEach(() => {
    store.close();
  });

  // ── MUST PASS: CHAIN_GENESIS_PREFIX constant ──

  it('CHAIN_GENESIS_PREFIX equals "PRIMUST_CHAIN_GENESIS"', () => {
    expect(CHAIN_GENESIS_PREFIX).toBe('PRIMUST_CHAIN_GENESIS');
  });

  // ── MUST PASS: chain verifies on 10 sequential records ──

  it('chain verifies on 10 sequential records', () => {
    store.openRun({
      run_id: 'run_001',
      workflow_id: 'wf_001',
      org_id: 'org_test',
      surface_id: 'surf_001',
      policy_snapshot_hash: 'sha256:' + 'x'.repeat(64),
      process_context_hash: null,
      action_unit_count: 10,
      ttl_seconds: 3600,
    });

    for (let i = 0; i < 10; i++) {
      const result = store.appendCheckRecord(makeRecord(i));
      expect(result).not.toBeNull();
      expect(result!.chain_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    }

    const verification = store.verifyChain('run_001');
    expect(verification.valid).toBe(true);
    expect(verification.brokenAt).toBe(-1);
  });

  // ── MUST PASS: modify record 5 → chain breaks at record 5 ──

  it('modify record 5 → chain breaks at record 5, not before', () => {
    store.openRun({
      run_id: 'run_001',
      workflow_id: 'wf_001',
      org_id: 'org_test',
      surface_id: 'surf_001',
      policy_snapshot_hash: 'sha256:' + 'x'.repeat(64),
      process_context_hash: null,
      action_unit_count: 10,
      ttl_seconds: 3600,
    });

    for (let i = 0; i < 10; i++) {
      store.appendCheckRecord(makeRecord(i));
    }

    // Tamper with record 5 by changing check_result directly in DB
    // This bypasses append-only — simulates data corruption
    const db = (store as any).db;
    db.prepare(`
      UPDATE check_execution_records SET check_result = 'tampered' WHERE record_id = 'rec_005'
    `).run();

    const verification = store.verifyChain('run_001');
    expect(verification.valid).toBe(false);
    expect(verification.brokenAt).toBe(5);
  });

  // ── MUST PASS: failed write does not throw to caller ──

  it('failed write does not throw to caller', () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    store.openRun({
      run_id: 'run_001',
      workflow_id: 'wf_001',
      org_id: 'org_test',
      surface_id: 'surf_001',
      policy_snapshot_hash: 'sha256:' + 'x'.repeat(64),
      process_context_hash: null,
      action_unit_count: 1,
      ttl_seconds: 3600,
    });

    // Insert a record
    store.appendCheckRecord(makeRecord(0));

    // Try to insert duplicate (same record_id → UNIQUE constraint violation)
    const result = store.appendCheckRecord(makeRecord(0));

    // FAIL-OPEN: should not throw, returns null
    expect(result).toBeNull();
    expect(consoleSpy).toHaveBeenCalled();

    consoleSpy.mockRestore();
  });

  // ── MUST PASS: policy_config_drift gap emitted ──

  it('policy_config_drift gap emitted when manifest_hash changes between runs', () => {
    // First run with manifest hash A
    store.openRun({
      run_id: 'run_001',
      workflow_id: 'wf_001',
      org_id: 'org_test',
      surface_id: 'surf_001',
      policy_snapshot_hash: 'sha256:' + 'x'.repeat(64),
      process_context_hash: null,
      action_unit_count: 1,
      ttl_seconds: 3600,
    });

    store.appendCheckRecord(makeRecord(0, 'run_001', {
      manifest_id: 'manifest_001',
      manifest_hash: 'sha256:' + 'a'.repeat(64),
    }));

    store.closeRun('run_001');

    // Second run with different manifest hash → should emit drift gap
    const driftGaps = store.openRun({
      run_id: 'run_002',
      workflow_id: 'wf_001',
      org_id: 'org_test',
      surface_id: 'surf_001',
      policy_snapshot_hash: 'sha256:' + 'x'.repeat(64),
      process_context_hash: null,
      action_unit_count: 1,
      ttl_seconds: 3600,
      manifest_hashes: {
        manifest_001: 'sha256:' + 'b'.repeat(64),
      },
    });

    expect(driftGaps.length).toBe(1);
    expect(driftGaps[0].gap_type).toBe('policy_config_drift');
    expect(driftGaps[0].severity).toBe('Medium');
    expect(driftGaps[0].details.manifest_id).toBe('manifest_001');
    expect(driftGaps[0].details.prior_hash).toBe('sha256:' + 'a'.repeat(64));
    expect(driftGaps[0].details.current_hash).toBe('sha256:' + 'b'.repeat(64));

    // Gap should be persisted
    const gaps = store.getGaps('run_002');
    expect(gaps.length).toBe(1);
    expect(gaps[0].gap_type).toBe('policy_config_drift');
  });

  // ── MUST PASS: no banned columns anywhere ──

  it('no column named agent_id, pipeline_id, tool_name, session_id, trace_id anywhere', () => {
    const tables = store.getAllTableNames();
    for (const table of tables) {
      const columns = store.getTableColumns(table);
      for (const banned of BANNED_COLUMNS) {
        expect(columns).not.toContain(banned);
      }
    }
  });

  // ── MUST PASS: reliance_mode column does not exist ──

  it('reliance_mode column does not exist in any table', () => {
    const tables = store.getAllTableNames();
    for (const table of tables) {
      const columns = store.getTableColumns(table);
      expect(columns).not.toContain('reliance_mode');
    }
  });

  // ── MUST PASS: process_context_hash stored on process_runs ──

  it('process_context_hash stored on process_runs when provided', () => {
    const contextHash = 'sha256:' + 'c'.repeat(64);

    store.openRun({
      run_id: 'run_001',
      workflow_id: 'wf_001',
      org_id: 'org_test',
      surface_id: 'surf_001',
      policy_snapshot_hash: 'sha256:' + 'x'.repeat(64),
      process_context_hash: contextHash,
      action_unit_count: 1,
      ttl_seconds: 3600,
    });

    const run = store.getProcessRun('run_001');
    expect(run).not.toBeNull();
    expect(run!.process_context_hash).toBe(contextHash);
  });

  it('process_context_hash stored as NULL when not provided', () => {
    store.openRun({
      run_id: 'run_002',
      workflow_id: 'wf_001',
      org_id: 'org_test',
      surface_id: 'surf_001',
      policy_snapshot_hash: 'sha256:' + 'x'.repeat(64),
      process_context_hash: null,
      action_unit_count: 1,
      ttl_seconds: 3600,
    });

    const run = store.getProcessRun('run_002');
    expect(run).not.toBeNull();
    expect(run!.process_context_hash).toBeNull();
  });

  // ── MUST PASS: nullable columns present in check_execution_records ──

  it('check_open_tst, check_close_tst, output_commitment, skip_rationale_hash present as nullable columns', () => {
    const columns = store.getTableColumns('check_execution_records');
    expect(columns).toContain('check_open_tst');
    expect(columns).toContain('check_close_tst');
    expect(columns).toContain('output_commitment');
    expect(columns).toContain('skip_rationale_hash');

    // Verify they can hold values
    store.openRun({
      run_id: 'run_001',
      workflow_id: 'wf_001',
      org_id: 'org_test',
      surface_id: 'surf_001',
      policy_snapshot_hash: 'sha256:' + 'x'.repeat(64),
      process_context_hash: null,
      action_unit_count: 1,
      ttl_seconds: 3600,
    });

    store.appendCheckRecord(makeRecord(0, 'run_001', {
      check_open_tst: 'base64:open_token',
      check_close_tst: 'base64:close_token',
      output_commitment: 'poseidon2:' + 'f'.repeat(64),
      skip_rationale_hash: 'poseidon2:' + 'e'.repeat(64),
    }));

    const records = store.getCheckRecords('run_001');
    expect(records.length).toBe(1);
    expect(records[0].check_open_tst).toBe('base64:open_token');
    expect(records[0].check_close_tst).toBe('base64:close_token');
    expect(records[0].output_commitment).toBe('poseidon2:' + 'f'.repeat(64));
    expect(records[0].skip_rationale_hash).toBe('poseidon2:' + 'e'.repeat(64));
  });

  // ── MUST PASS: reviewer_credential stored as JSON blob ──

  it('reviewer_credential stored as JSON blob, retrievable as struct', () => {
    store.openRun({
      run_id: 'run_001',
      workflow_id: 'wf_001',
      org_id: 'org_test',
      surface_id: 'surf_001',
      policy_snapshot_hash: 'sha256:' + 'x'.repeat(64),
      process_context_hash: null,
      action_unit_count: 1,
      ttl_seconds: 3600,
    });

    const credential = {
      reviewer_key_id: 'key_1',
      key_binding: 'software' as const,
      role: 'reviewer',
      org_credential_ref: null,
      reviewer_signature: 'ed25519:sig_data',
      display_hash: 'poseidon2:' + 'f'.repeat(64),
      rationale_hash: 'poseidon2:' + 'f'.repeat(64),
      signed_content_hash: 'poseidon2:' + 'f'.repeat(64),
      open_tst: 'base64:open_token',
      close_tst: 'base64:close_token',
    };

    store.appendCheckRecord(makeRecord(0, 'run_001', {
      proof_level_achieved: 'witnessed',
      reviewer_credential: credential,
    }));

    const records = store.getCheckRecords('run_001');
    expect(records.length).toBe(1);

    const retrieved = records[0].reviewer_credential as typeof credential;
    expect(retrieved).not.toBeNull();
    expect(retrieved.reviewer_key_id).toBe('key_1');
    expect(retrieved.key_binding).toBe('software');
    expect(retrieved.role).toBe('reviewer');
    expect(retrieved.reviewer_signature).toBe('ed25519:sig_data');
    expect(retrieved.display_hash).toBe('poseidon2:' + 'f'.repeat(64));
  });

  // ── Additional chain tests ──

  it('chain hashes are unique per record', () => {
    store.openRun({
      run_id: 'run_001',
      workflow_id: 'wf_001',
      org_id: 'org_test',
      surface_id: 'surf_001',
      policy_snapshot_hash: 'sha256:' + 'x'.repeat(64),
      process_context_hash: null,
      action_unit_count: 5,
      ttl_seconds: 3600,
    });

    const hashes: string[] = [];
    for (let i = 0; i < 5; i++) {
      const result = store.appendCheckRecord(makeRecord(i));
      hashes.push(result!.chain_hash);
    }

    const unique = new Set(hashes);
    expect(unique.size).toBe(5);
  });

  // ── Drift detection: no drift when hash unchanged ──

  it('no drift gap when manifest_hash is unchanged between runs', () => {
    store.openRun({
      run_id: 'run_001',
      workflow_id: 'wf_001',
      org_id: 'org_test',
      surface_id: 'surf_001',
      policy_snapshot_hash: 'sha256:' + 'x'.repeat(64),
      process_context_hash: null,
      action_unit_count: 1,
      ttl_seconds: 3600,
    });

    store.appendCheckRecord(makeRecord(0, 'run_001', {
      manifest_id: 'manifest_001',
      manifest_hash: 'sha256:' + 'a'.repeat(64),
    }));

    store.closeRun('run_001');

    const driftGaps = store.openRun({
      run_id: 'run_002',
      workflow_id: 'wf_001',
      org_id: 'org_test',
      surface_id: 'surf_001',
      policy_snapshot_hash: 'sha256:' + 'x'.repeat(64),
      process_context_hash: null,
      action_unit_count: 1,
      ttl_seconds: 3600,
      manifest_hashes: {
        manifest_001: 'sha256:' + 'a'.repeat(64), // same hash
      },
    });

    expect(driftGaps.length).toBe(0);
  });
});
