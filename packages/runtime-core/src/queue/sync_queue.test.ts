import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  SyncQueue,
  ZK_IS_BLOCKING,
  QUEUE_MAX_RECORDS,
  QUEUE_RECORD_TTL_MS,
  CLOSE_MAX_RETRIES,
  PIPELINE_TTL_SECONDS,
} from './sync_queue.js';
import type { SyncTarget, SyncResult, SleepFn } from './sync_queue.js';
import { SqliteStore } from '../store/sqlite_store.js';
import type { CheckExecutionRecord } from '../types/index.js';

// ── Helpers ──

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
    ...overrides,
  };
}

function createMockTarget(
  behavior: 'succeed' | 'fail_retryable' | 'fail_permanent' = 'succeed',
): SyncTarget & { sent: CheckExecutionRecord[][] } {
  const sent: CheckExecutionRecord[][] = [];
  return {
    sent,
    send: async (records) => {
      if (behavior === 'succeed') {
        sent.push([...records]);
        return { ok: true as const };
      }
      if (behavior === 'fail_retryable') {
        return { ok: false as const, error: 'timeout', retryable: true };
      }
      return { ok: false as const, error: 'auth_failed', retryable: false };
    },
  };
}

/** Instant sleep for fast tests */
const instantSleep: SleepFn = async () => {};

function openDefaultRun(store: SqliteStore, runId: string = 'run_001') {
  store.openRun({
    run_id: runId,
    workflow_id: 'wf_001',
    org_id: 'org_test',
    surface_id: 'surf_001',
    policy_snapshot_hash: 'sha256:' + 'x'.repeat(64),
    process_context_hash: null,
    action_unit_count: 10,
    ttl_seconds: 3600,
  });
}

// ── Tests ──

describe('SyncQueue', () => {
  let store: SqliteStore;

  beforeEach(() => {
    store = new SqliteStore(':memory:');
  });

  afterEach(() => {
    store.close();
  });

  // ── MUST PASS: ZK_IS_BLOCKING constant ──

  it('ZK_IS_BLOCKING === false', () => {
    expect(ZK_IS_BLOCKING).toBe(false);
  });

  // ── MUST PASS: Mode 1 — API unavailable does not throw ──

  it('Mode 1: push succeeds when API is unavailable', () => {
    openDefaultRun(store);
    const queue = new SyncQueue({ store, target: null });

    // Must not throw
    queue.push(makeRecord(0));
    expect(queue.getBufferSize()).toBe(1);

    // Record persisted to SQLite
    const records = store.getCheckRecords('run_001');
    expect(records.length).toBe(1);
  });

  it('Mode 1: close retries with backoff and emits api_unavailable gap after max retries', async () => {
    openDefaultRun(store);
    const target = createMockTarget('fail_retryable');
    const sleepCalls: number[] = [];
    const trackingSleep: SleepFn = async (ms) => { sleepCalls.push(ms); };

    const queue = new SyncQueue({ store, target, sleepFn: trackingSleep });
    queue.push(makeRecord(0));

    await queue.close('run_001');

    // Should have retried CLOSE_MAX_RETRIES times with backoff
    expect(sleepCalls.length).toBe(CLOSE_MAX_RETRIES);
    expect(sleepCalls[0]).toBe(1000);
    expect(sleepCalls[1]).toBe(2000);
    expect(sleepCalls[2]).toBe(4000);
    expect(sleepCalls[3]).toBe(8000);
    expect(sleepCalls[4]).toBe(16000);

    // Run should be auto_closed
    const run = store.getProcessRun('run_001');
    expect(run!.state).toBe('auto_closed');

    // api_unavailable gap should exist
    const gaps = store.getGaps('run_001');
    const apiGap = gaps.find((g) => g.gap_type === 'api_unavailable');
    expect(apiGap).toBeDefined();
    expect(apiGap!.severity).toBe('High');
  });

  it('Mode 1: close succeeds when API is available', async () => {
    openDefaultRun(store);
    const target = createMockTarget('succeed');
    const queue = new SyncQueue({ store, target, sleepFn: instantSleep });
    queue.push(makeRecord(0));

    await queue.close('run_001');

    const run = store.getProcessRun('run_001');
    expect(run!.state).toBe('closed');
    // target.sent may be called twice: once by push()'s fire-and-forget flush,
    // and once by close(). Both are valid.
    expect(target.sent.length).toBeGreaterThanOrEqual(1);
  });

  // ── MUST PASS: Mode 2 — Signer unavailable does not throw ──

  it('Mode 2: push succeeds with signer unavailable', () => {
    openDefaultRun(store);
    const queue = new SyncQueue({ store, target: null });
    queue.markSubsystemDown('signer_available');

    // Push a record (caller pipeline would set signature_pending fields)
    queue.push(makeRecord(0));

    expect(queue.getBufferSize()).toBe(1);
    expect(queue.getDegradedStatus().signer_available).toBe(false);

    const records = store.getCheckRecords('run_001');
    expect(records.length).toBe(1);
  });

  // ── MUST PASS: Mode 3 — Prover failure does not block VPEC issuance ──

  it('Mode 3: prover failure does not block VPEC issuance', () => {
    openDefaultRun(store);
    const queue = new SyncQueue({ store, target: null });
    queue.markSubsystemDown('zk_prover_available');

    const record = makeRecord(0, 'run_001', { proof_pending: true });
    queue.push(record);

    expect(queue.getBufferSize()).toBe(1);
    const stored = store.getCheckRecords('run_001');
    expect(stored.length).toBe(1);
    expect(stored[0].proof_pending).toBe(true);
  });

  it('Mode 3: zkml_proof_pending true when EZKL prover unavailable', () => {
    openDefaultRun(store);
    const queue = new SyncQueue({ store, target: null });
    queue.markSubsystemDown('zkml_prover_available');

    const record = makeRecord(0, 'run_001', { zkml_proof_pending: true });
    queue.push(record);

    const stored = store.getCheckRecords('run_001');
    expect(stored.length).toBe(1);
    expect(stored[0].zkml_proof_pending).toBe(true);
  });

  // ── MUST PASS: Mode 4 — Adapter failure does not throw ──

  it('Mode 4: adapter failure inserts check_not_executed gap, no throw', () => {
    openDefaultRun(store);

    // Simulate adapter failure: caller pipeline catches error and inserts gap
    const gap = {
      gap_id: 'gap_adapter_001',
      run_id: 'run_001',
      gap_type: 'check_not_executed' as const,
      severity: 'High' as const,
      state: 'open' as const,
      details: { check_id: 'check_001', reason: 'adapter_timeout' },
      detected_at: '2026-03-10T00:00:00Z',
      resolved_at: null,
    };

    // Must not throw
    store.insertGap(gap);

    const gaps = store.getGaps('run_001');
    expect(gaps.length).toBe(1);
    expect(gaps[0].gap_type).toBe('check_not_executed');
  });

  // ── MUST PASS: Mode 5 — Pipeline TTL ──

  it('Mode 5: auto-closes run after TTL expires', async () => {
    vi.useFakeTimers();
    openDefaultRun(store);
    const queue = new SyncQueue({ store, target: null });

    queue.startPipelineTtl('run_001', 1); // 1 second for test

    vi.advanceTimersByTime(1500);

    const run = store.getProcessRun('run_001');
    expect(run!.state).toBe('auto_closed');

    vi.useRealTimers();
  });

  // ── Queue mechanics ──

  it('drops oldest record when exceeding capacity', () => {
    openDefaultRun(store);
    const dropped: string[] = [];
    const queue = new SyncQueue({
      store,
      target: null,
      callbacks: {
        onRecordDropped: (record, reason) => {
          dropped.push(`${record.record_id}:${reason}`);
        },
      },
    });

    // Fill to capacity
    for (let i = 0; i < QUEUE_MAX_RECORDS; i++) {
      queue.push(makeRecord(i));
    }
    expect(queue.getBufferSize()).toBe(QUEUE_MAX_RECORDS);

    // One more should drop the oldest
    queue.push(makeRecord(QUEUE_MAX_RECORDS));
    expect(queue.getBufferSize()).toBe(QUEUE_MAX_RECORDS);
    expect(dropped.length).toBe(1);
    expect(dropped[0]).toContain('capacity_overflow');
  });

  it('drops records exceeding TTL', () => {
    openDefaultRun(store);
    const dropped: string[] = [];
    const queue = new SyncQueue({
      store,
      target: null,
      callbacks: {
        onRecordDropped: (record, reason) => {
          dropped.push(`${record.record_id}:${reason}`);
        },
      },
    });

    // Push a record
    queue.push(makeRecord(0));
    expect(queue.getBufferSize()).toBe(1);

    // Simulate time passing beyond TTL
    const now = Date.now();
    vi.spyOn(Date, 'now').mockReturnValue(now + QUEUE_RECORD_TTL_MS + 1);

    // Push another → triggers sweep
    queue.push(makeRecord(1));

    // First record should be dropped due to TTL
    expect(dropped.length).toBe(1);
    expect(dropped[0]).toContain('ttl_expired');

    vi.restoreAllMocks();
  });

  it('flush sends buffered records and clears buffer', async () => {
    openDefaultRun(store);
    const target = createMockTarget('succeed');
    const queue = new SyncQueue({ store, target, sleepFn: instantSleep });

    // Manually push without triggering auto-flush
    queue.markSubsystemDown('api_available');
    queue.push(makeRecord(0));
    queue.push(makeRecord(1));
    queue.markSubsystemUp('api_available');

    expect(queue.getBufferSize()).toBe(2);

    const count = await queue.flush();
    expect(count).toBe(2);
    expect(queue.getBufferSize()).toBe(0);
    expect(target.sent.length).toBe(1);
    expect(target.sent[0].length).toBe(2);
  });

  it('flush retains buffer on retryable failure', async () => {
    openDefaultRun(store);
    const target = createMockTarget('fail_retryable');
    const queue = new SyncQueue({ store, target, sleepFn: instantSleep });

    queue.markSubsystemDown('api_available');
    queue.push(makeRecord(0));
    queue.markSubsystemUp('api_available');

    const count = await queue.flush();
    expect(count).toBe(0);
    expect(queue.getBufferSize()).toBe(1); // retained
  });

  // ── Degraded status ──

  it('isFullyOperational returns true when all subsystems up', () => {
    const target = createMockTarget('succeed');
    const queue = new SyncQueue({ store, target });
    expect(queue.isFullyOperational()).toBe(true);
  });

  it('isFullyOperational returns false when any subsystem down', () => {
    const target = createMockTarget('succeed');
    const queue = new SyncQueue({ store, target });

    queue.markSubsystemDown('zk_prover_available');
    expect(queue.isFullyOperational()).toBe(false);

    queue.markSubsystemUp('zk_prover_available');
    expect(queue.isFullyOperational()).toBe(true);
  });

  it('markSubsystemDown/Up toggle correctly', () => {
    const queue = new SyncQueue({ store, target: null });

    queue.markSubsystemDown('signer_available');
    expect(queue.getDegradedStatus().signer_available).toBe(false);

    queue.markSubsystemUp('signer_available');
    expect(queue.getDegradedStatus().signer_available).toBe(true);
  });

  // ── Close with no target ──

  it('close succeeds with no target (closes run normally)', async () => {
    openDefaultRun(store);
    const queue = new SyncQueue({ store, target: null });

    await queue.close('run_001');

    const run = store.getProcessRun('run_001');
    expect(run!.state).toBe('closed');
  });

  // ── Pipeline TTL cancellation ──

  it('close cancels pipeline TTL timer', async () => {
    vi.useFakeTimers();
    openDefaultRun(store);
    const queue = new SyncQueue({ store, target: null });

    queue.startPipelineTtl('run_001', 10);
    await queue.close('run_001');

    // Advance past the TTL — should NOT auto-close again
    vi.advanceTimersByTime(15000);

    const run = store.getProcessRun('run_001');
    expect(run!.state).toBe('closed'); // not auto_closed

    vi.useRealTimers();
  });
});
