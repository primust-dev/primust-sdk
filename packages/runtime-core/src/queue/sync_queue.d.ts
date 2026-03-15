/**
 * Primust Runtime Core — Sync Queue + Degraded Operating Modes
 *
 * In-memory queue (500 records max, 10-min TTL) between local SQLite store
 * and remote Primust API. Handles API unavailability (Mode 1) and Pipeline
 * TTL (Mode 5) directly. Modes 2–4 are signaled via DegradedStatus flags
 * for the caller pipeline to read.
 *
 * FAIL-OPEN: push() and close() never throw to the caller.
 * ZK_IS_BLOCKING = false: ZK proof failures NEVER block VPEC issuance.
 */
import type { CheckExecutionRecord, Gap } from '../types/index.js';
import type { SqliteStore } from '../store/sqlite_store.js';
/** ZK proof failures NEVER block VPEC issuance. Non-negotiable. */
export declare const ZK_IS_BLOCKING: false;
/** Maximum in-memory queue depth */
export declare const QUEUE_MAX_RECORDS = 500;
/** Per-record TTL in milliseconds (10 minutes) */
export declare const QUEUE_RECORD_TTL_MS: number;
/** Maximum close() retries */
export declare const CLOSE_MAX_RETRIES = 5;
/** Maximum backoff cap in milliseconds */
export declare const CLOSE_BACKOFF_CAP_MS = 30000;
/** Default pipeline TTL in seconds (1 hour) */
export declare const PIPELINE_TTL_SECONDS = 3600;
export type SyncResult = {
    ok: true;
} | {
    ok: false;
    error: string;
    retryable: boolean;
};
export interface SyncTarget {
    send(records: CheckExecutionRecord[]): Promise<SyncResult>;
}
export interface DegradedStatus {
    api_available: boolean;
    signer_available: boolean;
    zk_prover_available: boolean;
    zkml_prover_available: boolean;
}
export interface SyncQueueCallbacks {
    onRecordDropped?: (record: CheckExecutionRecord, reason: 'ttl_expired' | 'capacity_overflow') => void;
    onGapDetected?: (gap: Gap) => void;
}
export type SleepFn = (ms: number) => Promise<void>;
export declare class SyncQueue {
    private buffer;
    private store;
    private target;
    private status;
    private callbacks;
    private pipelineTimers;
    private sleepFn;
    constructor(opts: {
        store: SqliteStore;
        target?: SyncTarget | null;
        callbacks?: SyncQueueCallbacks;
        sleepFn?: SleepFn;
    });
    /**
     * Push a record into the queue. Writes to SQLite first, then buffers
     * for API sync. Never throws.
     */
    push(record: Omit<CheckExecutionRecord, 'chain_hash'>): void;
    /**
     * Attempt to send buffered records upstream. Returns count sent.
     */
    flush(): Promise<number>;
    /**
     * Close a pipeline run with retry. On all retries failing,
     * auto-closes the run and emits an engine_error gap.
     */
    close(runId: string): Promise<void>;
    /**
     * Start a pipeline TTL timer. Auto-closes the run after ttlSeconds.
     */
    startPipelineTtl(runId: string, ttlSeconds?: number): void;
    /**
     * Cancel a pipeline TTL timer.
     */
    cancelPipelineTtl(runId: string): void;
    /**
     * Auto-close a run (called by TTL timer).
     */
    private autoClose;
    getDegradedStatus(): Readonly<DegradedStatus>;
    markSubsystemDown(subsystem: keyof DegradedStatus): void;
    markSubsystemUp(subsystem: keyof DegradedStatus): void;
    isFullyOperational(): boolean;
    getBufferSize(): number;
    private sweepExpired;
}
//# sourceMappingURL=sync_queue.d.ts.map