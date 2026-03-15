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
// ── Constants ──
/** ZK proof failures NEVER block VPEC issuance. Non-negotiable. */
export const ZK_IS_BLOCKING = false;
/** Maximum in-memory queue depth */
export const QUEUE_MAX_RECORDS = 500;
/** Per-record TTL in milliseconds (10 minutes) */
export const QUEUE_RECORD_TTL_MS = 10 * 60 * 1000;
/** Maximum close() retries */
export const CLOSE_MAX_RETRIES = 5;
/** Maximum backoff cap in milliseconds */
export const CLOSE_BACKOFF_CAP_MS = 30_000;
/** Default pipeline TTL in seconds (1 hour) */
export const PIPELINE_TTL_SECONDS = 3600;
const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
// ── SyncQueue ──
export class SyncQueue {
    buffer = [];
    store;
    target;
    status;
    callbacks;
    pipelineTimers = new Map();
    sleepFn;
    constructor(opts) {
        this.store = opts.store;
        this.target = opts.target ?? null;
        this.status = {
            api_available: opts.target != null,
            signer_available: true,
            zk_prover_available: true,
            zkml_prover_available: true,
        };
        this.callbacks = opts.callbacks ?? {};
        this.sleepFn = opts.sleepFn ?? defaultSleep;
    }
    /**
     * Push a record into the queue. Writes to SQLite first, then buffers
     * for API sync. Never throws.
     */
    push(record) {
        try {
            // Sweep expired records
            this.sweepExpired();
            // Evict oldest if at capacity
            if (this.buffer.length >= QUEUE_MAX_RECORDS) {
                const dropped = this.buffer.shift();
                this.callbacks.onRecordDropped?.(dropped.record, 'capacity_overflow');
                console.error('SyncQueue: record dropped due to capacity overflow');
            }
            // Write to local SQLite store (fail-open, returns null on error)
            const result = this.store.appendCheckRecord(record);
            // Buffer in-memory with the chain_hash from the store
            const fullRecord = {
                ...record,
                chain_hash: result?.chain_hash ?? '',
            };
            this.buffer.push({
                record: fullRecord,
                enqueued_at: Date.now(),
            });
            // Fire-and-forget flush if API available
            if (this.status.api_available && this.target) {
                this.flush().catch(() => { });
            }
        }
        catch (err) {
            console.error('SyncQueue.push failed:', err);
        }
    }
    /**
     * Attempt to send buffered records upstream. Returns count sent.
     */
    async flush() {
        try {
            this.sweepExpired();
            if (this.buffer.length === 0 || !this.target) {
                return 0;
            }
            const batch = this.buffer.map((qr) => qr.record);
            const result = await this.target.send(batch);
            if (result.ok) {
                const count = this.buffer.length;
                this.buffer = [];
                this.status.api_available = true;
                return count;
            }
            // Failure
            this.status.api_available = false;
            if (!result.retryable) {
                // Drop non-retryable records
                const dropped = this.buffer.splice(0);
                for (const qr of dropped) {
                    this.callbacks.onRecordDropped?.(qr.record, 'capacity_overflow');
                }
            }
            return 0;
        }
        catch (err) {
            this.status.api_available = false;
            console.error('SyncQueue.flush failed:', err);
            return 0;
        }
    }
    /**
     * Close a pipeline run with retry. On all retries failing,
     * auto-closes the run and emits an engine_error gap.
     */
    async close(runId) {
        try {
            // Attempt flush with exponential backoff
            let flushed = false;
            for (let attempt = 0; attempt < CLOSE_MAX_RETRIES; attempt++) {
                const count = await this.flush();
                if (count > 0 || this.buffer.length === 0) {
                    flushed = true;
                    break;
                }
                if (!this.target) {
                    break;
                }
                // Exponential backoff: min(1000 * 2^attempt, 30000)
                const delay = Math.min(1000 * Math.pow(2, attempt), CLOSE_BACKOFF_CAP_MS);
                await this.sleepFn(delay);
            }
            if (flushed || this.buffer.length === 0) {
                this.store.closeRun(runId, 'closed');
            }
            else {
                // All retries failed → auto_closed + engine_error gap
                this.store.closeRun(runId, 'auto_closed');
                const now = new Date().toISOString();
                const gap = {
                    gap_id: `gap_engine_error_${runId}`,
                    run_id: runId,
                    gap_type: 'engine_error',
                    severity: 'High',
                    state: 'open',
                    details: {
                        reason: `API unreachable after ${CLOSE_MAX_RETRIES} retries`,
                    },
                    detected_at: now,
                    resolved_at: null,
                    incident_report_ref: null,
                };
                this.store.insertGap(gap);
                this.callbacks.onGapDetected?.(gap);
            }
            // Cancel any pipeline TTL timer
            this.cancelPipelineTtl(runId);
        }
        catch (err) {
            console.error('SyncQueue.close failed:', err);
            // Last-resort: attempt to close run even if everything else failed
            try {
                this.store.closeRun(runId, 'auto_closed');
            }
            catch {
                // truly fail-open
            }
        }
    }
    /**
     * Start a pipeline TTL timer. Auto-closes the run after ttlSeconds.
     */
    startPipelineTtl(runId, ttlSeconds = PIPELINE_TTL_SECONDS) {
        const timer = setTimeout(() => {
            this.autoClose(runId);
        }, ttlSeconds * 1000);
        this.pipelineTimers.set(runId, timer);
    }
    /**
     * Cancel a pipeline TTL timer.
     */
    cancelPipelineTtl(runId) {
        const timer = this.pipelineTimers.get(runId);
        if (timer) {
            clearTimeout(timer);
            this.pipelineTimers.delete(runId);
        }
    }
    /**
     * Auto-close a run (called by TTL timer).
     */
    autoClose(runId) {
        try {
            this.store.closeRun(runId, 'auto_closed');
            this.pipelineTimers.delete(runId);
        }
        catch (err) {
            console.error('SyncQueue.autoClose failed:', err);
        }
    }
    // ── Degraded status ──
    getDegradedStatus() {
        return { ...this.status };
    }
    markSubsystemDown(subsystem) {
        this.status[subsystem] = false;
    }
    markSubsystemUp(subsystem) {
        this.status[subsystem] = true;
    }
    isFullyOperational() {
        return (this.status.api_available &&
            this.status.signer_available &&
            this.status.zk_prover_available &&
            this.status.zkml_prover_available);
    }
    getBufferSize() {
        return this.buffer.length;
    }
    // ── Internal ──
    sweepExpired() {
        const now = Date.now();
        const before = this.buffer.length;
        const expired = [];
        this.buffer = this.buffer.filter((qr) => {
            if (now - qr.enqueued_at > QUEUE_RECORD_TTL_MS) {
                expired.push(qr);
                return false;
            }
            return true;
        });
        for (const qr of expired) {
            this.callbacks.onRecordDropped?.(qr.record, 'ttl_expired');
        }
        return before - this.buffer.length;
    }
}
//# sourceMappingURL=sync_queue.js.map