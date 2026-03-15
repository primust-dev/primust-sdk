/**
 * Primust Runtime Core — SQLite Store + Integrity Chain
 *
 * Tables match P4-A schemas exactly. All column names use P4-A field names verbatim.
 *
 * INTEGRITY CHAIN:
 *   First record:   chain_hash = SHA256(CHAIN_GENESIS_PREFIX || run_id || canonical(record))
 *   Subsequent:     chain_hash = SHA256(CHAIN_GENESIS_PREFIX || prev_chain_hash || canonical(record))
 *
 * POLICY CONFIG DRIFT DETECTION:
 *   On openRun, if manifest_hash changed since last closed run → emit policy_config_drift gap.
 *
 * FAIL-OPEN: store write failure → log error, do NOT throw.
 * APPEND-ONLY: no UPDATE on check_execution_records after insert.
 */
import type { CheckExecutionRecord, Gap } from '../types/index.js';
export declare const CHAIN_GENESIS_PREFIX = "PRIMUST_CHAIN_GENESIS";
export declare class SqliteStore {
    private db;
    constructor(dbPath?: string);
    private createTables;
    /**
     * Open a new process run. Detects policy_config_drift if manifest hashes changed.
     */
    openRun(run: {
        run_id: string;
        workflow_id: string;
        org_id: string;
        surface_id: string;
        policy_snapshot_hash: string;
        process_context_hash: string | null;
        action_unit_count: number;
        ttl_seconds: number;
        manifest_hashes?: Record<string, string>;
    }): Gap[];
    closeRun(runId: string, state?: 'closed' | 'partial' | 'cancelled' | 'auto_closed'): void;
    getProcessRun(runId: string): Record<string, unknown> | undefined;
    /**
     * Write a policy snapshot. INSERT OR IGNORE (content-addressed, immutable after write).
     * FAIL-OPEN: logs error but does NOT throw.
     */
    writePolicySnapshot(snapshot: {
        snapshot_id: string;
        policy_pack_id: string;
        policy_pack_version: string;
        effective_checks: Record<string, unknown>[];
        snapshotted_at: string;
        policy_basis: string;
    }): void;
    getPolicySnapshot(snapshotId: string): Record<string, unknown> | undefined;
    /**
     * Append a check execution record. Computes chain_hash automatically.
     * FAIL-OPEN: logs error but does NOT throw.
     */
    appendCheckRecord(record: Omit<CheckExecutionRecord, 'chain_hash'>): {
        chain_hash: string;
    } | null;
    getCheckRecords(runId: string): Record<string, unknown>[];
    /**
     * Verify the integrity chain for a run. Returns the index of the first
     * broken link, or -1 if the chain is valid.
     */
    verifyChain(runId: string): {
        valid: boolean;
        brokenAt: number;
    };
    insertGap(gap: Gap): void;
    getGaps(runId: string): Record<string, unknown>[];
    insertSurface(surface: {
        surface_id: string;
        org_id: string;
        environment: string;
        surface_type: string;
        surface_name: string;
        surface_version: string;
        observation_mode: string;
        scope_type: string;
        scope_description: string;
        surface_coverage_statement: string;
        proof_ceiling: string;
        gaps_detectable: string[];
        gaps_not_detectable: string[];
        registered_at: string;
    }): void;
    getSurface(surfaceId: string): Record<string, unknown> | undefined;
    getTableColumns(tableName: string): string[];
    getAllTableNames(): string[];
    private buildRecordContent;
    private buildRecordContentFromRow;
    close(): void;
}
//# sourceMappingURL=sqlite_store.d.ts.map