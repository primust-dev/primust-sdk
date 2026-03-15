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
import Database from 'better-sqlite3';
import { sha256 } from '@noble/hashes/sha256';
import { canonical } from '@primust/artifact-core';
// ── Constants ──
export const CHAIN_GENESIS_PREFIX = 'PRIMUST_CHAIN_GENESIS';
// ── Helpers ──
function hexEncode(bytes) {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}
function computeChainHash(prefix, content) {
    const input = new TextEncoder().encode(prefix + content);
    return 'sha256:' + hexEncode(sha256(input));
}
// ── Store ──
export class SqliteStore {
    db;
    constructor(dbPath = ':memory:') {
        this.db = new Database(dbPath);
        this.db.pragma('journal_mode = WAL');
        this.db.pragma('foreign_keys = ON');
        this.createTables();
    }
    createTables() {
        this.db.exec(`
      CREATE TABLE IF NOT EXISTS observation_surfaces (
        surface_id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        environment TEXT NOT NULL,
        surface_type TEXT NOT NULL,
        surface_name TEXT NOT NULL,
        surface_version TEXT NOT NULL,
        observation_mode TEXT NOT NULL,
        scope_type TEXT NOT NULL,
        scope_description TEXT NOT NULL,
        surface_coverage_statement TEXT NOT NULL,
        proof_ceiling TEXT NOT NULL,
        gaps_detectable TEXT NOT NULL,
        gaps_not_detectable TEXT NOT NULL,
        registered_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS check_manifests (
        manifest_id TEXT PRIMARY KEY,
        manifest_hash TEXT NOT NULL,
        domain TEXT NOT NULL,
        name TEXT NOT NULL,
        semantic_version TEXT NOT NULL,
        check_type TEXT NOT NULL,
        implementation_type TEXT NOT NULL,
        supported_proof_level TEXT NOT NULL,
        evaluation_scope TEXT NOT NULL,
        evaluation_window_seconds INTEGER,
        stages TEXT NOT NULL,
        aggregation_config TEXT NOT NULL,
        freshness_threshold_hours REAL,
        benchmark TEXT,
        model_or_tool_hash TEXT,
        publisher TEXT NOT NULL,
        signer_id TEXT NOT NULL,
        kid TEXT NOT NULL,
        signed_at TEXT NOT NULL,
        signature TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS policy_packs (
        policy_pack_id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        checks TEXT NOT NULL,
        created_at TEXT NOT NULL,
        signer_id TEXT NOT NULL,
        kid TEXT NOT NULL,
        signature TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS policy_snapshots (
        snapshot_id TEXT PRIMARY KEY,
        policy_pack_id TEXT NOT NULL,
        policy_pack_version TEXT NOT NULL,
        effective_checks TEXT NOT NULL,
        snapshotted_at TEXT NOT NULL,
        policy_basis TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS process_runs (
        run_id TEXT PRIMARY KEY,
        workflow_id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        surface_id TEXT NOT NULL,
        policy_snapshot_hash TEXT NOT NULL,
        process_context_hash TEXT,
        state TEXT NOT NULL,
        action_unit_count INTEGER NOT NULL,
        started_at TEXT NOT NULL,
        closed_at TEXT,
        ttl_seconds INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS action_units (
        action_unit_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        surface_id TEXT NOT NULL,
        action_type TEXT NOT NULL,
        recorded_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS check_execution_records (
        record_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        action_unit_id TEXT NOT NULL,
        manifest_id TEXT NOT NULL,
        manifest_hash TEXT NOT NULL,
        surface_id TEXT NOT NULL,
        commitment_hash TEXT NOT NULL,
        output_commitment TEXT,
        commitment_algorithm TEXT NOT NULL,
        commitment_type TEXT NOT NULL,
        check_result TEXT NOT NULL,
        proof_level_achieved TEXT NOT NULL,
        proof_pending INTEGER NOT NULL DEFAULT 0,
        zkml_proof_pending INTEGER NOT NULL DEFAULT 0,
        check_open_tst TEXT,
        check_close_tst TEXT,
        skip_rationale_hash TEXT,
        reviewer_credential TEXT,
        unverified_provenance INTEGER NOT NULL DEFAULT 0,
        freshness_warning INTEGER NOT NULL DEFAULT 0,
        chain_hash TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        recorded_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS gaps (
        gap_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        gap_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        state TEXT NOT NULL,
        details TEXT NOT NULL,
        detected_at TEXT NOT NULL,
        resolved_at TEXT
      );

      CREATE TABLE IF NOT EXISTS waivers (
        waiver_id TEXT PRIMARY KEY,
        gap_id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        requestor_user_id TEXT NOT NULL,
        approver_user_id TEXT NOT NULL,
        reason TEXT NOT NULL,
        compensating_control TEXT,
        expires_at TEXT NOT NULL,
        signature TEXT NOT NULL,
        approved_at TEXT NOT NULL
      );
    `);
    }
    // ── Process Runs ──
    /**
     * Open a new process run. Detects policy_config_drift if manifest hashes changed.
     */
    openRun(run) {
        const now = new Date().toISOString();
        const driftGaps = [];
        try {
            this.db.prepare(`
        INSERT INTO process_runs (
          run_id, workflow_id, org_id, surface_id, policy_snapshot_hash,
          process_context_hash, state, action_unit_count, started_at, closed_at, ttl_seconds
        ) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, NULL, ?)
      `).run(run.run_id, run.workflow_id, run.org_id, run.surface_id, run.policy_snapshot_hash, run.process_context_hash, run.action_unit_count, now, run.ttl_seconds);
            // Policy config drift detection
            if (run.manifest_hashes) {
                const lastRun = this.db.prepare(`
          SELECT run_id FROM process_runs
          WHERE workflow_id = ? AND state = 'closed' AND run_id != ?
          ORDER BY started_at DESC LIMIT 1
        `).get(run.workflow_id, run.run_id);
                if (lastRun) {
                    for (const [manifestId, currentHash] of Object.entries(run.manifest_hashes)) {
                        const priorRecord = this.db.prepare(`
              SELECT manifest_hash FROM check_execution_records
              WHERE run_id = ? AND manifest_id = ? LIMIT 1
            `).get(lastRun.run_id, manifestId);
                        if (priorRecord && priorRecord.manifest_hash !== currentHash) {
                            const gap = {
                                gap_id: `gap_drift_${manifestId}_${run.run_id}`,
                                run_id: run.run_id,
                                gap_type: 'policy_config_drift',
                                severity: 'Medium',
                                state: 'open',
                                details: {
                                    manifest_id: manifestId,
                                    prior_hash: priorRecord.manifest_hash,
                                    current_hash: currentHash,
                                    detected_at: now,
                                },
                                detected_at: now,
                                resolved_at: null,
                                incident_report_ref: null,
                            };
                            driftGaps.push(gap);
                            this.insertGap(gap);
                        }
                    }
                }
            }
        }
        catch (err) {
            console.error('SqliteStore.openRun failed:', err);
        }
        return driftGaps;
    }
    closeRun(runId, state = 'closed') {
        try {
            this.db.prepare(`
        UPDATE process_runs SET state = ?, closed_at = ? WHERE run_id = ?
      `).run(state, new Date().toISOString(), runId);
        }
        catch (err) {
            console.error('SqliteStore.closeRun failed:', err);
        }
    }
    getProcessRun(runId) {
        return this.db.prepare('SELECT * FROM process_runs WHERE run_id = ?').get(runId);
    }
    // ── Policy Snapshots ──
    /**
     * Write a policy snapshot. INSERT OR IGNORE (content-addressed, immutable after write).
     * FAIL-OPEN: logs error but does NOT throw.
     */
    writePolicySnapshot(snapshot) {
        try {
            this.db.prepare(`
        INSERT OR IGNORE INTO policy_snapshots (
          snapshot_id, policy_pack_id, policy_pack_version,
          effective_checks, snapshotted_at, policy_basis
        ) VALUES (?, ?, ?, ?, ?, ?)
      `).run(snapshot.snapshot_id, snapshot.policy_pack_id, snapshot.policy_pack_version, JSON.stringify(snapshot.effective_checks), snapshot.snapshotted_at, snapshot.policy_basis);
        }
        catch (err) {
            console.error('SqliteStore.writePolicySnapshot failed:', err);
        }
    }
    getPolicySnapshot(snapshotId) {
        const row = this.db.prepare('SELECT * FROM policy_snapshots WHERE snapshot_id = ?').get(snapshotId);
        if (row) {
            row.effective_checks = JSON.parse(row.effective_checks);
        }
        return row;
    }
    // ── Check Execution Records (append-only) ──
    /**
     * Append a check execution record. Computes chain_hash automatically.
     * FAIL-OPEN: logs error but does NOT throw.
     */
    appendCheckRecord(record) {
        try {
            // Build record content for chain hash (without chain_hash itself)
            const recordContent = this.buildRecordContent(record);
            const canonicalContent = canonical(recordContent);
            // Get previous chain_hash for this run
            const prevRecord = this.db.prepare(`
        SELECT chain_hash FROM check_execution_records
        WHERE run_id = ? ORDER BY recorded_at DESC, rowid DESC LIMIT 1
      `).get(record.run_id);
            let chainHash;
            if (prevRecord) {
                chainHash = computeChainHash(CHAIN_GENESIS_PREFIX, prevRecord.chain_hash + canonicalContent);
            }
            else {
                chainHash = computeChainHash(CHAIN_GENESIS_PREFIX, record.run_id + canonicalContent);
            }
            this.db.prepare(`
        INSERT INTO check_execution_records (
          record_id, run_id, action_unit_id, manifest_id, manifest_hash,
          surface_id, commitment_hash, output_commitment, commitment_algorithm,
          commitment_type, check_result, proof_level_achieved, proof_pending,
          zkml_proof_pending, check_open_tst, check_close_tst, skip_rationale_hash,
          reviewer_credential, unverified_provenance, freshness_warning,
          chain_hash, idempotency_key, recorded_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(record.record_id, record.run_id, record.action_unit_id, record.manifest_id, record.manifest_hash, record.surface_id, record.commitment_hash, record.output_commitment, record.commitment_algorithm, record.commitment_type, record.check_result, record.proof_level_achieved, record.proof_pending ? 1 : 0, record.zkml_proof_pending ? 1 : 0, record.check_open_tst, record.check_close_tst, record.skip_rationale_hash, record.reviewer_credential ? JSON.stringify(record.reviewer_credential) : null, record.unverified_provenance ? 1 : 0, record.freshness_warning ? 1 : 0, chainHash, record.idempotency_key, record.recorded_at);
            return { chain_hash: chainHash };
        }
        catch (err) {
            console.error('SqliteStore.appendCheckRecord failed:', err);
            return null;
        }
    }
    getCheckRecords(runId) {
        const rows = this.db.prepare('SELECT * FROM check_execution_records WHERE run_id = ? ORDER BY recorded_at, rowid').all(runId);
        return rows.map((row) => ({
            ...row,
            proof_pending: row.proof_pending === 1,
            zkml_proof_pending: row.zkml_proof_pending === 1,
            unverified_provenance: row.unverified_provenance === 1,
            freshness_warning: row.freshness_warning === 1,
            reviewer_credential: row.reviewer_credential
                ? JSON.parse(row.reviewer_credential)
                : null,
        }));
    }
    // ── Chain Verification ──
    /**
     * Verify the integrity chain for a run. Returns the index of the first
     * broken link, or -1 if the chain is valid.
     */
    verifyChain(runId) {
        const records = this.db.prepare('SELECT * FROM check_execution_records WHERE run_id = ? ORDER BY recorded_at, rowid').all(runId);
        for (let i = 0; i < records.length; i++) {
            const record = records[i];
            const recordContent = this.buildRecordContentFromRow(record);
            const canonicalContent = canonical(recordContent);
            let expectedHash;
            if (i === 0) {
                expectedHash = computeChainHash(CHAIN_GENESIS_PREFIX, runId + canonicalContent);
            }
            else {
                const prevHash = records[i - 1].chain_hash;
                expectedHash = computeChainHash(CHAIN_GENESIS_PREFIX, prevHash + canonicalContent);
            }
            if (record.chain_hash !== expectedHash) {
                return { valid: false, brokenAt: i };
            }
        }
        return { valid: true, brokenAt: -1 };
    }
    // ── Gaps ──
    insertGap(gap) {
        try {
            this.db.prepare(`
        INSERT INTO gaps (gap_id, run_id, gap_type, severity, state, details, detected_at, resolved_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(gap.gap_id, gap.run_id, gap.gap_type, gap.severity, gap.state, JSON.stringify(gap.details), gap.detected_at, gap.resolved_at);
        }
        catch (err) {
            console.error('SqliteStore.insertGap failed:', err);
        }
    }
    getGaps(runId) {
        const rows = this.db.prepare('SELECT * FROM gaps WHERE run_id = ? ORDER BY detected_at').all(runId);
        return rows.map((row) => ({
            ...row,
            details: JSON.parse(row.details),
        }));
    }
    // ── Observation Surfaces ──
    insertSurface(surface) {
        try {
            this.db.prepare(`
        INSERT OR IGNORE INTO observation_surfaces (
          surface_id, org_id, environment, surface_type, surface_name, surface_version,
          observation_mode, scope_type, scope_description, surface_coverage_statement,
          proof_ceiling, gaps_detectable, gaps_not_detectable, registered_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(surface.surface_id, surface.org_id, surface.environment, surface.surface_type, surface.surface_name, surface.surface_version, surface.observation_mode, surface.scope_type, surface.scope_description, surface.surface_coverage_statement, surface.proof_ceiling, JSON.stringify(surface.gaps_detectable), JSON.stringify(surface.gaps_not_detectable), surface.registered_at);
        }
        catch (err) {
            console.error('SqliteStore.insertSurface failed:', err);
        }
    }
    getSurface(surfaceId) {
        const row = this.db.prepare('SELECT * FROM observation_surfaces WHERE surface_id = ?').get(surfaceId);
        if (row) {
            row.gaps_detectable = JSON.parse(row.gaps_detectable);
            row.gaps_not_detectable = JSON.parse(row.gaps_not_detectable);
        }
        return row;
    }
    // ── Schema inspection ──
    getTableColumns(tableName) {
        const rows = this.db.prepare(`PRAGMA table_info(${tableName})`).all();
        return rows.map((r) => r.name);
    }
    getAllTableNames() {
        const rows = this.db.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`).all();
        return rows.map((r) => r.name);
    }
    // ── Internal helpers ──
    buildRecordContent(record) {
        return {
            record_id: record.record_id,
            run_id: record.run_id,
            action_unit_id: record.action_unit_id,
            manifest_id: record.manifest_id,
            manifest_hash: record.manifest_hash,
            surface_id: record.surface_id,
            commitment_hash: record.commitment_hash,
            output_commitment: record.output_commitment,
            commitment_algorithm: record.commitment_algorithm,
            commitment_type: record.commitment_type,
            check_result: record.check_result,
            proof_level_achieved: record.proof_level_achieved,
            proof_pending: record.proof_pending,
            zkml_proof_pending: record.zkml_proof_pending,
            check_open_tst: record.check_open_tst,
            check_close_tst: record.check_close_tst,
            skip_rationale_hash: record.skip_rationale_hash,
            reviewer_credential: record.reviewer_credential,
            unverified_provenance: record.unverified_provenance,
            freshness_warning: record.freshness_warning,
            idempotency_key: record.idempotency_key,
            recorded_at: record.recorded_at,
        };
    }
    buildRecordContentFromRow(row) {
        return {
            record_id: row.record_id,
            run_id: row.run_id,
            action_unit_id: row.action_unit_id,
            manifest_id: row.manifest_id,
            manifest_hash: row.manifest_hash,
            surface_id: row.surface_id,
            commitment_hash: row.commitment_hash,
            output_commitment: row.output_commitment,
            commitment_algorithm: row.commitment_algorithm,
            commitment_type: row.commitment_type,
            check_result: row.check_result,
            proof_level_achieved: row.proof_level_achieved,
            proof_pending: row.proof_pending === 1,
            zkml_proof_pending: row.zkml_proof_pending === 1,
            check_open_tst: row.check_open_tst,
            check_close_tst: row.check_close_tst,
            skip_rationale_hash: row.skip_rationale_hash,
            reviewer_credential: row.reviewer_credential
                ? JSON.parse(row.reviewer_credential)
                : null,
            unverified_provenance: row.unverified_provenance === 1,
            freshness_warning: row.freshness_warning === 1,
            idempotency_key: row.idempotency_key,
            recorded_at: row.recorded_at,
        };
    }
    close() {
        this.db.close();
    }
}
//# sourceMappingURL=sqlite_store.js.map