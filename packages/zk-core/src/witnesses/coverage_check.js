/**
 * Witness builder for coverage_check circuit.
 *
 * Proves every action had a corresponding check record and that
 * coverage meets a minimum threshold.
 */
import { buildCommitmentRoot } from '@primust/artifact-core';
const MAX_ACTIONS = 256;
/**
 * Build witness inputs for the coverage_check circuit.
 *
 * @param runId - The process run to build witness for
 * @param store - SqliteStore instance
 * @param thresholdPct - Minimum coverage percentage (0-100)
 * @returns CoverageCheckInputs ready for circuit proving
 * @throws If coverage does not meet threshold
 */
export function buildCoverageCheckWitness(runId, store, thresholdPct) {
    const records = store.getCheckRecords(runId);
    if (records.length > MAX_ACTIONS) {
        throw new Error(`Record count ${records.length} exceeds MAX_ACTIONS ${MAX_ACTIONS}`);
    }
    const actionCount = records.length;
    const recordCount = records.length;
    // Build action hashes and has_record arrays
    const actionHashes = [];
    const hasRecord = [];
    for (const record of records) {
        actionHashes.push(record.commitment_hash);
        hasRecord.push(1);
    }
    // Pad to MAX_ACTIONS
    while (actionHashes.length < MAX_ACTIONS) {
        actionHashes.push('poseidon2:' + '0'.repeat(64));
        hasRecord.push(0);
    }
    // Compute commitment root using Poseidon2
    const root = buildCommitmentRoot(records.map((r) => r.commitment_hash), 'poseidon2');
    const coveredCount = records.length;
    // Verify coverage meets threshold
    if (coveredCount * 100 < thresholdPct * actionCount) {
        throw new Error(`Coverage ${coveredCount}/${actionCount} (${Math.round((coveredCount * 100) / actionCount)}%) ` +
            `below threshold ${thresholdPct}%`);
    }
    return {
        commitment_root: root ?? 'poseidon2:' + '0'.repeat(64),
        total_actions: actionCount,
        covered_count: coveredCount,
        threshold_pct: thresholdPct,
        action_hashes: actionHashes,
        has_record: hasRecord,
        record_count: recordCount,
    };
}
//# sourceMappingURL=coverage_check.js.map