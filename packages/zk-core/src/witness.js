/**
 * Primust ZK Core — Witness Builder (P6-B)
 *
 * Bridges SqliteStore check records to circuit private inputs.
 * Produces a WitnessInput that can be submitted to the prover.
 */
import { buildCommitmentRoot } from '@primust/artifact-core';
/** Maximum records per proof (must match Noir circuit MAX_RECORDS). */
export const MAX_RECORDS = 64;
/** Maps CheckResult string to u8 for circuit input. */
const CHECK_RESULT_TO_U8 = {
    pass: 0,
    fail: 1,
    error: 2,
    skipped: 3,
    degraded: 4,
    override: 5,
    not_applicable: 6,
    timed_out: 7,
};
/**
 * Build a witness from all CheckExecutionRecords in a run.
 *
 * @param runId - The process run to build witness for
 * @param store - SqliteStore instance
 * @param policySnapshotHash - The policy snapshot hash for this run
 * @returns WitnessInput ready for circuit proving
 */
export function buildWitness(runId, store, policySnapshotHash) {
    const records = store.getCheckRecords(runId);
    if (records.length > MAX_RECORDS) {
        throw new Error(`Record count ${records.length} exceeds MAX_RECORDS ${MAX_RECORDS}`);
    }
    const commitmentHashes = [];
    const checkResults = [];
    const manifestHashValues = [];
    for (const record of records) {
        commitmentHashes.push(record.commitment_hash);
        checkResults.push(CHECK_RESULT_TO_U8[record.check_result] ?? 2);
        manifestHashValues.push(record.manifest_hash);
    }
    // Compute commitment root using Poseidon2 — Noir circuits use Poseidon2
    // natively for in-circuit Merkle tree verification. This root is for ZK
    // proof public inputs, separate from the VPEC commitment_root (which uses SHA-256).
    const root = buildCommitmentRoot(records.map((r) => r.commitment_hash), 'poseidon2');
    // Pad to MAX_RECORDS for fixed-size circuit input
    const recordCount = records.length;
    while (commitmentHashes.length < MAX_RECORDS) {
        commitmentHashes.push('poseidon2:' + '0'.repeat(64));
        checkResults.push(0);
        manifestHashValues.push('sha256:' + '0'.repeat(64));
    }
    return {
        commitment_root: root ?? 'poseidon2:' + '0'.repeat(64),
        policy_snapshot_hash: policySnapshotHash,
        commitment_hashes: commitmentHashes,
        check_results: checkResults,
        manifest_hash_values: manifestHashValues,
        record_count: recordCount,
    };
}
//# sourceMappingURL=witness.js.map