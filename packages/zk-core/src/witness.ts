/**
 * Primust ZK Core — Witness Builder (P6-B)
 *
 * Bridges SqliteStore check records to circuit private inputs.
 * Produces a WitnessInput that can be submitted to the prover.
 */

import { buildCommitmentRoot } from '@primust/artifact-core';
import type { SqliteStore } from '@primust/runtime-core';

import type { WitnessInput } from './types.js';

/** Maximum records per proof (must match Noir circuit MAX_RECORDS). */
export const MAX_RECORDS = 64;

/** Maps CheckResult string to u8 for circuit input. */
const CHECK_RESULT_TO_U8: Record<string, number> = {
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
export function buildWitness(
  runId: string,
  store: SqliteStore,
  policySnapshotHash: string,
): WitnessInput {
  const records = store.getCheckRecords(runId);

  if (records.length > MAX_RECORDS) {
    throw new Error(
      `Record count ${records.length} exceeds MAX_RECORDS ${MAX_RECORDS}`,
    );
  }

  const commitmentHashes: string[] = [];
  const checkResults: number[] = [];
  const manifestHashValues: string[] = [];

  for (const record of records) {
    commitmentHashes.push(record.commitment_hash as string);
    checkResults.push(
      CHECK_RESULT_TO_U8[record.check_result as string] ?? 2,
    );
    manifestHashValues.push(record.manifest_hash as string);
  }

  // Compute commitment root using Poseidon2 — Noir circuits use Poseidon2
  // natively for in-circuit Merkle tree verification. This root is for ZK
  // proof public inputs, separate from the VPEC commitment_root (which uses SHA-256).
  const root = buildCommitmentRoot(
    records.map((r) => r.commitment_hash as string),
    'poseidon2',
  );

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
