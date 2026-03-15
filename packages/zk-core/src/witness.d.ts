/**
 * Primust ZK Core — Witness Builder (P6-B)
 *
 * Bridges SqliteStore check records to circuit private inputs.
 * Produces a WitnessInput that can be submitted to the prover.
 */
import type { SqliteStore } from '@primust/runtime-core';
import type { WitnessInput } from './types.js';
/** Maximum records per proof (must match Noir circuit MAX_RECORDS). */
export declare const MAX_RECORDS = 64;
/**
 * Build a witness from all CheckExecutionRecords in a run.
 *
 * @param runId - The process run to build witness for
 * @param store - SqliteStore instance
 * @param policySnapshotHash - The policy snapshot hash for this run
 * @returns WitnessInput ready for circuit proving
 */
export declare function buildWitness(runId: string, store: SqliteStore, policySnapshotHash: string): WitnessInput;
//# sourceMappingURL=witness.d.ts.map