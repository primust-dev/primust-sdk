/**
 * Witness builder for ordering_proof circuit.
 *
 * Proves monotonic sequence ordering with no gaps and that
 * the hash chain closes correctly.
 */
import type { SqliteStore } from '@primust/runtime-core';
import type { OrderingProofInputs } from '../types.js';
/**
 * Build witness inputs for the ordering_proof circuit.
 *
 * Extracts recorded_at timestamps from check records as monotonic
 * sequence values, then computes the hash chain terminal.
 *
 * @param runId - The process run to build witness for
 * @param store - SqliteStore instance
 * @returns OrderingProofInputs ready for circuit proving
 * @throws If records are not monotonically ordered
 */
export declare function buildOrderingProofWitness(runId: string, store: SqliteStore): OrderingProofInputs;
//# sourceMappingURL=ordering_proof.d.ts.map