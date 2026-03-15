/**
 * Witness builder for coverage_check circuit.
 *
 * Proves every action had a corresponding check record and that
 * coverage meets a minimum threshold.
 */
import type { SqliteStore } from '@primust/runtime-core';
import type { CoverageCheckInputs } from '../types.js';
/**
 * Build witness inputs for the coverage_check circuit.
 *
 * @param runId - The process run to build witness for
 * @param store - SqliteStore instance
 * @param thresholdPct - Minimum coverage percentage (0-100)
 * @returns CoverageCheckInputs ready for circuit proving
 * @throws If coverage does not meet threshold
 */
export declare function buildCoverageCheckWitness(runId: string, store: SqliteStore, thresholdPct: number): CoverageCheckInputs;
//# sourceMappingURL=coverage_check.d.ts.map