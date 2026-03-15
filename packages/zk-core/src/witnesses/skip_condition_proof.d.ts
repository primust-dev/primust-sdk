/**
 * Witness builder for skip_condition_proof circuit.
 *
 * Proves that a recorded skip was justified — the declared skip
 * condition evaluated to true. Upgrades skip records from attestation
 * to mathematical proof level.
 */
import type { CheckExecutionRecord, PolicySnapshot } from '@primust/runtime-core';
import type { SkipConditionInputs } from '../types.js';
/**
 * Build witness inputs for the skip_condition_proof circuit.
 *
 * @param record - The CheckExecutionRecord with the skip
 * @param snapshot - The PolicySnapshot at run time
 * @param conditionValues - The actual condition parameter values (max 16)
 * @param blindingFactor - Blinding factor for hash preimage hiding
 * @returns SkipConditionInputs ready for circuit proving
 * @throws If all condition values are zero (vacuous skip not provable)
 */
export declare function buildSkipConditionWitness(record: CheckExecutionRecord, snapshot: PolicySnapshot, conditionValues: bigint[], blindingFactor: bigint): SkipConditionInputs;
//# sourceMappingURL=skip_condition_proof.d.ts.map