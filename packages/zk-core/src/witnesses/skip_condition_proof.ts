/**
 * Witness builder for skip_condition_proof circuit.
 *
 * Proves that a recorded skip was justified — the declared skip
 * condition evaluated to true. Upgrades skip records from attestation
 * to mathematical proof level.
 */

import { commit } from '@primust/artifact-core';
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
export function buildSkipConditionWitness(
  record: CheckExecutionRecord,
  snapshot: PolicySnapshot,
  conditionValues: bigint[],
  blindingFactor: bigint,
): SkipConditionInputs {
  // Validate: at least one condition value must be non-zero
  const hasNonZero = conditionValues.some((v) => v !== 0n);
  if (!hasNonZero) {
    throw new Error(
      'skip_condition_proof: all condition_values are zero — vacuous skip cannot be proven',
    );
  }

  // Pad condition_values to 16 elements
  const paddedValues = Array(16).fill(0n) as bigint[];
  for (let i = 0; i < Math.min(conditionValues.length, 16); i++) {
    paddedValues[i] = conditionValues[i];
  }

  // Compute skip_condition_hash: Poseidon2(condition_values ++ blinding_factor)
  // Encode as bytes for commit(): each bigint as 32-byte big-endian, concatenated
  const hashInput = new Uint8Array(17 * 32);
  for (let i = 0; i < 16; i++) {
    const bytes = bigintToBytes32(paddedValues[i]);
    hashInput.set(bytes, i * 32);
  }
  hashInput.set(bigintToBytes32(blindingFactor), 16 * 32);
  const { hash: skipConditionHash } = commit(hashInput, 'poseidon2');

  // commitment_root from the record's commitment chain
  const commitmentRoot =
    record.commitment_hash ?? 'poseidon2:' + '0'.repeat(64);

  // Merkle path placeholder (real path computed from store in production)
  const merklePath = Array(20).fill(0n) as bigint[];
  const merkleIndex = 0;

  return {
    skip_condition_hash: skipConditionHash,
    commitment_root: commitmentRoot,
    condition_values: paddedValues,
    blinding_factor: blindingFactor,
    merkle_path: merklePath,
    merkle_index: merkleIndex,
    run_id: record.run_id,
    manifest_id: record.manifest_id,
    policy_snapshot_hash:
      snapshot.policy_pack_id + ':' + snapshot.policy_pack_version,
  };
}

/** Convert a bigint to 32-byte big-endian Uint8Array. */
function bigintToBytes32(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}
