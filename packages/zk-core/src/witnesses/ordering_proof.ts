/**
 * Witness builder for ordering_proof circuit.
 *
 * Proves monotonic sequence ordering with no gaps and that
 * the hash chain closes correctly.
 */

import { commit } from '@primust/artifact-core';
import type { SqliteStore } from '@primust/runtime-core';

import type { OrderingProofInputs } from '../types.js';

const MAX_SEQUENCE = 256;

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
export function buildOrderingProofWitness(
  runId: string,
  store: SqliteStore,
): OrderingProofInputs {
  const records = store.getCheckRecords(runId);

  if (records.length > MAX_SEQUENCE) {
    throw new Error(
      `Record count ${records.length} exceeds MAX_SEQUENCE ${MAX_SEQUENCE}`,
    );
  }

  if (records.length === 0) {
    throw new Error('ordering_proof: no records to prove ordering for');
  }

  // Extract sequence values from record timestamps (as unix epoch ms)
  const sequenceValues: string[] = [];
  for (const record of records) {
    const ts = new Date(record.recorded_at as string).getTime();
    sequenceValues.push('poseidon2:' + BigInt(ts).toString(16).padStart(64, '0'));
  }

  // Verify monotonic ordering
  for (let i = 0; i < sequenceValues.length - 1; i++) {
    if (sequenceValues[i] >= sequenceValues[i + 1]) {
      throw new Error(
        `ordering_proof: records not monotonically ordered at index ${i}`,
      );
    }
  }

  // Compute hash chain: start with v[0], then H(chain, v[i+1]) for each subsequent
  // For the circuit, chain_root is the terminal hash
  const count = records.length;
  // First value as bytes
  const firstTs = BigInt(new Date(records[0].recorded_at as string).getTime());

  let chainHash = 'poseidon2:' + firstTs.toString(16).padStart(64, '0');
  if (count > 1) {
    for (let i = 1; i < count; i++) {
      const nextTs = BigInt(new Date(records[i].recorded_at as string).getTime());
      const pairInput = new Uint8Array(64);
      pairInput.set(bigintToBytes32(BigInt('0x' + chainHash.replace('poseidon2:', ''))), 0);
      pairInput.set(bigintToBytes32(nextTs), 32);
      const { hash } = commit(pairInput, 'poseidon2');
      chainHash = hash;
    }
  }

  // Pad to MAX_SEQUENCE
  while (sequenceValues.length < MAX_SEQUENCE) {
    sequenceValues.push('poseidon2:' + '0'.repeat(64));
  }

  return {
    chain_root: chainHash,
    sequence_length: count,
    sequence_values: sequenceValues,
    sequence_count: count,
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
