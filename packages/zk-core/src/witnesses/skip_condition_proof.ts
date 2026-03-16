/**
 * Witness builder for skip_condition_proof circuit.
 *
 * Proves that a recorded skip was justified — the declared skip
 * condition evaluated to true. Upgrades skip records from attestation
 * to mathematical proof level.
 */

import { commit, buildCommitmentRoot } from '@primust/artifact-core';
import type { CheckExecutionRecord, PolicySnapshot } from '@primust/runtime-core';

import type { SkipConditionInputs } from '../types.js';

/**
 * BN254 scalar field modulus — must match artifact-core.
 */
const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Parse a commitment hash string (e.g. "poseidon2:abcdef...") to a BN254 field element.
 */
function parseHashToField(hash: string): bigint {
  const colonIdx = hash.indexOf(':');
  if (colonIdx === -1) throw new Error(`Invalid hash format: ${hash}`);
  const hex = hash.slice(colonIdx + 1);
  return BigInt('0x' + hex) % BN254_MODULUS;
}

/**
 * Poseidon2 hash of two field elements, matching the circuit's Merkle node computation.
 * Uses the same @zkpassport/poseidon2 implementation as artifact-core.
 */
function poseidon2Pair(left: bigint, right: bigint): bigint {
  // Dynamic import to avoid duplicating the poseidon2Hash dependency;
  // artifact-core already depends on it, so it's available.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { poseidon2Hash } = require('@zkpassport/poseidon2') as { poseidon2Hash: (inputs: bigint[]) => bigint };
  return poseidon2Hash([left, right]);
}

/**
 * Compute a Merkle proof (sibling path + leaf index) for a given leaf
 * within a set of leaves. The tree construction mirrors buildCommitmentRoot
 * in artifact-core: leaves are paired left-to-right, odd leaves are
 * duplicated (hash(leaf, leaf)), and layers are built bottom-up.
 *
 * @param leaves - All leaf field elements in tree order
 * @param leafIndex - Index of the target leaf in the leaves array
 * @param depth - Maximum tree depth (number of sibling slots), default 20
 * @returns { path, index } where path[i] is the sibling at level i and
 *          index is the original leaf position (used for left/right decisions)
 */
function computeMerkleProof(
  leaves: bigint[],
  leafIndex: number,
  depth: number = 20,
): { path: bigint[]; index: number } {
  if (leafIndex < 0 || leafIndex >= leaves.length) {
    throw new Error(`Leaf index ${leafIndex} out of range [0, ${leaves.length})`);
  }

  const path: bigint[] = Array(depth).fill(0n);
  let layer = [...leaves];
  let idx = leafIndex;

  for (let level = 0; level < depth; level++) {
    if (layer.length <= 1) {
      // Remaining path entries stay 0 (circuit treats 0-siblings as "past the top")
      break;
    }

    // Determine sibling index
    const siblingIdx = (idx & 1) === 0 ? idx + 1 : idx - 1;

    // If sibling exists, use it; otherwise duplicate (odd leaf count)
    if (siblingIdx < layer.length) {
      path[level] = layer[siblingIdx];
    } else {
      path[level] = layer[idx]; // duplicate: hash(leaf, leaf)
    }

    // Build next layer (same pairing logic as buildPoseidon2MerkleRoot)
    const nextLayer: bigint[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : layer[i];
      nextLayer.push(poseidon2Pair(left, right));
    }
    layer = nextLayer;
    idx = idx >> 1;
  }

  return { path, index: leafIndex };
}

/**
 * Build witness inputs for the skip_condition_proof circuit.
 *
 * @param record - The CheckExecutionRecord with the skip
 * @param snapshot - The PolicySnapshot at run time
 * @param conditionValues - The actual condition parameter values (max 16)
 * @param blindingFactor - Blinding factor for hash preimage hiding
 * @param commitmentHashes - All commitment hashes (leaves) in the Merkle tree.
 *   When provided, the function computes the real Merkle proof path for the
 *   record's position. When omitted (single-record case), the record's own
 *   commitment_hash is used as the sole leaf (leaf == root, all siblings zero).
 * @returns SkipConditionInputs ready for circuit proving
 * @throws If all condition values are zero (vacuous skip not provable)
 */
export function buildSkipConditionWitness(
  record: CheckExecutionRecord,
  snapshot: PolicySnapshot,
  conditionValues: bigint[],
  blindingFactor: bigint,
  commitmentHashes?: string[],
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

  // Determine commitment_root and Merkle proof path
  let commitmentRoot: string;
  let merklePath: bigint[];
  let merkleIndex: number;

  if (commitmentHashes && commitmentHashes.length > 0) {
    // Multi-leaf tree: compute root from all leaves and extract proof path
    commitmentRoot = buildCommitmentRoot(commitmentHashes, 'poseidon2') ?? record.commitment_hash;

    // Find this record's leaf index in the tree
    const leafIndex = commitmentHashes.indexOf(record.commitment_hash);
    if (leafIndex === -1) {
      throw new Error(
        `skip_condition_proof: record commitment_hash not found in commitmentHashes array`,
      );
    }

    // Convert leaves to field elements and compute the proof
    const leafFields = commitmentHashes.map(parseHashToField);
    const proof = computeMerkleProof(leafFields, leafIndex);
    merklePath = proof.path;
    merkleIndex = proof.index;
  } else {
    // Single-leaf case: leaf IS the root, all siblings are zero, circuit
    // skips zero-sibling levels so current == root after zero iterations.
    commitmentRoot = record.commitment_hash ?? 'poseidon2:' + '0'.repeat(64);
    merklePath = Array(20).fill(0n) as bigint[];
    merkleIndex = 0;
  }

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
