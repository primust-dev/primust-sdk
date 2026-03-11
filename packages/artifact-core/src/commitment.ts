/**
 * Primust Artifact Core — Commitment Layer (P6-A)
 *
 * Poseidon2 (default, ZK-friendly) and SHA-256 (legacy fallback) commitments.
 * Pure implementation, no native bindings, WASM-compatible.
 *
 * PRIVACY INVARIANT: Raw content NEVER leaves the customer environment.
 * Only the commitment hash transits to Primust API.
 */

import { sha256 } from '@noble/hashes/sha256';
import { poseidon2Hash } from '@zkpassport/poseidon2';

import type { CommitmentAlgorithm, ProofLevel } from './types/artifact.js';

// ── Constants ──

/** ZK proof generation is always non-blocking. Non-negotiable. */
export const ZK_IS_BLOCKING = false as const;

/**
 * BN254 scalar field modulus.
 * All Poseidon2 field arithmetic operates modulo this prime.
 */
const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ── Types ──

export interface CommitmentResult {
  hash: string;
  algorithm: CommitmentAlgorithm;
}

// ── Helpers ──

/**
 * Convert bytes to BN254 field elements.
 * Each chunk of 31 bytes is interpreted as a big-endian unsigned integer
 * to stay within the BN254 scalar field modulus.
 */
function bytesToFieldElements(input: Uint8Array): bigint[] {
  if (input.length === 0) return [0n];

  const elements: bigint[] = [];
  const chunkSize = 31; // 31 bytes < 254 bits, always fits in BN254 field

  for (let i = 0; i < input.length; i += chunkSize) {
    const end = Math.min(i + chunkSize, input.length);
    let value = 0n;
    for (let j = i; j < end; j++) {
      value = (value << 8n) | BigInt(input[j]);
    }
    elements.push(value % BN254_MODULUS);
  }

  return elements;
}

/**
 * Poseidon2 hash over arbitrary bytes.
 * Converts to field elements, then applies Poseidon2 sponge-style:
 * absorb pairs of elements, squeeze final hash.
 */
function poseidon2(input: Uint8Array): string {
  const elements = bytesToFieldElements(input);

  // Sponge: absorb pairs of field elements
  let state = 0n;
  for (let i = 0; i < elements.length; i += 2) {
    const left = elements[i];
    const right = i + 1 < elements.length ? elements[i + 1] : 0n;
    state = poseidon2Hash([state + left, right]);
  }

  return 'poseidon2:' + state.toString(16).padStart(64, '0');
}

/**
 * SHA-256 hash over arbitrary bytes.
 */
function sha256Commit(input: Uint8Array): string {
  const hash = sha256(input);
  const hex = Array.from(hash)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return 'sha256:' + hex;
}

/**
 * Poseidon2 hash of two field elements (for Merkle tree internal nodes).
 */
function poseidon2Pair(left: bigint, right: bigint): bigint {
  return poseidon2Hash([left, right]);
}

/**
 * Parse a commitment hash string to extract the raw bigint value.
 * Accepts both 'poseidon2:hex' and 'sha256:hex' formats.
 */
function parseHashToField(hash: string): bigint {
  const colonIdx = hash.indexOf(':');
  if (colonIdx === -1) throw new Error(`Invalid hash format: ${hash}`);
  const hex = hash.slice(colonIdx + 1);
  return BigInt('0x' + hex) % BN254_MODULUS;
}

// ── Public API ──

/**
 * Compute a commitment hash over input bytes.
 *
 * @param input - Raw content bytes (NEVER transmitted — only the hash leaves the environment)
 * @param algorithm - 'poseidon2' (default, ZK-friendly) or 'sha256' (legacy fallback)
 */
export function commit(
  input: Uint8Array,
  algorithm: CommitmentAlgorithm = 'poseidon2',
): CommitmentResult {
  if (algorithm === 'sha256') {
    return { hash: sha256Commit(input), algorithm: 'sha256' };
  }
  return { hash: poseidon2(input), algorithm: 'poseidon2' };
}

/**
 * Compute a commitment hash for check output.
 * Always uses poseidon2 — output_commitment is poseidon2-only invariant.
 */
export function commitOutput(output: Uint8Array): CommitmentResult {
  return { hash: poseidon2(output), algorithm: 'poseidon2' };
}

/**
 * Build a Merkle root over an array of commitment hashes.
 *
 * @returns poseidon2 Merkle root, or null for empty array.
 *          Single hash → returns that hash unchanged.
 *          Uses poseidon2 for all intermediate nodes.
 */
export function buildCommitmentRoot(hashes: string[]): string | null {
  if (hashes.length === 0) return null;
  if (hashes.length === 1) return hashes[0];

  // Convert to field elements
  let layer = hashes.map(parseHashToField);

  // Build binary Merkle tree bottom-up
  while (layer.length > 1) {
    const next: bigint[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      // Odd leaf: duplicate last
      const right = i + 1 < layer.length ? layer[i + 1] : layer[i];
      next.push(poseidon2Pair(left, right));
    }
    layer = next;
  }

  return 'poseidon2:' + layer[0].toString(16).padStart(64, '0');
}

// ── Proof Level Selection ──

/** Stage types that map to proof levels. */
type StageType =
  | 'deterministic_rule'
  | 'ml_model'
  | 'zkml_model'
  | 'statistical_test'
  | 'custom_code'
  | 'human_review';

/**
 * Select the proof level for a given stage type.
 *
 * Mapping:
 *   deterministic_rule → mathematical
 *   zkml_model         → execution_zkml
 *   ml_model           → execution
 *   statistical_test   → execution (default; non-deterministic sampling/bootstrapping)
 *   custom_code        → execution
 *   human_review       → witnessed
 *
 * Note: attestation is the weakest level and only applies from explicit manifest
 * declaration, not from stage type mapping.
 */
export function selectProofLevel(stageType: StageType): ProofLevel {
  switch (stageType) {
    case 'deterministic_rule':
      return 'mathematical';
    case 'zkml_model':
      return 'execution_zkml';
    case 'ml_model':
      return 'execution';
    case 'statistical_test':
      return 'execution';
    case 'custom_code':
      return 'execution';
    case 'human_review':
      return 'witnessed';
  }
}
