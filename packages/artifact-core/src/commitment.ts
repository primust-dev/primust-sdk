/**
 * Primust Artifact Core — Commitment Layer (P6-A)
 *
 * SHA-256 (default) and Poseidon2 (opt-in via PRIMUST_COMMITMENT_ALGORITHM=poseidon2) commitments.
 * Poseidon2 uses a pure implementation — opt-in only until an audited reference
 * (e.g. Barretenberg) is validated.
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
 * @param algorithm - 'sha256' (default) or 'poseidon2' (opt-in). If not specified, uses
 *                    PRIMUST_COMMITMENT_ALGORITHM env var or defaults to 'sha256'.
 */
export function commit(
  input: Uint8Array,
  algorithm?: CommitmentAlgorithm,
): CommitmentResult {
  const alg = algorithm ?? resolveAlgorithm();
  if (alg === 'poseidon2') {
    return { hash: poseidon2(input), algorithm: 'poseidon2' };
  }
  return { hash: sha256Commit(input), algorithm: 'sha256' };
}

/**
 * Compute a commitment hash for check output. Uses resolved algorithm.
 */
export function commitOutput(output: Uint8Array): CommitmentResult {
  const alg = resolveAlgorithm();
  if (alg === 'poseidon2') {
    return { hash: poseidon2(output), algorithm: 'poseidon2' };
  }
  return { hash: sha256Commit(output), algorithm: 'sha256' };
}

/**
 * Resolve the commitment algorithm.
 * Default is "sha256". Poseidon2 is opt-in via PRIMUST_COMMITMENT_ALGORITHM=poseidon2
 * until an audited implementation (e.g. Barretenberg) is validated.
 */
function resolveAlgorithm(): CommitmentAlgorithm {
  if (typeof process !== 'undefined' && process.env?.PRIMUST_COMMITMENT_ALGORITHM === 'poseidon2') {
    return 'poseidon2';
  }
  return 'sha256';
}

/**
 * Parse a commitment hash string to raw bytes.
 */
function parseHashToRawBytes(hash: string): Uint8Array {
  const colonIdx = hash.indexOf(':');
  if (colonIdx === -1) throw new Error(`Invalid hash format: ${hash}`);
  const hex = hash.slice(colonIdx + 1);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Build a Merkle root over an array of commitment hashes.
 * Uses the resolved algorithm (SHA-256 default, Poseidon2 opt-in) for intermediate nodes.
 *
 * @returns Merkle root, or null for empty array.
 *          Single hash → returns that hash unchanged.
 */
export function buildCommitmentRoot(hashes: string[], algorithm?: CommitmentAlgorithm): string | null {
  const alg = algorithm ?? resolveAlgorithm();
  if (hashes.length === 0) return null;
  if (hashes.length === 1) return hashes[0];

  if (alg === 'poseidon2') {
    return buildPoseidon2MerkleRoot(hashes);
  }
  return buildSha256MerkleRoot(hashes);
}

function buildPoseidon2MerkleRoot(hashes: string[]): string {
  let layer = hashes.map(parseHashToField);

  while (layer.length > 1) {
    const next: bigint[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : layer[i];
      next.push(poseidon2Pair(left, right));
    }
    layer = next;
  }

  return 'poseidon2:' + layer[0].toString(16).padStart(64, '0');
}

function buildSha256MerkleRoot(hashes: string[]): string {
  let layer = hashes.map(parseHashToRawBytes);

  while (layer.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : layer[i];
      const combined = new Uint8Array(left.length + right.length);
      combined.set(left);
      combined.set(right, left.length);
      next.push(sha256(combined));
    }
    layer = next;
  }

  return 'sha256:' + Array.from(layer[0]).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Proof Level Selection ──

/** Stage types that map to proof levels. */
type StageType =
  | 'deterministic_rule'
  | 'ml_model'
  | 'zkml_model'
  | 'statistical_test'
  | 'custom_code'
  | 'witnessed'
  | 'policy_engine';

/**
 * Select the proof level for a given stage type.
 *
 * Mapping:
 *   deterministic_rule → mathematical
 *   zkml_model         → verifiable_inference
 *   ml_model           → execution
 *   statistical_test   → execution (default; non-deterministic sampling/bootstrapping)
 *   custom_code        → execution
 *   witnessed          → witnessed
 *
 * Note: attestation is the weakest level and only applies from explicit manifest
 * declaration, not from stage type mapping.
 */
export function selectProofLevel(stageType: StageType): ProofLevel {
  switch (stageType) {
    case 'deterministic_rule':
      return 'mathematical';
    case 'zkml_model':
      return 'verifiable_inference';
    case 'ml_model':
      return 'execution';
    case 'statistical_test':
      return 'execution';
    case 'custom_code':
      return 'execution';
    case 'witnessed':
      return 'witnessed';
    case 'policy_engine':
      return 'mathematical';
  }
}
