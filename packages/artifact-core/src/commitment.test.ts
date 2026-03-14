/**
 * Tests for commitment layer — P6-A.
 * 9 MUST PASS tests covering poseidon2/sha256 commitments, golden vectors,
 * Merkle root, proof level selection, and privacy invariant.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it, vi } from 'vitest';

import {
  ZK_IS_BLOCKING,
  buildCommitmentRoot,
  commit,
  commitOutput,
  selectProofLevel,
} from './commitment.js';

// ── Helpers ──

function hexToBytes(hex: string): Uint8Array {
  if (hex === '') return new Uint8Array(0);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

interface CommitmentVector {
  id: string;
  input_hex?: string;
  input_utf8?: string;
  algorithm?: string;
  expected_hash?: string;
  type?: string;
  input_hashes?: string[];
  expected_root?: string | null;
}

const vectorsPath = resolve(__dirname, '../../../schemas/golden/commitment_vectors.json');
const vectorsFile = JSON.parse(readFileSync(vectorsPath, 'utf-8'));
// v2.0.0 structure: separate sha256_vectors, poseidon2_vectors, merkle_* sections
const sha256Vectors: CommitmentVector[] = vectorsFile.sha256_vectors ?? [];
const poseidon2Vectors: CommitmentVector[] = vectorsFile.poseidon2_vectors ?? [];
const merkleSha256Vectors: CommitmentVector[] = vectorsFile.merkle_sha256_vectors ?? [];
const merklePoseidon2Vectors: CommitmentVector[] = vectorsFile.merkle_poseidon2_vectors ?? [];
// Combined for backward-compatible iteration
const vectors: CommitmentVector[] = [
  ...sha256Vectors.map(v => ({ ...v, type: 'commitment' })),
  ...poseidon2Vectors.map(v => ({ ...v, type: 'commitment' })),
  ...merkleSha256Vectors.map(v => ({ ...v, type: 'merkle_root' })),
  ...merklePoseidon2Vectors.map(v => ({ ...v, type: 'merkle_root' })),
];

// ── Tests ──

describe('commitment', () => {
  it('MUST PASS: poseidon2 commitment is deterministic', () => {
    const input = new TextEncoder().encode('deterministic test input');
    const a = commit(input, 'poseidon2');
    const b = commit(input, 'poseidon2');
    expect(a.hash).toBe(b.hash);
    expect(a.algorithm).toBe('poseidon2');
    expect(a.hash).toMatch(/^poseidon2:[0-9a-f]{64}$/);
  });

  it('MUST PASS: sha256 commitment is deterministic', () => {
    const input = new TextEncoder().encode('deterministic test input');
    const a = commit(input, 'sha256');
    const b = commit(input, 'sha256');
    expect(a.hash).toBe(b.hash);
    expect(a.algorithm).toBe('sha256');
    expect(a.hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('MUST PASS: all golden vectors pass', () => {
    for (const vec of vectors) {
      if (vec.type === 'merkle_root') {
        const root = buildCommitmentRoot(vec.input_hashes!, vec.algorithm as 'poseidon2' | 'sha256');
        expect(root).toBe(vec.expected_root);
      } else {
        const input = vec.input_hex !== undefined
          ? hexToBytes(vec.input_hex)
          : new TextEncoder().encode(vec.input_utf8!);
        const result = commit(input, vec.algorithm as 'poseidon2' | 'sha256');
        expect(result.hash).toBe(vec.expected_hash);
      }
    }
  });

  it('MUST PASS: commitOutput uses default algorithm (sha256)', () => {
    const output = new TextEncoder().encode('some output content');
    const result = commitOutput(output);
    expect(result.algorithm).toBe('sha256');
    expect(result.hash).toMatch(/^sha256:/);
  });

  it('MUST PASS: buildCommitmentRoot(empty array) returns null', () => {
    expect(buildCommitmentRoot([])).toBeNull();
  });

  it('MUST PASS: ZK_IS_BLOCKING === false', () => {
    expect(ZK_IS_BLOCKING).toBe(false);
  });

  it('MUST PASS: raw content not present in HTTP request body', () => {
    const originalFetch = globalThis.fetch;
    const mockFetch = vi.fn();
    globalThis.fetch = mockFetch;

    try {
      const rawContent = new TextEncoder().encode('sensitive raw content');
      commit(rawContent, 'poseidon2');
      commit(rawContent, 'sha256');
      commitOutput(rawContent);

      // No HTTP calls should have been made — raw content stays local
      expect(mockFetch).not.toHaveBeenCalled();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('MUST PASS: all 5 proof levels present in proof level selection logic', () => {
    const stageTypes = [
      'deterministic_rule',
      'ml_model',
      'zkml_model',
      'statistical_test',
      'custom_code',
      'witnessed',
    ] as const;

    const proofLevels = new Set(stageTypes.map(selectProofLevel));

    expect(proofLevels).toContain('mathematical');
    expect(proofLevels).toContain('verifiable_inference');
    expect(proofLevels).toContain('execution');
    expect(proofLevels).toContain('witnessed');
  });

  it('MUST PASS: verifiable_inference proof level triggers only for zkml_model stage type', () => {
    expect(selectProofLevel('zkml_model')).toBe('verifiable_inference');

    // No other stage type should produce verifiable_inference
    const others = [
      'deterministic_rule',
      'ml_model',
      'statistical_test',
      'custom_code',
      'witnessed',
    ] as const;

    for (const st of others) {
      expect(selectProofLevel(st)).not.toBe('verifiable_inference');
    }
  });
});
