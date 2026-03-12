import { describe, it, expect } from 'vitest';
import {
  computeProofCeiling,
  computeManifestHash,
  validateManifest,
  bindBenchmark,
  validateRecordFields,
  PROOF_LEVEL_HIERARCHY,
} from './manifest_validator.js';
import type { CheckManifest, ManifestBenchmark, CheckExecutionRecord } from '@primust/runtime-core';

// ── Helpers ──

function makeManifest(overrides: Partial<CheckManifest> = {}): CheckManifest {
  return {
    manifest_id: 'placeholder',
    manifest_hash: 'sha256:' + 'a'.repeat(64),
    domain: 'ai_agent',
    name: 'test_check',
    semantic_version: '1.0.0',
    check_type: 'safety_check',
    implementation_type: 'rule',
    supported_proof_level: 'execution',
    evaluation_scope: 'per_run',
    evaluation_window_seconds: null,
    stages: [
      {
        stage: 1,
        name: 'ML Eval',
        type: 'ml_model',
        proof_level: 'execution',
        redacted: false,
      },
    ],
    aggregation_config: {
      method: 'all_stages_must_pass',
      threshold: null,
    },
    freshness_threshold_hours: null,
    benchmark: null,
    model_or_tool_hash: null,
    publisher: 'primust',
    signer_id: 'signer_test',
    kid: 'kid_test',
    signed_at: '2026-03-10T00:00:00Z',
    signature: {
      signer_id: 'signer_test',
      kid: 'kid_test',
      algorithm: 'Ed25519',
      signature: 'sig_placeholder',
      signed_at: '2026-03-10T00:00:00Z',
    },
    ...overrides,
  } as CheckManifest;
}

function makeRecord(overrides: Partial<CheckExecutionRecord> = {}): CheckExecutionRecord {
  return {
    record_id: 'rec_001',
    run_id: 'run_001',
    action_unit_id: 'au_1',
    manifest_id: 'manifest_001',
    manifest_hash: 'sha256:' + 'a'.repeat(64),
    surface_id: 'surf_001',
    commitment_hash: 'poseidon2:' + 'b'.repeat(64),
    output_commitment: null,
    commitment_algorithm: 'poseidon2',
    commitment_type: 'input_commitment',
    check_result: 'pass',
    proof_level_achieved: 'execution',
    proof_pending: false,
    zkml_proof_pending: false,
    check_open_tst: null,
    check_close_tst: null,
    skip_rationale_hash: null,
    reviewer_credential: null,
    unverified_provenance: false,
    freshness_warning: false,
    chain_hash: 'sha256:' + 'c'.repeat(64),
    idempotency_key: 'idem_001',
    recorded_at: '2026-03-10T00:00:00Z',
    ...overrides,
  } as CheckExecutionRecord;
}

// ── Tests ──

describe('Manifest Validator', () => {
  // ── MUST PASS: human_review → witnessed ──

  it('human_review stage → computeProofCeiling returns witnessed', () => {
    const manifest = makeManifest({
      supported_proof_level: 'witnessed',
      stages: [
        { stage: 1, name: 'Human Review', type: 'witnessed', proof_level: 'witnessed', redacted: false },
      ],
    });

    expect(computeProofCeiling(manifest)).toBe('witnessed');
  });

  // ── MUST PASS: human_review → NEVER attestation ──

  it('human_review stage → proof ceiling NEVER returns attestation', () => {
    const manifest = makeManifest({
      supported_proof_level: 'attestation',
      stages: [
        { stage: 1, name: 'Human Review', type: 'witnessed', proof_level: 'attestation', redacted: false },
      ],
    });

    const errors = validateManifest(manifest);
    const stageError = errors.find((e) => e.code === 'witnessed_attestation_forbidden');
    expect(stageError).not.toBeUndefined();
    expect(stageError!.code).toBe('witnessed_attestation_forbidden');
  });

  // ── MUST PASS: manual proof level above ceiling → error ──

  it('manual supported_proof_level above computed ceiling → validation error', () => {
    const manifest = makeManifest({
      supported_proof_level: 'mathematical',
      stages: [
        { stage: 1, name: 'ML Eval', type: 'ml_model', proof_level: 'execution', redacted: false },
      ],
    });

    const errors = validateManifest(manifest);
    const aboveError = errors.find((e) => e.code === 'proof_level_above_ceiling');
    expect(aboveError).not.toBeUndefined();
    expect(aboveError!.code).toBe('proof_level_above_ceiling');
  });

  // ── MUST PASS: deterministic hash ──

  it('manifest_hash = SHA256(canonical(manifest)) — deterministic', () => {
    const manifest = makeManifest();
    const hash1 = computeManifestHash(manifest);
    const hash2 = computeManifestHash(manifest);

    expect(hash1).toBe(hash2);
    expect(hash1).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  // ── MUST PASS: manifest_id = manifest_hash ──

  it('manifest_id = manifest_hash (content-addressed)', () => {
    const manifest = makeManifest();
    const hash = computeManifestHash(manifest);

    // After proper registration, manifest_id should equal the computed hash
    expect(hash).toMatch(/^sha256:[0-9a-f]{64}$/);

    // A well-formed manifest has manifest_id === manifest_hash === computeManifestHash
    const wellFormed = makeManifest({
      manifest_id: hash,
      manifest_hash: hash,
    });
    expect(wellFormed.manifest_id).toBe(wellFormed.manifest_hash);
    expect(wellFormed.manifest_id).toBe(computeManifestHash(wellFormed));
  });

  // ── MUST PASS: benchmark present → hash changes ──

  it('benchmark present → benchmark_hash included in manifest canonical content', () => {
    const benchmarkA: ManifestBenchmark = {
      benchmark_id: 'bench_001',
      benchmark_hash: 'sha256:' + 'a'.repeat(64),
      precision: 0.95,
      recall: 0.92,
      f1: 0.935,
      test_dataset: 'test_v1',
      published_by: 'primust',
    };
    const benchmarkB: ManifestBenchmark = {
      benchmark_id: 'bench_002',
      benchmark_hash: 'sha256:' + 'b'.repeat(64),
      precision: 0.88,
      recall: 0.85,
      f1: 0.865,
      test_dataset: 'test_v2',
      published_by: 'primust',
    };

    const manifestA = makeManifest({ benchmark: benchmarkA });
    const manifestB = makeManifest({ benchmark: benchmarkB });

    const hashA = computeManifestHash(manifestA);
    const hashB = computeManifestHash(manifestB);

    expect(hashA).not.toBe(hashB);
  });

  // ── MUST PASS: benchmark absent → null, no impact ──

  it('benchmark absent → benchmark field null, no impact on manifest_hash', () => {
    const manifest = makeManifest({ benchmark: null });
    const hash = computeManifestHash(manifest);

    expect(manifest.benchmark).toBeNull();
    expect(hash).toMatch(/^sha256:[0-9a-f]{64}$/);

    // Same manifest without benchmark produces the same hash
    const manifest2 = makeManifest({ benchmark: null });
    expect(computeManifestHash(manifest2)).toBe(hash);
  });

  // ── MUST PASS: all 5 proof levels valid ──

  it('all 5 proof levels valid in PROOF_LEVEL_HIERARCHY', () => {
    expect(PROOF_LEVEL_HIERARCHY).toEqual([
      'mathematical',
      'verifiable_inference',
      'execution',
      'witnessed',
      'attestation',
    ]);
    expect(PROOF_LEVEL_HIERARCHY.length).toBe(5);
  });

  // ── MUST PASS: zkml_model → verifiable_inference ──

  it('zkml_model stage → proof ceiling = verifiable_inference', () => {
    const manifest = makeManifest({
      supported_proof_level: 'verifiable_inference',
      stages: [
        { stage: 1, name: 'ZKML Eval', type: 'zkml_model', proof_level: 'verifiable_inference', redacted: false },
      ],
    });

    expect(computeProofCeiling(manifest)).toBe('verifiable_inference');
  });

  // ── MUST PASS: skip_rationale_hash required when not_applicable ──

  it('skip_rationale_hash required when check_result = not_applicable', () => {
    const record = makeRecord({
      check_result: 'not_applicable',
      skip_rationale_hash: null,
    });

    const errors = validateRecordFields(record);
    const skipError = errors.find((e) => e.code === 'skip_rationale_hash_missing');
    expect(skipError).not.toBeUndefined();
    expect(skipError!.code).toBe('skip_rationale_hash_missing');
  });

  // ── Additional: proof ceiling with mixed stages ──

  it('mixed stages → proof ceiling is weakest', () => {
    const manifest = makeManifest({
      supported_proof_level: 'witnessed',
      stages: [
        { stage: 1, name: 'Rule', type: 'deterministic_rule', proof_level: 'mathematical', redacted: false },
        { stage: 2, name: 'Review', type: 'witnessed', proof_level: 'witnessed', redacted: false },
      ],
    });

    expect(computeProofCeiling(manifest)).toBe('witnessed');
  });

  // ── Additional: bindBenchmark ──

  it('bindBenchmark attaches benchmark to manifest', () => {
    const manifest = makeManifest({ benchmark: null });
    const benchmark: ManifestBenchmark = {
      benchmark_id: 'bench_001',
      benchmark_hash: 'sha256:' + 'a'.repeat(64),
      precision: 0.95,
      recall: 0.92,
      f1: 0.935,
      test_dataset: 'test_v1',
      published_by: 'primust',
    };

    const bound = bindBenchmark(manifest, benchmark);
    expect(bound.benchmark).toBe(benchmark);
    expect(bound.name).toBe(manifest.name); // other fields preserved
  });
});
