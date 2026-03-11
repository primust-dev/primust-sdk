import { describe, it, expect } from 'vitest';
import { ManifestRegistry } from './manifest_registry.js';
import type { CheckManifest } from '@primust/runtime-core';

function makeManifest(overrides: Partial<CheckManifest> = {}): CheckManifest {
  return {
    manifest_id: 'placeholder', // will be replaced by registry
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
        name: 'Rule Eval',
        type: 'deterministic_rule',
        proof_level: 'mathematical',
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

describe('ManifestRegistry', () => {
  // ── MUST PASS: Registration is idempotent ──

  it('same content produces same manifest_id, created=false on second call', () => {
    const registry = new ManifestRegistry();
    const manifest = makeManifest();

    const first = registry.registerManifest(manifest);
    expect(first.created).toBe(true);
    expect(first.manifest_id).toMatch(/^sha256:/);

    const second = registry.registerManifest(manifest);
    expect(second.created).toBe(false);
    expect(second.manifest_id).toBe(first.manifest_id);
  });

  // ── MUST PASS: manifest_id is SHA-256 of canonical content ──

  it('manifest_id starts with sha256: prefix', () => {
    const registry = new ManifestRegistry();
    const result = registry.registerManifest(makeManifest());

    expect(result.manifest_id).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  // ── MUST PASS: getManifest returns registered manifest ──

  it('getManifest returns the registered manifest', () => {
    const registry = new ManifestRegistry();
    const manifest = makeManifest();
    const result = registry.registerManifest(manifest);

    const retrieved = registry.getManifest(result.manifest_id);
    expect(retrieved).toBeDefined();
    expect(retrieved!.name).toBe('test_check');
  });

  it('getManifest returns undefined for unknown id', () => {
    const registry = new ManifestRegistry();
    expect(registry.getManifest('sha256:nonexistent')).toBeUndefined();
  });

  // ── MUST PASS: Different content → different manifest_id ──

  it('different content produces different manifest_id', () => {
    const registry = new ManifestRegistry();

    const result1 = registry.registerManifest(makeManifest({ name: 'check_a' }));
    const result2 = registry.registerManifest(makeManifest({ name: 'check_b' }));

    expect(result1.manifest_id).not.toBe(result2.manifest_id);
    expect(result1.created).toBe(true);
    expect(result2.created).toBe(true);
  });

  // ── getManifestHash ──

  it('getManifestHash returns hash for registered manifest', () => {
    const registry = new ManifestRegistry();
    const manifest = makeManifest();
    const result = registry.registerManifest(manifest);

    const hash = registry.getManifestHash(result.manifest_id);
    expect(hash).toBe(manifest.manifest_hash);
  });

  it('getManifestHash returns undefined for unknown id', () => {
    const registry = new ManifestRegistry();
    expect(registry.getManifestHash('sha256:unknown')).toBeUndefined();
  });
});
