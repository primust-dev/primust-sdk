import { describe, it, expect } from 'vitest';
import { validateArtifact } from './validate-artifact.js';
import type { VPECArtifact } from './types/artifact.js';

/** Build a valid VPEC artifact fixture. Override fields as needed. */
function validArtifact(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const base: VPECArtifact = {
    vpec_id: 'vpec_00000000-0000-0000-0000-000000000001',
    schema_version: '4.0.0',
    org_id: 'org_test',
    run_id: 'run_00000000-0000-0000-0000-000000000001',
    workflow_id: 'wf_test',
    process_context_hash: null,
    policy_snapshot_hash: 'sha256:' + 'a'.repeat(64),
    policy_basis: 'P1_self_declared',
    partial: false,
    surface_summary: [
      {
        surface_id: 'surf_1',
        surface_type: 'in_process_adapter',
        observation_mode: 'pre_action',
        proof_ceiling: 'execution',
        scope_type: 'full_workflow',
        scope_description: 'Full workflow adapter',
        surface_coverage_statement: 'All tool calls in graph scope',
      },
    ],
    proof_level: 'execution',
    proof_distribution: {
      mathematical: 0,
      verifiable_inference: 0,
      execution: 5,
      witnessed: 0,
      attestation: 0,
      weakest_link: 'execution',
      weakest_link_explanation: 'All checks ran in execution mode',
    },
    state: 'signed',
    coverage: {
      records_total: 5,
      records_pass: 4,
      records_fail: 0,
      records_degraded: 1,
      records_not_applicable: 0,
      policy_coverage_pct: 100,
      instrumentation_surface_pct: 95.5,
      instrumentation_surface_basis: 'LangGraph full_workflow adapter — all tool calls in graph scope.',
    },
    gaps: [],
    manifest_hashes: {
      'manifest_001': 'sha256:' + 'b'.repeat(64),
    },
    commitment_root: 'poseidon2:' + 'c'.repeat(64),
    commitment_algorithm: 'poseidon2',
    zk_proof: null,
    issuer: {
      signer_id: 'signer_test',
      kid: 'kid_test',
      algorithm: 'Ed25519',
      public_key_url: 'https://primust.com/.well-known/primust-pubkeys/abc123.pem',
      org_region: 'us',
    },
    signature: {
      signer_id: 'signer_test',
      kid: 'kid_test',
      algorithm: 'Ed25519',
      signature: 'dGVzdF9zaWduYXR1cmU',
      signed_at: '2026-03-10T00:00:00Z',
    },
    timestamp_anchor: {
      type: 'none',
      tsa: 'none',
      value: null,
    },
    transparency_log: {
      rekor_log_id: null,
      rekor_entry_url: null,
      published_at: null,
    },
    issued_at: '2026-03-10T00:00:00Z',
    pending_flags: {
      signature_pending: false,
      proof_pending: false,
      zkml_proof_pending: false,
      submission_pending: false,
      rekor_pending: true,
    },
    test_mode: false,
  };

  return { ...base, ...overrides } as unknown as Record<string, unknown>;
}

describe('validateArtifact', () => {
  it('valid artifact passes validation', () => {
    const result = validateArtifact(validArtifact());
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  describe('MUST PASS: invariant enforcement', () => {
    it('proof_level above weakest_link → validation error', () => {
      const artifact = validArtifact({
        proof_level: 'mathematical',
        proof_distribution: {
          mathematical: 0,
          verifiable_inference: 0,
          execution: 5,
          witnessed: 0,
          attestation: 0,
          weakest_link: 'execution',
          weakest_link_explanation: 'All checks ran in execution mode',
        },
      });

      const result = validateArtifact(artifact);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.code === 'PROOF_LEVEL_MISMATCH')).toBe(true);
    });

    it('reliance_mode field anywhere → validation error', () => {
      const artifact = validArtifact({ reliance_mode: 'full' });

      const result = validateArtifact(artifact);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.code === 'RELIANCE_MODE_FORBIDDEN')).toBe(true);
    });

    it('reliance_mode nested in sub-object → validation error', () => {
      const artifact = validArtifact();
      (artifact as any).coverage.reliance_mode = 'partial';

      const result = validateArtifact(artifact);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.code === 'RELIANCE_MODE_FORBIDDEN')).toBe(true);
    });

    it('manifest_hashes as array → validation error', () => {
      const artifact = validArtifact({
        manifest_hashes: ['sha256:' + 'a'.repeat(64)],
      });

      const result = validateArtifact(artifact);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.code === 'MANIFEST_HASHES_NOT_MAP')).toBe(true);
    });

    it('gaps with bare string IDs → validation error', () => {
      const artifact = validArtifact({
        gaps: ['gap_001', 'gap_002'],
      });

      const result = validateArtifact(artifact);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.code === 'GAP_BARE_STRING')).toBe(true);
    });

    it('test_mode: true + proof_pending: true → valid provisional artifact', () => {
      const artifact = validArtifact({
        test_mode: true,
        state: 'provisional',
        pending_flags: {
          signature_pending: false,
          proof_pending: true,
          zkml_proof_pending: false,
          submission_pending: false,
          rekor_pending: true,
        },
      });

      const result = validateArtifact(artifact);
      expect(result.valid).toBe(true);
    });

    it('schema_version: "4.0.0" on all issued artifacts', () => {
      const artifact = validArtifact({ schema_version: '2.0.0' });

      const result = validateArtifact(artifact);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.code === 'INVALID_SCHEMA_VERSION')).toBe(true);
    });

    it('all 5 proof levels valid in proof_level enum', () => {
      const levels = ['mathematical', 'verifiable_inference', 'execution', 'witnessed', 'attestation'];

      for (const level of levels) {
        const artifact = validArtifact({
          proof_level: level,
          proof_distribution: {
            mathematical: 0,
            verifiable_inference: 0,
            execution: 0,
            witnessed: 0,
            attestation: 0,
            [level]: 5,
            weakest_link: level,
            weakest_link_explanation: `All at ${level}`,
          },
        });

        const result = validateArtifact(artifact);
        expect(result.errors.filter((e) => e.code === 'INVALID_PROOF_LEVEL')).toHaveLength(0);
      }
    });

    it('all 16 gap types valid in gap_type enum', () => {
      const gapTypes = [
        'check_not_executed',
        'enforcement_override',
        'engine_error',
        'check_degraded',
        'external_boundary_traversal',
        'lineage_token_missing',
        'admission_gate_override',
        'check_timing_suspect',
        'reviewer_credential_invalid',
        'witnessed_display_missing',
        'witnessed_rationale_missing',
        'deterministic_consistency_violation',
        'skip_rationale_missing',
        'policy_config_drift',
        'zkml_proof_pending_timeout',
        'zkml_proof_failed',
      ];

      // 16 gap types — spec says 15 but there are 16 in the enum
      expect(gapTypes).toHaveLength(16);

      const gaps = gapTypes.map((gt, i) => ({
        gap_id: `gap_${i}`,
        gap_type: gt,
        severity: 'Medium',
      }));

      const artifact = validArtifact({ gaps });

      const result = validateArtifact(artifact);
      expect(result.errors.filter((e) => e.code === 'GAP_INVALID_TYPE_VALUE')).toHaveLength(0);
    });
  });

  describe('additional invariants', () => {
    it('partial: true with non-zero policy_coverage_pct → error', () => {
      const artifact = validArtifact({
        partial: true,
        coverage: {
          records_total: 5,
          records_pass: 3,
          records_fail: 0,
          records_degraded: 0,
          records_not_applicable: 2,
          policy_coverage_pct: 60,
          instrumentation_surface_pct: 100,
          instrumentation_surface_basis: 'Full scope',
        },
      });

      const result = validateArtifact(artifact);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.code === 'PARTIAL_COVERAGE_NOT_ZERO')).toBe(true);
    });

    it('partial: true with policy_coverage_pct 0 → valid', () => {
      const artifact = validArtifact({
        partial: true,
        coverage: {
          records_total: 5,
          records_pass: 3,
          records_fail: 0,
          records_degraded: 0,
          records_not_applicable: 2,
          policy_coverage_pct: 0,
          instrumentation_surface_pct: null,
          instrumentation_surface_basis: 'Partial — coverage not calculated',
        },
      });

      const result = validateArtifact(artifact);
      expect(result.valid).toBe(true);
    });

    it('issuer.public_key_url with wrong domain → error', () => {
      const artifact = validArtifact({
        issuer: {
          signer_id: 'signer_test',
          kid: 'kid_test',
          algorithm: 'Ed25519',
          public_key_url: 'https://evil.com/.well-known/primust-pubkeys/abc.pem',
          org_region: 'us',
        },
      });

      const result = validateArtifact(artifact);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.code === 'ISSUER_URL_INVALID')).toBe(true);
    });

    it('invalid gap_type value → error', () => {
      const artifact = validArtifact({
        gaps: [{ gap_id: 'g1', gap_type: 'nonexistent_type', severity: 'High' }],
      });

      const result = validateArtifact(artifact);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.code === 'GAP_INVALID_TYPE_VALUE')).toBe(true);
    });

    it('gap missing gap_type and severity → error', () => {
      const artifact = validArtifact({
        gaps: [{ gap_id: 'g1' }],
      });

      const result = validateArtifact(artifact);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.code === 'GAP_MISSING_FIELDS')).toBe(true);
    });

    it('invalid proof_level value → error', () => {
      const artifact = validArtifact({
        proof_level: 'quantum_proof',
        proof_distribution: {
          mathematical: 0,
          verifiable_inference: 0,
          execution: 0,
          witnessed: 0,
          attestation: 5,
          weakest_link: 'quantum_proof',
          weakest_link_explanation: 'invalid',
        },
      });

      const result = validateArtifact(artifact);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.code === 'INVALID_PROOF_LEVEL')).toBe(true);
    });
  });
});
