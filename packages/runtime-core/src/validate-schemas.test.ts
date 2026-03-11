import { describe, it, expect } from 'vitest';
import {
  scanBannedFields,
  validateManifestStage,
  validateCheckExecutionRecord,
  validateWaiver,
  validateEvidencePack,
} from './validate-schemas.js';
import type {
  ManifestStage,
  CheckExecutionRecord,
  Waiver,
  EvidencePack,
} from './types/index.js';

// ── Helpers ──

function makeCheckRecord(overrides: Partial<CheckExecutionRecord> = {}): CheckExecutionRecord {
  return {
    record_id: 'rec_001',
    run_id: 'run_001',
    action_unit_id: 'au_001',
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
  };
}

function makeWaiver(overrides: Partial<Waiver> = {}): Waiver {
  return {
    waiver_id: 'waiver_001',
    gap_id: 'gap_001',
    org_id: 'org_test',
    requestor_user_id: 'user_req',
    approver_user_id: 'user_apr',
    reason: 'This is a sufficiently long reason that explains why this waiver is needed for the gap.',
    compensating_control: null,
    expires_at: '2026-04-10T00:00:00Z', // 31 days from approved_at
    signature: {
      signer_id: 'signer_test',
      kid: 'kid_test',
      algorithm: 'Ed25519',
      signature: 'sig_placeholder',
      signed_at: '2026-03-10T00:00:00Z',
    },
    approved_at: '2026-03-10T00:00:00Z',
    ...overrides,
  };
}

function makeEvidencePack(overrides: Partial<EvidencePack> = {}): EvidencePack {
  return {
    pack_id: 'pack_001',
    org_id: 'org_test',
    period_start: '2026-03-01T00:00:00Z',
    period_end: '2026-03-10T00:00:00Z',
    artifact_ids: ['vpec_001'],
    merkle_root: 'sha256:' + 'd'.repeat(64),
    proof_distribution: {
      mathematical: 0,
      execution_zkml: 0,
      execution: 5,
      witnessed: 0,
      attestation: 0,
    },
    coverage_verified_pct: 80,
    coverage_pending_pct: 15,
    coverage_ungoverned_pct: 5,
    observation_summary: [
      {
        surface_id: 'surf_1',
        surface_coverage_statement: 'All tool calls',
      },
    ],
    gap_summary: {
      Critical: 0,
      High: 0,
      Medium: 1,
      Low: 0,
      Informational: 0,
    },
    report_hash: 'sha256:' + 'e'.repeat(64),
    signature: {
      signer_id: 'signer_test',
      kid: 'kid_test',
      algorithm: 'Ed25519',
      signature: 'sig_placeholder',
      signed_at: '2026-03-10T00:00:00Z',
    },
    timestamp_anchor: {
      type: 'none',
      tsa: 'none',
      value: null,
    },
    generated_at: '2026-03-10T00:00:00Z',
    ...overrides,
  };
}

// ── Tests ──

describe('scanBannedFields', () => {
  it('returns empty for clean object', () => {
    expect(scanBannedFields({ name: 'test', org_id: 'org_1' })).toEqual([]);
  });

  it('detects reliance_mode at top level', () => {
    const errors = scanBannedFields({ reliance_mode: 'full' });
    expect(errors.length).toBe(1);
    expect(errors[0].code).toBe('banned_field_reliance_mode');
  });

  it('detects agent_id nested in object', () => {
    const errors = scanBannedFields({
      config: { agent_id: 'agent_123' },
    });
    expect(errors.length).toBe(1);
    expect(errors[0].code).toBe('banned_field_agent_id');
    expect(errors[0].message).toContain('config.agent_id');
  });

  it('detects banned fields in arrays', () => {
    const errors = scanBannedFields({
      items: [{ pipeline_id: 'p1' }, { ok: true }],
    });
    expect(errors.length).toBe(1);
    expect(errors[0].code).toBe('banned_field_pipeline_id');
  });

  it('detects all 8 banned field names', () => {
    const obj = {
      agent_id: 'x',
      pipeline_id: 'x',
      tool_name: 'x',
      session_id: 'x',
      trace_id: 'x',
      reliance_mode: 'x',
      PGC: 'x',
      attestation: 'x',
    };
    const errors = scanBannedFields(obj);
    expect(errors.length).toBe(8);
  });

  it('handles null and undefined gracefully', () => {
    expect(scanBannedFields(null)).toEqual([]);
    expect(scanBannedFields(undefined)).toEqual([]);
  });
});

describe('validateManifestStage', () => {
  it('passes for human_review + witnessed', () => {
    const stage: ManifestStage = {
      stage: 1,
      name: 'Human Review',
      type: 'human_review',
      proof_level: 'witnessed',
      redacted: false,
    };
    expect(validateManifestStage(stage)).toEqual([]);
  });

  it('rejects human_review + attestation (invariant 2)', () => {
    const stage: ManifestStage = {
      stage: 1,
      name: 'Human Review',
      type: 'human_review',
      proof_level: 'attestation',
      redacted: false,
    };
    const errors = validateManifestStage(stage);
    expect(errors.some((e) => e.code === 'human_review_attestation_forbidden')).toBe(true);
  });

  it('rejects human_review + execution', () => {
    const stage: ManifestStage = {
      stage: 1,
      name: 'Human Review',
      type: 'human_review',
      proof_level: 'execution',
      redacted: false,
    };
    const errors = validateManifestStage(stage);
    expect(errors.some((e) => e.code === 'human_review_must_be_witnessed')).toBe(true);
  });

  it('passes for deterministic_rule + mathematical', () => {
    const stage: ManifestStage = {
      stage: 1,
      name: 'Rule Check',
      type: 'deterministic_rule',
      proof_level: 'mathematical',
      redacted: false,
    };
    expect(validateManifestStage(stage)).toEqual([]);
  });
});

describe('validateCheckExecutionRecord', () => {
  it('passes for valid record', () => {
    expect(validateCheckExecutionRecord(makeCheckRecord())).toEqual([]);
  });

  it('rejects missing manifest_hash (invariant 3)', () => {
    const errors = validateCheckExecutionRecord(
      makeCheckRecord({ manifest_hash: '' }),
    );
    expect(errors.some((e) => e.code === 'manifest_hash_missing')).toBe(true);
  });

  it('rejects witnessed without reviewer_credential (invariant 4)', () => {
    const errors = validateCheckExecutionRecord(
      makeCheckRecord({
        proof_level_achieved: 'witnessed',
        reviewer_credential: null,
      }),
    );
    expect(errors.some((e) => e.code === 'reviewer_credential_missing')).toBe(true);
  });

  it('passes witnessed with reviewer_credential', () => {
    const errors = validateCheckExecutionRecord(
      makeCheckRecord({
        proof_level_achieved: 'witnessed',
        reviewer_credential: {
          reviewer_key_id: 'key_1',
          key_binding: 'software',
          role: 'reviewer',
          org_credential_ref: null,
          reviewer_signature: 'ed25519:sig',
          display_hash: 'poseidon2:' + 'f'.repeat(64),
          rationale_hash: 'poseidon2:' + 'f'.repeat(64),
          signed_content_hash: 'poseidon2:' + 'f'.repeat(64),
          open_tst: 'base64:token',
          close_tst: 'base64:token',
        },
      }),
    );
    expect(errors).toEqual([]);
  });

  it('rejects not_applicable without skip_rationale_hash (invariant 5)', () => {
    const errors = validateCheckExecutionRecord(
      makeCheckRecord({
        check_result: 'not_applicable',
        skip_rationale_hash: null,
      }),
    );
    expect(errors.some((e) => e.code === 'skip_rationale_hash_missing')).toBe(true);
  });

  it('passes not_applicable with skip_rationale_hash', () => {
    const errors = validateCheckExecutionRecord(
      makeCheckRecord({
        check_result: 'not_applicable',
        skip_rationale_hash: 'poseidon2:' + 'a'.repeat(64),
      }),
    );
    expect(errors).toEqual([]);
  });

  it('rejects output_commitment without poseidon2 prefix', () => {
    const errors = validateCheckExecutionRecord(
      makeCheckRecord({ output_commitment: 'sha256:' + 'a'.repeat(64) }),
    );
    expect(errors.some((e) => e.code === 'output_commitment_invalid_prefix')).toBe(true);
  });

  it('rejects check_close_tst without check_open_tst', () => {
    const errors = validateCheckExecutionRecord(
      makeCheckRecord({
        check_close_tst: 'base64:token',
        check_open_tst: null,
      }),
    );
    expect(errors.some((e) => e.code === 'check_open_tst_missing')).toBe(true);
  });
});

describe('validateWaiver', () => {
  it('passes for valid waiver', () => {
    expect(validateWaiver(makeWaiver())).toEqual([]);
  });

  it('rejects reason shorter than 50 chars (invariant 7)', () => {
    const errors = validateWaiver(makeWaiver({ reason: 'Too short' }));
    expect(errors.some((e) => e.code === 'waiver_reason_too_short')).toBe(true);
  });

  it('rejects expires_at beyond 90 days (invariant 7)', () => {
    const errors = validateWaiver(
      makeWaiver({
        approved_at: '2026-03-10T00:00:00Z',
        expires_at: '2026-07-10T00:00:00Z', // ~122 days
      }),
    );
    expect(errors.some((e) => e.code === 'waiver_exceeds_90_days')).toBe(true);
  });

  it('rejects expires_at before approved_at', () => {
    const errors = validateWaiver(
      makeWaiver({
        approved_at: '2026-03-10T00:00:00Z',
        expires_at: '2026-03-09T00:00:00Z',
      }),
    );
    expect(errors.some((e) => e.code === 'waiver_expires_before_approval')).toBe(true);
  });

  it('passes waiver at exactly 90 days', () => {
    const errors = validateWaiver(
      makeWaiver({
        approved_at: '2026-03-10T00:00:00Z',
        expires_at: '2026-06-08T00:00:00Z', // exactly 90 days
      }),
    );
    expect(errors).toEqual([]);
  });
});

describe('validateEvidencePack', () => {
  it('passes when coverage sums to 100 (invariant 8)', () => {
    expect(validateEvidencePack(makeEvidencePack())).toEqual([]);
  });

  it('rejects when coverage does not sum to 100', () => {
    const errors = validateEvidencePack(
      makeEvidencePack({
        coverage_verified_pct: 80,
        coverage_pending_pct: 15,
        coverage_ungoverned_pct: 10,
      }),
    );
    expect(errors.some((e) => e.code === 'coverage_sum_not_100')).toBe(true);
  });

  it('passes 100/0/0 split', () => {
    const errors = validateEvidencePack(
      makeEvidencePack({
        coverage_verified_pct: 100,
        coverage_pending_pct: 0,
        coverage_ungoverned_pct: 0,
      }),
    );
    expect(errors).toEqual([]);
  });

  it('passes 0/0/100 split', () => {
    const errors = validateEvidencePack(
      makeEvidencePack({
        coverage_verified_pct: 0,
        coverage_pending_pct: 0,
        coverage_ungoverned_pct: 100,
      }),
    );
    expect(errors).toEqual([]);
  });
});
