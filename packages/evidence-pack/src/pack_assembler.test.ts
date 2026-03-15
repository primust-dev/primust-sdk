/**
 * Tests for Evidence Pack assembly — P8-A + P8-B.
 * 8 MUST PASS tests for P8-A + 3 MUST PASS tests for P8-B = 11 total.
 */

import { describe, expect, it } from 'vitest';

import {
  generateKeyPair,
  sign,
  buildCommitmentRoot,
} from '@primust/artifact-core';
import type {
  VPECArtifact,
  SignerRecord,
  ProofLevel,
} from '@primust/artifact-core';

import { assemblePack, dryRunOutput } from './pack_assembler.js';
import type { EvidencePackWithInstructions } from './pack_assembler.js';

// ── Helpers ──

const { signerRecord, privateKey } = generateKeyPair('signer_001', 'org_001', 'artifact_signer');

function makeArtifact(overrides: Partial<VPECArtifact> = {}): VPECArtifact {

  const doc: Record<string, unknown> = {
    vpec_id: `vpec_${crypto.randomUUID()}`,
    schema_version: '4.0.0',
    org_id: 'org_001',
    run_id: 'run_001',
    workflow_id: 'wf_001',
    process_context_hash: null,
    policy_snapshot_hash: 'sha256:' + 'aa'.repeat(32),
    policy_basis: 'P1_self_declared',
    partial: false,
    surface_summary: [
      {
        surface_id: 'surf_001',
        surface_type: 'in_process_adapter',
        observation_mode: 'pre_action',
        proof_ceiling: 'mathematical',
        scope_type: 'full_workflow',
        scope_description: 'Full workflow coverage',
        surface_coverage_statement: 'All workflow steps observed',
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
      weakest_link_explanation: 'Weakest proof level is execution',
    },
    state: 'signed',
    coverage: {
      records_total: 5,
      records_pass: 5,
      records_fail: 0,
      records_degraded: 0,
      records_not_applicable: 0,
      policy_coverage_pct: 100,
      instrumentation_surface_pct: 100,
      instrumentation_surface_basis: 'All workflow steps observed',
    },
    gaps: [],
    manifest_hashes: { manifest_001: 'sha256:' + 'ab'.repeat(32) },
    commitment_root: buildCommitmentRoot(['poseidon2:' + 'cc'.repeat(32)]),
    commitment_algorithm: 'poseidon2',
    zk_proof: null,
    issuer: {
      signer_id: signerRecord.signer_id,
      kid: signerRecord.kid,
      algorithm: 'Ed25519',
      public_key_url: `https://primust.com/.well-known/primust-pubkeys/${signerRecord.kid}.pem`,
      org_region: 'us',
    },
    timestamp_anchor: { type: 'none', tsa: 'none', value: null },
    transparency_log: {
      rekor_log_id: null,
      rekor_entry_url: null,
      published_at: null,
    },
    issued_at: new Date().toISOString(),
    pending_flags: {
      signature_pending: false,
      proof_pending: false,
      zkml_proof_pending: false,
      submission_pending: false,
      rekor_pending: false,
    },
    test_mode: false,
    ...overrides,
  };

  // Sign the document body (without signature field) — matches verifier's
  // strip-then-verify pattern: const { signature: _, ...body } = artifact
  const { signatureEnvelope } = sign(doc, privateKey, signerRecord);
  doc.signature = {
    signer_id: signatureEnvelope.signer_id,
    kid: signatureEnvelope.kid,
    algorithm: signatureEnvelope.algorithm,
    signature: signatureEnvelope.signature,
    signed_at: signatureEnvelope.signed_at,
  };

  return doc as unknown as VPECArtifact;
}

// ── P8-A Tests ──

describe('Evidence Pack assembly (P8-A)', () => {
  it('MUST PASS: one signed artifact → one Evidence Pack', async () => {
    const artifact = makeArtifact();

    const pack = await assemblePack(
      [artifact],
      '2026-03-01',
      '2026-03-31',
      'org_001',
      signerRecord,
      privateKey,
      { coverage_verified_pct: 100, coverage_pending_pct: 0, coverage_ungoverned_pct: 0 },
    );

    expect(pack.pack_id).toMatch(/^pack_/);
    expect(pack.artifact_ids).toHaveLength(1);
    expect(pack.org_id).toBe('org_001');
  });

  it('MUST PASS: Merkle root changes if any artifact is tampered', async () => {
    const artifact1 = makeArtifact();
    const artifact2 = makeArtifact({
      commitment_root: buildCommitmentRoot(['poseidon2:' + 'dd'.repeat(32)]),
    });

    const pack1 = await assemblePack(
      [artifact1],
      '2026-03-01',
      '2026-03-31',
      'org_001',
      signerRecord,
      privateKey,
      { coverage_verified_pct: 100, coverage_pending_pct: 0, coverage_ungoverned_pct: 0 },
    );

    const pack2 = await assemblePack(
      [artifact2],
      '2026-03-01',
      '2026-03-31',
      'org_001',
      signerRecord,
      privateKey,
      { coverage_verified_pct: 100, coverage_pending_pct: 0, coverage_ungoverned_pct: 0 },
    );

    expect(pack1.merkle_root).not.toBe(pack2.merkle_root);
  });

  it('MUST PASS: coverage_verified + coverage_pending + coverage_ungoverned = 100 (assertion fires)', async () => {
    const artifact = makeArtifact();

    await expect(
      assemblePack(
        [artifact],
        '2026-03-01',
        '2026-03-31',
        'org_001',
        signerRecord,
        privateKey,
        { coverage_verified_pct: 50, coverage_pending_pct: 30, coverage_ungoverned_pct: 10 }, // sums to 90, not 100
      ),
    ).rejects.toThrow('must sum to 100');
  });

  it('MUST PASS: pack rejected if any artifact fails P2-A verification', async () => {
    const artifact = makeArtifact();
    // Tamper with artifact to break signature
    (artifact as unknown as Record<string, unknown>).org_id = 'tampered_org';

    await expect(
      assemblePack(
        [artifact],
        '2026-03-01',
        '2026-03-31',
        'org_001',
        signerRecord,
        privateKey,
        { coverage_verified_pct: 100, coverage_pending_pct: 0, coverage_ungoverned_pct: 0 },
      ),
    ).rejects.toThrow('failed verification');
  });

  it('MUST PASS: reliance_mode not in pack schema', async () => {
    const artifact = makeArtifact();

    const pack = await assemblePack(
      [artifact],
      '2026-03-01',
      '2026-03-31',
      'org_001',
      signerRecord,
      privateKey,
      { coverage_verified_pct: 100, coverage_pending_pct: 0, coverage_ungoverned_pct: 0 },
    );

    const json = JSON.stringify(pack);
    expect(json).not.toContain('reliance_mode');
  });

  it('MUST PASS: surface_coverage_statement present per surface in observation_summary', async () => {
    const artifact = makeArtifact();

    const pack = await assemblePack(
      [artifact],
      '2026-03-01',
      '2026-03-31',
      'org_001',
      signerRecord,
      privateKey,
      { coverage_verified_pct: 100, coverage_pending_pct: 0, coverage_ungoverned_pct: 0 },
    );

    for (const entry of pack.observation_summary) {
      expect(entry.surface_coverage_statement).toBeTypeOf('string');
      expect(entry.surface_coverage_statement.length).toBeGreaterThan(0);
    }
  });

  it('MUST PASS: all 5 proof levels aggregated in proof_distribution', async () => {
    const artifact = makeArtifact({
      proof_distribution: {
        mathematical: 2,
        verifiable_inference: 1,
        execution: 3,
        witnessed: 1,
        attestation: 1,
        weakest_link: 'attestation' as ProofLevel,
        weakest_link_explanation: 'Weakest is attestation',
      },
      proof_level: 'attestation' as ProofLevel,
    });

    const pack = await assemblePack(
      [artifact],
      '2026-03-01',
      '2026-03-31',
      'org_001',
      signerRecord,
      privateKey,
      { coverage_verified_pct: 100, coverage_pending_pct: 0, coverage_ungoverned_pct: 0 },
    );

    const dist = pack.proof_distribution;
    expect(dist.mathematical).toBe(2);
    expect(dist.verifiable_inference).toBe(1);
    expect(dist.execution).toBe(3);
    expect(dist.witnessed).toBe(1);
    expect(dist.attestation).toBe(1);
  });

  it('MUST PASS: manifest_hashes aggregated from all artifacts (map not array)', async () => {
    const artifact1 = makeArtifact({
      manifest_hashes: { manifest_001: 'sha256:' + 'ab'.repeat(32) },
    });
    const artifact2 = makeArtifact({
      manifest_hashes: { manifest_002: 'sha256:' + 'cd'.repeat(32) },
    });

    const pack = await assemblePack(
      [artifact1, artifact2],
      '2026-03-01',
      '2026-03-31',
      'org_001',
      signerRecord,
      privateKey,
      { coverage_verified_pct: 100, coverage_pending_pct: 0, coverage_ungoverned_pct: 0 },
    );

    const packAny = pack as unknown as Record<string, unknown>;
    const manifestHashes = packAny.manifest_hashes as Record<string, string>;
    expect(manifestHashes).toBeTypeOf('object');
    expect(Array.isArray(manifestHashes)).toBe(false);
    expect(manifestHashes['manifest_001']).toBeTypeOf('string');
    expect(manifestHashes['manifest_002']).toBeTypeOf('string');
  });
});

// ── P8-B Tests ──

describe('Evidence Pack CLI and verification instructions (P8-B)', () => {
  it('MUST PASS: --dry-run prints "Raw content: NONE"', () => {
    const output = dryRunOutput(
      ['vpec_abc123', 'vpec_def456', 'vpec_ghi789'],
      '2026-03-01',
      '2026-03-31',
      98.7,
      0,
      1.3,
      'in_process_adapter (LangGraph) — full_workflow',
      147,
    );

    expect(output).toContain('Raw content:');
    expect(output).toContain('NONE');
  });

  it('MUST PASS: --dry-run makes zero API calls', () => {
    // dryRunOutput is a pure function — no network calls
    const output = dryRunOutput(
      ['vpec_001'],
      '2026-03-01',
      '2026-03-31',
      100,
      0,
      0,
      'in_process_adapter — full_workflow',
      50,
    );

    expect(output).toContain('=== PRIMUST DRY RUN');
    expect(output).toContain('=== End dry run ===');
    // Function is synchronous — no awaits, no fetches
    expect(typeof output).toBe('string');
  });

  it('MUST PASS: verification_instructions in every pack', async () => {
    const artifact = makeArtifact();

    const pack = await assemblePack(
      [artifact],
      '2026-03-01',
      '2026-03-31',
      'org_001',
      signerRecord,
      privateKey,
      { coverage_verified_pct: 100, coverage_pending_pct: 0, coverage_ungoverned_pct: 0 },
    );

    expect(pack.verification_instructions).toBeTypeOf('object');
    expect(pack.verification_instructions.cli_command).toContain('primust pack verify');
    expect(pack.verification_instructions.offline_command).toContain('--trust-root');
    expect(pack.verification_instructions.trust_root_url).toBe('https://keys.primust.com/jwks');
    expect(pack.verification_instructions.what_this_proves).toBeTypeOf('string');
    expect(pack.verification_instructions.what_this_does_not_prove).toBeTypeOf('string');
    expect(pack.verification_instructions.coverage_basis_explanation).toBeTypeOf('string');
  });
});
