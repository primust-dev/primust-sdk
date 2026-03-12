import { describe, it, expect, vi, beforeEach } from 'vitest';
import { verify } from './verifier.js';
import { main } from './cli.js';
import {
  generateKeyPair,
  sign,
  toBase64Url,
} from '@primust/artifact-core';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

/**
 * Build a valid artifact body (without signature) that passes schema validation.
 * This is the document that gets signed.
 */
function buildArtifactBody(
  kid: string,
  publicKeyB64Url: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const base: Record<string, unknown> = {
    vpec_id: 'vpec_00000000-0000-0000-0000-000000000001',
    schema_version: '3.0.0',
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
      execution_zkml: 0,
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
      instrumentation_surface_basis: 'LangGraph full_workflow adapter.',
    },
    gaps: [],
    manifest_hashes: {
      manifest_001: 'sha256:' + 'b'.repeat(64),
    },
    commitment_root: 'poseidon2:' + 'c'.repeat(64),
    commitment_algorithm: 'poseidon2',
    zk_proof: null,
    issuer: {
      signer_id: 'signer_test',
      kid: kid,
      algorithm: 'Ed25519',
      public_key_url: 'https://primust.com/.well-known/primust-pubkeys/test.pem',
      org_region: 'us',
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

  return { ...base, ...overrides };
}

/**
 * Create a fully signed artifact (body + signature field) using artifact-core.
 * Returns the complete artifact as it would appear in a JSON file,
 * plus the public key in base64url for verification.
 */
function createSignedArtifact(overrides: Record<string, unknown> = {}): {
  artifact: Record<string, unknown>;
  publicKeyB64Url: string;
} {
  const { signerRecord, privateKey } = generateKeyPair(
    'signer_test',
    'org_test',
    'artifact_signer',
  );

  const body = buildArtifactBody(signerRecord.kid, signerRecord.public_key_b64url, overrides);

  // sign() returns { document, signatureEnvelope }
  const { signatureEnvelope } = sign(body, privateKey, signerRecord);

  // Assemble full artifact = body + signature field
  const artifact: Record<string, unknown> = {
    ...body,
    signature: {
      signer_id: signatureEnvelope.signer_id,
      kid: signatureEnvelope.kid,
      algorithm: signatureEnvelope.algorithm,
      signature: signatureEnvelope.signature,
      signed_at: signatureEnvelope.signed_at,
    },
  };

  return { artifact, publicKeyB64Url: signerRecord.public_key_b64url };
}

// Temp directory for trust root PEMs
let tmpDir: string;

beforeEach(() => {
  tmpDir = join(tmpdir(), `primust-test-${Date.now()}`);
  mkdirSync(tmpDir, { recursive: true });
});

/**
 * Write a trust root PEM file and return its path.
 * For Ed25519, the "PEM" is just the raw base64url public key.
 */
function writeTrustRoot(publicKeyB64Url: string): string {
  const pemPath = join(tmpDir, 'test-key.pem');
  writeFileSync(pemPath, publicKeyB64Url, 'utf-8');
  return pemPath;
}

// ── Verifier MUST PASS tests ──

describe('verify()', () => {
  it('MUST PASS: valid signed artifact → valid: true', async () => {
    const { artifact, publicKeyB64Url } = createSignedArtifact();
    const trustRoot = writeTrustRoot(publicKeyB64Url);

    const result = await verify(artifact, { skip_network: true, trust_root: trustRoot });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('MUST PASS: tampered artifact → valid: false, integrity_check_failed', async () => {
    const { artifact, publicKeyB64Url } = createSignedArtifact();
    const trustRoot = writeTrustRoot(publicKeyB64Url);

    // Tamper with a field after signing
    artifact.org_id = 'org_tampered';

    const result = await verify(artifact, { skip_network: true, trust_root: trustRoot });
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('integrity_check_failed');
  });

  it('MUST PASS: wrong kid → valid: false', async () => {
    const { artifact, publicKeyB64Url } = createSignedArtifact();
    const trustRoot = writeTrustRoot(publicKeyB64Url);

    // Change issuer kid to something different from signature kid
    const issuer = artifact.issuer as Record<string, unknown>;
    issuer.kid = 'kid_wrong';

    const result = await verify(artifact, { skip_network: true, trust_root: trustRoot });
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('kid_mismatch');
  });

  it('MUST PASS: reliance_mode in artifact → valid: false, banned_field_reliance_mode', async () => {
    const { artifact, publicKeyB64Url } = createSignedArtifact();
    const trustRoot = writeTrustRoot(publicKeyB64Url);

    // Inject reliance_mode at top level
    artifact.reliance_mode = 'full';

    const result = await verify(artifact, { skip_network: true, trust_root: trustRoot });
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('banned_field_reliance_mode');
  });

  it('MUST PASS: proof_level != weakest_link → valid: false', async () => {
    // Create artifact with mismatched proof_level (schema validation catches this)
    const { artifact, publicKeyB64Url } = createSignedArtifact({
      proof_level: 'mathematical',
      // proof_distribution.weakest_link is still 'execution'
    });
    const trustRoot = writeTrustRoot(publicKeyB64Url);

    const result = await verify(artifact, { skip_network: true, trust_root: trustRoot });
    expect(result.valid).toBe(false);
    // This is caught by schema validation as PROOF_LEVEL_MISMATCH
    expect(
      result.errors.some((e) => e.includes('PROOF_LEVEL_MISMATCH')),
    ).toBe(true);
  });

  it('MUST PASS: test_mode: true + production=true → valid: false', async () => {
    const { artifact, publicKeyB64Url } = createSignedArtifact({ test_mode: true });
    const trustRoot = writeTrustRoot(publicKeyB64Url);

    const result = await verify(artifact, {
      skip_network: true,
      trust_root: trustRoot,
      production: true,
    });
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('test_mode_rejected_in_production');
  });

  it('MUST PASS: skip_network=true → zero HTTP calls', async () => {
    const { artifact, publicKeyB64Url } = createSignedArtifact();
    const trustRoot = writeTrustRoot(publicKeyB64Url);

    // Spy on global fetch
    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    const result = await verify(artifact, { skip_network: true, trust_root: trustRoot });
    expect(result.valid).toBe(true);
    expect(fetchSpy).not.toHaveBeenCalled();

    fetchSpy.mockRestore();
  });

  it('MUST PASS: all 5 proof levels parse correctly in VerificationResult', async () => {
    const levels = ['mathematical', 'execution_zkml', 'execution', 'witnessed', 'attestation'];

    for (const level of levels) {
      const { artifact, publicKeyB64Url } = createSignedArtifact({
        proof_level: level,
        proof_distribution: {
          mathematical: 0,
          execution_zkml: 0,
          execution: 0,
          witnessed: 0,
          attestation: 0,
          [level]: 5,
          weakest_link: level,
          weakest_link_explanation: `All at ${level}`,
        },
      });
      const trustRoot = writeTrustRoot(publicKeyB64Url);

      const result = await verify(artifact, { skip_network: true, trust_root: trustRoot });
      expect(result.proof_level).toBe(level);
    }
  });

  it('MUST PASS: all 16 gap types parse correctly in gaps[]', async () => {
    const gapTypes = [
      'check_not_executed', 'enforcement_override', 'engine_error', 'check_degraded',
      'external_boundary_traversal', 'lineage_token_missing', 'admission_gate_override',
      'check_timing_suspect', 'reviewer_credential_invalid', 'witnessed_display_missing',
      'witnessed_rationale_missing', 'deterministic_consistency_violation',
      'skip_rationale_missing', 'policy_config_drift', 'zkml_proof_pending_timeout',
      'zkml_proof_failed',
    ];

    const gaps = gapTypes.map((gt, i) => ({
      gap_id: `gap_${i}`,
      gap_type: gt,
      severity: 'Medium',
    }));

    const { artifact, publicKeyB64Url } = createSignedArtifact({ gaps });
    const trustRoot = writeTrustRoot(publicKeyB64Url);

    const result = await verify(artifact, { skip_network: true, trust_root: trustRoot });
    expect(result.valid).toBe(true);
    expect(result.gaps).toHaveLength(16);
    for (let i = 0; i < gapTypes.length; i++) {
      expect(result.gaps[i].gap_type).toBe(gapTypes[i]);
    }
  });

  it('MUST PASS: manifest_hashes as array → parse error', async () => {
    const { artifact, publicKeyB64Url } = createSignedArtifact({
      manifest_hashes: ['sha256:' + 'a'.repeat(64)],
    });
    const trustRoot = writeTrustRoot(publicKeyB64Url);

    const result = await verify(artifact, { skip_network: true, trust_root: trustRoot });
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('manifest_hashes_not_object');
  });

  it('MUST PASS: mathematical proof_level + missing ZK verifier → error', async () => {
    const { artifact, publicKeyB64Url } = createSignedArtifact({
      proof_level: 'mathematical',
      proof_distribution: {
        mathematical: 5,
        execution_zkml: 0,
        execution: 0,
        witnessed: 0,
        attestation: 0,
        weakest_link: 'mathematical',
        weakest_link_explanation: 'All at mathematical',
      },
      zk_proof: {
        proving_system: 'ultrahonk',
        proof: 'dGVzdA==',
        public_inputs: ['0x01'],
        verification_key: 'dGVzdA==',
      },
    });
    const trustRoot = writeTrustRoot(publicKeyB64Url);

    // bb.js is not installed — verifyUltraHonk returns null
    const result = await verify(artifact, { skip_network: true, trust_root: trustRoot });
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('mathematical_proof_not_verified');
  });

  it('test_mode: true + non-production → valid with warning', async () => {
    const { artifact, publicKeyB64Url } = createSignedArtifact({ test_mode: true });
    const trustRoot = writeTrustRoot(publicKeyB64Url);

    const result = await verify(artifact, { skip_network: true, trust_root: trustRoot });
    expect(result.valid).toBe(true);
    expect(result.warnings).toContain('test_credential');
  });
});

// ── CLI MUST PASS tests ──

describe('CLI (main)', () => {
  function writeArtifactFile(artifact: Record<string, unknown>): string {
    const filePath = join(tmpDir, 'artifact.json');
    writeFileSync(filePath, JSON.stringify(artifact, null, 2), 'utf-8');
    return filePath;
  }

  it('MUST PASS: valid artifact → exit 0', async () => {
    const { artifact, publicKeyB64Url } = createSignedArtifact();
    const trustRoot = writeTrustRoot(publicKeyB64Url);
    const filePath = writeArtifactFile(artifact);

    const code = await main([filePath, '--skip-network', '--trust-root', trustRoot]);
    expect(code).toBe(0);
  });

  it('MUST PASS: tampered artifact → exit 1', async () => {
    const { artifact, publicKeyB64Url } = createSignedArtifact();
    const trustRoot = writeTrustRoot(publicKeyB64Url);
    artifact.org_id = 'tampered';
    const filePath = writeArtifactFile(artifact);

    const code = await main([filePath, '--skip-network', '--trust-root', trustRoot]);
    expect(code).toBe(1);
  });

  it('MUST PASS: file not found → exit 2', async () => {
    const code = await main(['/nonexistent/file.json', '--skip-network']);
    expect(code).toBe(2);
  });

  it('MUST PASS: --production + test_mode: true → exit 1', async () => {
    const { artifact, publicKeyB64Url } = createSignedArtifact({ test_mode: true });
    const trustRoot = writeTrustRoot(publicKeyB64Url);
    const filePath = writeArtifactFile(artifact);

    const code = await main([filePath, '--production', '--skip-network', '--trust-root', trustRoot]);
    expect(code).toBe(1);
  });

  it('MUST PASS: --json emits valid VerificationResult JSON', async () => {
    const { artifact, publicKeyB64Url } = createSignedArtifact();
    const trustRoot = writeTrustRoot(publicKeyB64Url);
    const filePath = writeArtifactFile(artifact);

    // Capture stdout
    const logs: string[] = [];
    const origLog = console.log;
    console.log = (...args: unknown[]) => logs.push(args.join(' '));

    const code = await main([filePath, '--json', '--skip-network', '--trust-root', trustRoot]);

    console.log = origLog;

    expect(code).toBe(0);
    const output = JSON.parse(logs.join('\n'));
    expect(output.valid).toBe(true);
    expect(output.vpec_id).toBe('vpec_00000000-0000-0000-0000-000000000001');
    expect(output.errors).toEqual([]);
  });

  it('MUST PASS: all 5 proof levels display correctly in human output', async () => {
    const levels = ['mathematical', 'execution_zkml', 'execution', 'witnessed', 'attestation'];
    const expected = ['mathematical', 'execution+zkml', 'execution', 'witnessed', 'attestation'];

    for (let i = 0; i < levels.length; i++) {
      const { artifact, publicKeyB64Url } = createSignedArtifact({
        proof_level: levels[i],
        proof_distribution: {
          mathematical: 0,
          execution_zkml: 0,
          execution: 0,
          witnessed: 0,
          attestation: 0,
          [levels[i]]: 5,
          weakest_link: levels[i],
          weakest_link_explanation: `All at ${levels[i]}`,
        },
      });
      const trustRoot = writeTrustRoot(publicKeyB64Url);
      const filePath = writeArtifactFile(artifact);

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(' '));

      await main([filePath, '--skip-network', '--trust-root', trustRoot]);

      console.log = origLog;

      const output = logs.join('\n');
      expect(output).toContain(expected[i]);
    }
  });

  it('MUST PASS: --skip-network → zero HTTP calls', async () => {
    const { artifact, publicKeyB64Url } = createSignedArtifact();
    const trustRoot = writeTrustRoot(publicKeyB64Url);
    const filePath = writeArtifactFile(artifact);

    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    await main([filePath, '--skip-network', '--trust-root', trustRoot]);

    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it('MUST PASS: execution_zkml renders as "execution+zkml" in human output', async () => {
    const { artifact, publicKeyB64Url } = createSignedArtifact({
      proof_level: 'execution_zkml',
      proof_distribution: {
        mathematical: 0,
        execution_zkml: 5,
        execution: 0,
        witnessed: 0,
        attestation: 0,
        weakest_link: 'execution_zkml',
        weakest_link_explanation: 'All at execution_zkml',
      },
    });
    const trustRoot = writeTrustRoot(publicKeyB64Url);
    const filePath = writeArtifactFile(artifact);

    const logs: string[] = [];
    const origLog = console.log;
    console.log = (...args: unknown[]) => logs.push(args.join(' '));

    await main([filePath, '--skip-network', '--trust-root', trustRoot]);

    console.log = origLog;

    const output = logs.join('\n');
    expect(output).toContain('execution+zkml');
    expect(output).not.toContain('execution_zkml');
  });
});
