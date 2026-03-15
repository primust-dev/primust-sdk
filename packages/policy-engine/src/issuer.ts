/**
 * Primust Policy Engine — VPEC Issuance from Closed Run (P7-A)
 *
 * close_run(run_id, options?) → VPECArtifact
 *
 * 17 issuance steps:
 *   1. Load ProcessRun — validate state
 *   2. Load PolicySnapshot
 *   3. Load CheckExecutionRecords
 *   4. Compute proof_level (weakest)
 *   5. Build proof_distribution
 *   6. Load gaps
 *   7. Compute coverage (two denominators — never collapse)
 *   8. Build surface_summary
 *   9. Build manifest_hashes map
 *  10. Compute commitment_root
 *  11. Build VPEC document
 *  12. Sign
 *  13. Timestamp (DigiCert RFC 3161)
 *  14. ZK proof queuing (non-blocking)
 *  15. Rekor stub
 *  16. Close run
 *  17. Return VPEC
 *
 * ZK_IS_BLOCKING = false — VPEC is issued BEFORE proof completes.
 */

import {
  sign,
  buildCommitmentRoot,
  ZK_IS_BLOCKING,
} from '@primust/artifact-core';
import {
  buildWitness,
  proveAsync,
  StubProverClient,
} from '@primust/zk-core';
import type { ProverClient } from '@primust/zk-core';
import type {
  VPECArtifact,
  ProofLevel,
  ProofDistribution,
  Coverage,
  GapEntry,
  SurfaceEntry,
  SignerRecord,
  ArtifactIssuer,
  ArtifactSignature,
  TimestampAnchor,
  TransparencyLog,
  PendingFlags,
  OrgRegion,
} from '@primust/artifact-core';
import type { SqliteStore } from '@primust/runtime-core';
import type {
  CheckExecutionRecord,
  Gap,
  ProcessRun,
} from '@primust/runtime-core';

import { detectGaps } from './gap_detector.js';

// ── Types ──

export interface CloseRunOptions {
  partial?: boolean;
  request_zk?: boolean;
  test_mode?: boolean;
  org_region?: OrgRegion;
  public_key_url?: string;
  /** ProverClient for ZK proof generation. Defaults to StubProverClient. */
  prover_client?: ProverClient;
}

// ── Constants ──

/** Proof level hierarchy: lower index = stronger. */
const PROOF_LEVEL_ORDER: ProofLevel[] = [
  'mathematical',
  'verifiable_inference',
  'execution',
  'witnessed',
  'attestation',
];

// ── Helpers ──

function proofLevelIndex(level: ProofLevel): number {
  const idx = PROOF_LEVEL_ORDER.indexOf(level);
  return idx === -1 ? PROOF_LEVEL_ORDER.length : idx;
}

function weakestProofLevel(levels: ProofLevel[]): ProofLevel {
  if (levels.length === 0) return 'attestation';
  let weakest = levels[0];
  for (const level of levels) {
    if (proofLevelIndex(level) > proofLevelIndex(weakest)) {
      weakest = level;
    }
  }
  return weakest;
}

// ── Main ──

/**
 * Issue a VPEC artifact from a closed ProcessRun.
 *
 * @param runId - The run to close and issue from
 * @param store - SqliteStore instance
 * @param signerRecord - Active SignerRecord for signing
 * @param privateKey - Ed25519 private key bytes
 * @param options - Issuance options (partial, request_zk, test_mode)
 * @returns Signed VPECArtifact
 */
export function closeRun(
  runId: string,
  store: SqliteStore,
  signerRecord: SignerRecord,
  privateKey: Uint8Array,
  options: CloseRunOptions = {},
): VPECArtifact {
  const isPartial = options.partial ?? false;
  const requestZk = options.request_zk ?? false;
  const testMode = options.test_mode ?? false;
  const orgRegion = options.org_region ?? 'us';
  const publicKeyUrl = options.public_key_url ?? `https://primust.com/.well-known/primust-pubkeys/${signerRecord.kid}.pem`;

  // Step 1: Load ProcessRun — validate state
  const rawRun = store.getProcessRun(runId);
  if (!rawRun) {
    throw new Error(`ProcessRun not found: ${runId}`);
  }
  const run = rawRun as unknown as ProcessRun;
  if (run.state !== 'open' && !isPartial) {
    throw new Error(`ProcessRun ${runId} is not open (state: ${run.state})`);
  }

  // Step 2: Load PolicySnapshot
  const rawSnapshot = store.getPolicySnapshot(run.policy_snapshot_hash);
  const snapshot = rawSnapshot as unknown as { effective_checks: Array<{ manifest_id: string; required: boolean; check_id: string }> } | undefined;

  // Step 3: Load all CheckExecutionRecords
  const rawRecords = store.getCheckRecords(runId);
  const records = rawRecords as unknown as CheckExecutionRecord[];

  // Step 4: Compute proof_level = weakest across all records
  const recordLevels = records.map((r) => r.proof_level_achieved as ProofLevel);
  const proofLevel = weakestProofLevel(recordLevels);

  // Step 5: Build proof_distribution
  const dist: Record<string, number> = {
    mathematical: 0,
    verifiable_inference: 0,
    execution: 0,
    witnessed: 0,
    attestation: 0,
  };
  for (const level of recordLevels) {
    if (level in dist) {
      dist[level]++;
    }
  }

  const proofDistribution: ProofDistribution = {
    mathematical: dist.mathematical,
    verifiable_inference: dist.verifiable_inference,
    execution: dist.execution,
    witnessed: dist.witnessed,
    attestation: dist.attestation,
    weakest_link: proofLevel,
    weakest_link_explanation: records.length === 0
      ? 'No records — defaulting to attestation'
      : `Weakest proof level across ${records.length} records is ${proofLevel}`,
  };

  // Step 6: Load all Gaps → build gaps[] as GapEntry[]
  const detectedGaps = detectGaps(runId, store, snapshot as unknown as import('@primust/runtime-core').PolicySnapshot | undefined);
  const gapEntries: GapEntry[] = detectedGaps.map((g) => ({
    gap_id: g.gap_id,
    gap_type: g.gap_type,
    severity: g.severity,
  }));

  // Step 7: Compute coverage
  const recordsPass = records.filter((r) => r.check_result === 'pass').length;
  const recordsFail = records.filter((r) => r.check_result === 'fail').length;
  const recordsDegraded = records.filter((r) => r.check_result === 'degraded').length;
  const recordsNotApplicable = records.filter((r) => r.check_result === 'not_applicable').length;

  let policyCoveragePct = 0;
  if (snapshot && snapshot.effective_checks.length > 0) {
    const requiredChecks = snapshot.effective_checks.filter((c) => c.required);
    if (requiredChecks.length > 0) {
      const executedManifestIds = new Set(records.map((r) => r.manifest_id));
      const executedRequired = requiredChecks.filter((c) =>
        executedManifestIds.has(c.manifest_id),
      );
      if (isPartial) {
        // partial: credit NOT awarded for missing records
        policyCoveragePct = 0;
      } else {
        policyCoveragePct = Math.round(
          (executedRequired.length / requiredChecks.length) * 100,
        );
      }
    }
  }

  // Step 8: Build surface_summary[]
  const surfaceSummary: SurfaceEntry[] = [];
  const rawSurface = store.getSurface(run.surface_id);
  let instrumentationSurfacePct: number | null = null;
  let instrumentationSurfaceBasis = 'No observation surface registered';

  if (rawSurface) {
    surfaceSummary.push({
      surface_id: rawSurface.surface_id as string,
      surface_type: rawSurface.surface_type as SurfaceEntry['surface_type'],
      observation_mode: rawSurface.observation_mode as SurfaceEntry['observation_mode'],
      proof_ceiling: rawSurface.proof_ceiling as ProofLevel,
      scope_type: rawSurface.scope_type as SurfaceEntry['scope_type'],
      scope_description: rawSurface.scope_description as string,
      surface_coverage_statement: rawSurface.surface_coverage_statement as string,
    });

    instrumentationSurfaceBasis = rawSurface.surface_coverage_statement as string;
    if (rawSurface.scope_type === 'partial_unknown') {
      instrumentationSurfacePct = null;
    } else if (rawSurface.scope_type === 'full_workflow') {
      instrumentationSurfacePct = 100;
    } else {
      instrumentationSurfacePct = null; // conservative default
    }
  }

  const coverage: Coverage = {
    records_total: records.length,
    records_pass: recordsPass,
    records_fail: recordsFail,
    records_degraded: recordsDegraded,
    records_not_applicable: recordsNotApplicable,
    policy_coverage_pct: policyCoveragePct,
    instrumentation_surface_pct: instrumentationSurfacePct,
    instrumentation_surface_basis: instrumentationSurfaceBasis,
  };

  // Step 9: Build manifest_hashes{} map (object, NOT array)
  const manifestHashes: Record<string, string> = {};
  for (const record of records) {
    manifestHashes[record.manifest_id] = record.manifest_hash;
  }

  // Step 10: Compute commitment_root
  const commitmentHashes = records.map((r) => r.commitment_hash);
  const commitmentRoot = buildCommitmentRoot(commitmentHashes);

  // Step 11: Build VPEC document
  const vpecId = `vpec_${crypto.randomUUID()}`;
  const now = new Date().toISOString();

  const issuer: ArtifactIssuer = {
    signer_id: signerRecord.signer_id,
    kid: signerRecord.kid,
    algorithm: 'Ed25519',
    public_key_url: publicKeyUrl,
    org_region: orgRegion,
  };

  // Build the document for signing (state = provisional at this point)
  const vpecDocument: Record<string, unknown> = {
    vpec_id: vpecId,
    schema_version: '4.0.0',
    org_id: run.org_id,
    run_id: runId,
    workflow_id: run.workflow_id,
    process_context_hash: run.process_context_hash ?? null,
    policy_snapshot_hash: run.policy_snapshot_hash,
    policy_basis: snapshot
      ? (rawSnapshot as Record<string, unknown>)?.policy_basis ?? 'P1_self_declared'
      : 'P1_self_declared',
    partial: isPartial,
    surface_summary: surfaceSummary,
    proof_level: proofLevel,
    proof_distribution: proofDistribution,
    state: 'provisional',
    coverage,
    gaps: gapEntries,
    manifest_hashes: manifestHashes,
    commitment_root: commitmentRoot,
    commitment_algorithm: 'sha256',
    zk_proof: null,
    issuer,
    // signature placeholder — will be replaced
    signature: {
      signer_id: signerRecord.signer_id,
      kid: signerRecord.kid,
      algorithm: 'Ed25519',
      signature: '',
      signed_at: now,
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
    issued_at: now,
    pending_flags: {
      signature_pending: false,
      proof_pending: false,
      zkml_proof_pending: false,
      submission_pending: false,
      rekor_pending: false,
    },
    test_mode: testMode,
  };

  // Step 12: Sign with active artifact_signer
  const { signatureEnvelope } = sign(vpecDocument, privateKey, signerRecord);
  vpecDocument.state = 'signed';
  vpecDocument.signature = {
    signer_id: signatureEnvelope.signer_id,
    kid: signatureEnvelope.kid,
    algorithm: signatureEnvelope.algorithm,
    signature: signatureEnvelope.signature,
    signed_at: signatureEnvelope.signed_at,
  };

  // Step 13: Timestamp (DigiCert RFC 3161)
  // Applied by FastAPI layer after signing — see apps/api/src/primust_api/tsa.py

  // Step 14: ZK proof queuing (non-blocking)
  // Trigger proof generation when requested, regardless of current proof levels.
  // Records report 'execution' until ZK is verified; the proof, when it completes,
  // upgrades the VPEC from execution → mathematical.
  if (requestZk && records.length > 0) {
    (vpecDocument.pending_flags as PendingFlags).proof_pending = true;

    // ZK_IS_BLOCKING is false — VPEC returned immediately, proof runs async
    const proverClient = options.prover_client ?? new StubProverClient();
    try {
      const witness = buildWitness(runId, store, run.policy_snapshot_hash);
      // Fire-and-forget: proof completes asynchronously via webhook
      void proveAsync(witness, runId, 'mathematical', proverClient).catch(
        (err) => {
          // eslint-disable-next-line no-console
          console.error(`[primust] Proof submission failed for run ${runId}:`, err);
        },
      );
    } catch (witnessErr) {
      // Witness build failure is non-fatal — VPEC still issues with proof_pending
      // eslint-disable-next-line no-console
      console.error(`[primust] Witness build failed for run ${runId}:`, witnessErr);
    }
  }

  // Step 15: Rekor stub
  // rekor_pending already set to false

  // Step 16: Close ProcessRun
  store.closeRun(runId, isPartial ? 'partial' : 'closed');

  // Step 17: Return VPEC
  return vpecDocument as unknown as VPECArtifact;
}
