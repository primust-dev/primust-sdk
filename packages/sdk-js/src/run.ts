/**
 * Primust TypeScript SDK — Run context.
 *
 * A Run is opened by Pipeline.open() and closed by run.close() -> VPEC.
 * All record() calls happen on a Run.
 *
 * INVARIANT: Raw input is committed locally via @primust/artifact-core commit()
 * before any data is handed to the transport layer. The transport layer
 * receives only commitment hashes, never raw values.
 */

import {
  commit,
  commitOutput,
  canonical,
} from '@primust/artifact-core';

import type {
  CheckSession,
  ReviewSession,
  PrimustLogEvent,
  LoggerOptions,
} from './pipeline.js';

// ── Types ──

export interface RecordResult {
  recordId: string;
  commitmentHash: string;
  outputCommitment: string | null;
  commitmentAlgorithm: string;
  proofLevel: string;
  recordedAt: string;
  chainHash: string;
  queued: boolean;
}

export interface RecordOptions {
  output?: unknown;
  visibility?: string;
  checkSession?: CheckSession | ReviewSession;
  reviewerSignature?: string;
  displayContent?: unknown;
  rationale?: string;
}

export interface ProofLevelBreakdown {
  mathematical: number;
  verifiable_inference: number;
  execution: number;
  witnessed: number;
  attestation: number;
}

export interface GovernanceGap {
  gapId: string;
  gapType: string;
  severity: string;
  check?: string;
  sequence?: number;
  timestamp: string;
}

export interface VPECResult {
  vpecId: string;
  runId: string;
  workflowId: string;
  orgId: string;
  issuedAt: string;
  proofLevel: string;
  proofLevelBreakdown: ProofLevelBreakdown;
  coverageVerifiedPct: number;
  totalChecksRun: number;
  checksPassed: number;
  checksFailed: number;
  governanceGaps: GovernanceGap[];
  chainIntact: boolean;
  merkleRoot: string;
  signature: string;
  timestampRfc3161: string;
  testMode: boolean;
  raw: Record<string, unknown>;
}

// ── Constants ──

const VPEC_POLL_INTERVAL = 1500; // ms
const VPEC_POLL_TIMEOUT = 30000; // ms

const PROOF_LEVEL_ORDER = [
  'attestation',
  'witnessed',
  'execution',
  'verifiable_inference',
  'mathematical',
] as const;

// ── Helpers ──

function toBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (typeof value === 'string') return new TextEncoder().encode(value);
  return new TextEncoder().encode(canonical(value));
}

async function sha256hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ── Run ──

export class Run {
  readonly runId: string;
  readonly workflowId: string;
  readonly orgId: string;
  readonly policySnapshotHash: string;

  private readonly _fetch: typeof globalThis.fetch;
  private readonly _baseUrl: string;
  private readonly _apiKey: string;
  private readonly _testMode: boolean;

  private _closed = false;
  private _recordIds: string[] = [];
  private _chainHash = '';
  private _sequence = 0;
  private _proofLevels: string[] = [];

  private _loggerCallback: ((event: PrimustLogEvent) => void) | null = null;
  private _loggerOptions: LoggerOptions = {};

  constructor(opts: {
    runId: string;
    workflowId: string;
    orgId: string;
    policySnapshotHash: string;
    fetch: typeof globalThis.fetch;
    baseUrl: string;
    apiKey: string;
    testMode: boolean;
    loggerCallback?: ((event: PrimustLogEvent) => void) | null;
    loggerOptions?: LoggerOptions;
  }) {
    this.runId = opts.runId;
    this.workflowId = opts.workflowId;
    this.orgId = opts.orgId;
    this.policySnapshotHash = opts.policySnapshotHash;
    this._fetch = opts.fetch;
    this._baseUrl = opts.baseUrl;
    this._apiKey = opts.apiKey;
    this._testMode = opts.testMode;
    this._loggerCallback = opts.loggerCallback ?? null;
    this._loggerOptions = opts.loggerOptions ?? {};
  }

  /**
   * Register a log callback for SIEM linkage.
   */
  setLogger(
    callback: (event: PrimustLogEvent) => void,
    options?: LoggerOptions,
  ): void {
    this._loggerCallback = callback;
    if (options) this._loggerOptions = options;
  }

  // ------------------------------------------------------------------
  // run.record()
  // ------------------------------------------------------------------

  async record(
    check: string,
    manifestId: string,
    checkResult: string,
    input: unknown,
    options: RecordOptions = {},
  ): Promise<RecordResult> {
    if (this._closed) {
      throw new Error('Cannot record on a closed Run.');
    }

    const recordId = `rec_${crypto.randomUUID().replace(/-/g, '')}`;
    const sequence = this._sequence;
    this._sequence += 1;
    const recordedAt = new Date().toISOString();

    // -- LOCAL COMMITMENT -- raw input never leaves --
    const inputBytes = toBytes(input);
    const { hash: commitmentHash, algorithm: commitmentAlgorithm } = commit(inputBytes);

    let outputCommitment: string | null = null;
    if (options.output !== undefined) {
      const outputBytes = toBytes(options.output);
      const result = commitOutput(outputBytes);
      outputCommitment = result.hash;
    }

    let displayHash = '';
    if (options.displayContent !== undefined) {
      const { hash } = commit(toBytes(options.displayContent));
      displayHash = hash;
    }

    let rationaleHash = '';
    if (options.rationale !== undefined) {
      const { hash } = commit(new TextEncoder().encode(options.rationale));
      rationaleHash = hash;
    }
    // -------------------------------------------------

    // Rolling chain hash for chain integrity
    const chainInput = `${this._chainHash}|${recordId}|${commitmentHash}|${sequence}`;
    this._chainHash = await sha256hex(chainInput);

    const proofLevel = this._estimateProofLevel(
      options.checkSession ?? null,
      options.reviewerSignature ?? null,
    );

    // Build envelope -- ONLY hashes and metadata, never raw values
    const envelope: Record<string, unknown> = {
      record_id: recordId,
      run_id: this.runId,
      manifest_id: manifestId,
      check,
      sequence,
      check_result: checkResult,
      commitment_hash: commitmentHash,
      commitment_algorithm: commitmentAlgorithm,
      commitment_type: 'input_commitment',
      proof_level_achieved: proofLevel,
      idempotency_key: `idem_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`,
      visibility: options.visibility ?? 'opaque',
      chain_hash: this._chainHash,
      recorded_at: recordedAt,
    };

    if (outputCommitment) {
      envelope.output_commitment = outputCommitment;
    }
    if (displayHash) {
      envelope.display_hash = displayHash;
    }
    if (rationaleHash) {
      envelope.rationale_hash = rationaleHash;
    }

    const checkSession = options.checkSession ?? null;
    if (checkSession) {
      envelope.check_open_tst = checkSession.checkOpenTst;

      if (_isReviewSession(checkSession)) {
        envelope.reviewer_credential = {
          reviewer_key_id: checkSession.reviewerKeyId,
          key_binding: 'software',
          role: 'reviewer',
          org_credential_ref: null,
          reviewer_signature: options.reviewerSignature ?? '',
          display_hash: displayHash,
          rationale_hash: rationaleHash,
          signed_content_hash: commitmentHash,
          open_tst: checkSession.checkOpenTst ?? '',
          close_tst: recordedAt,
        };
      }
    }

    this._proofLevels.push(proofLevel);

    // Logger callback
    if (this._loggerCallback) {
      const event: PrimustLogEvent = {
        primust_record_id: recordId,
        primust_commitment_hash: commitmentHash,
        primust_check_result: checkResult,
        primust_proof_level: proofLevel,
        primust_workflow_id: this.workflowId,
        primust_run_id: this.runId,
        primust_recorded_at: recordedAt,
        gap_types_emitted: [],
      };
      try {
        this._loggerCallback(event);
      } catch {
        // Exceptions in callback are caught -- never propagate.
      }
    }

    // -- TRANSMIT -- only the envelope (no raw data) --
    let response: Record<string, unknown> | null = null;
    try {
      response = await this._api('POST', `/api/v1/runs/${this.runId}/records`, envelope);
    } catch {
      // API unreachable -- queued
    }
    const queued = response === null;
    // -------------------------------------------------

    let serverProofLevel = proofLevel;
    if (response && typeof response.proof_level === 'string') {
      serverProofLevel = response.proof_level;
    }

    const result: RecordResult = {
      recordId,
      commitmentHash,
      outputCommitment,
      commitmentAlgorithm,
      proofLevel: serverProofLevel,
      recordedAt,
      chainHash: this._chainHash,
      queued,
    };

    this._recordIds.push(recordId);
    return result;
  }

  // ------------------------------------------------------------------
  // run.openCheck() -- timed check sessions
  // ------------------------------------------------------------------

  openCheck(check: string, manifestId: string): CheckSession {
    const sessionId = `cs_${crypto.randomUUID().replace(/-/g, '')}`;
    const openedAt = new Date().toISOString();
    const stub = JSON.stringify({ session_id: sessionId, ts: openedAt, source: 'local_stub' });
    const openTst = btoa(stub);

    return {
      checkName: check,
      manifestId,
      manifestHash: null,
      checkOpenTst: openTst,
    };
  }

  // ------------------------------------------------------------------
  // run.openReview() -- Witnessed level human review
  // ------------------------------------------------------------------

  openReview(
    check: string,
    manifestId: string,
    reviewerKeyId: string,
    minDurationSeconds: number = 0,
  ): ReviewSession {
    const sessionId = `rv_${crypto.randomUUID().replace(/-/g, '')}`;
    const openedAt = new Date().toISOString();
    const stub = JSON.stringify({ session_id: sessionId, ts: openedAt, source: 'local_stub' });
    const openTst = btoa(stub);

    return {
      checkName: check,
      manifestId,
      manifestHash: null,
      checkOpenTst: openTst,
      reviewerKeyId,
      minDurationSeconds,
      openedAt,
    };
  }

  // ------------------------------------------------------------------
  // run.close() -> VPECResult
  // ------------------------------------------------------------------

  async close(): Promise<VPECResult> {
    if (this._closed) {
      throw new Error('Run already closed.');
    }
    this._closed = true;

    const closedAt = new Date().toISOString();
    const overallProofLevel = this._weakestLinkProofLevel();

    const closePayload = {
      run_id: this.runId,
      record_ids: this._recordIds,
      final_chain_hash: this._chainHash,
      closed_at: closedAt,
      record_count: this._recordIds.length,
    };

    let response: Record<string, unknown> | null = null;
    try {
      response = await this._api('POST', `/api/v1/runs/${this.runId}/close`, closePayload);
    } catch {
      // API unreachable
    }

    if (response === null) {
      return this._pendingVpec(closedAt, overallProofLevel);
    }

    const vpecData = await this._pollForVpec(response);
    return this._parseVpec(vpecData, overallProofLevel);
  }

  // ------------------------------------------------------------------
  // Internal helpers
  // ------------------------------------------------------------------

  private _weakestLinkProofLevel(): string {
    if (this._proofLevels.length === 0) return 'attestation';
    for (const level of PROOF_LEVEL_ORDER) {
      if (this._proofLevels.includes(level)) {
        return level;
      }
    }
    return 'attestation';
  }

  private _estimateProofLevel(
    checkSession: CheckSession | ReviewSession | null,
    reviewerSignature: string | null,
  ): string {
    if ((checkSession && _isReviewSession(checkSession)) || reviewerSignature) {
      return 'witnessed';
    }
    return 'attestation';
  }

  private async _pollForVpec(initialResponse: Record<string, unknown>): Promise<Record<string, unknown>> {
    // API returns VPEC at top level (vpec_id is the marker)
    if ('vpec_id' in initialResponse) return initialResponse;
    // Legacy wrapper format
    if ('vpec' in initialResponse && typeof initialResponse.vpec === 'object') {
      return initialResponse.vpec as Record<string, unknown>;
    }

    const deadline = Date.now() + VPEC_POLL_TIMEOUT;
    while (Date.now() < deadline) {
      await sleep(VPEC_POLL_INTERVAL);
      try {
        const result = await this._api('GET', `/api/v1/runs/${this.runId}/vpec`);
        if (result && 'vpec_id' in result) return result;
      } catch {
        // keep polling
      }
    }

    // Timed out -- return close response as stub
    return initialResponse;
  }

  private _pendingVpec(closedAt: string, proofLevel: string): VPECResult {
    return {
      vpecId: `vpec_pending_${this.runId}`,
      runId: this.runId,
      workflowId: this.workflowId,
      orgId: this.orgId,
      issuedAt: closedAt,
      proofLevel,
      proofLevelBreakdown: {
        mathematical: 0,
        verifiable_inference: 0,
        execution: 0,
        witnessed: 0,
        attestation: 0,
      },
      coverageVerifiedPct: 0.0,
      totalChecksRun: this._recordIds.length,
      checksPassed: 0,
      checksFailed: 0,
      governanceGaps: [{
        gapId: `gap_${crypto.randomUUID().replace(/-/g, '')}`,
        gapType: 'system_unavailable',
        severity: 'high',
        timestamp: closedAt,
      }],
      chainIntact: true,
      merkleRoot: '',
      signature: '',
      timestampRfc3161: '',
      testMode: this._testMode,
      raw: { status: 'pending', run_id: this.runId },
    };
  }

  private _parseVpec(data: Record<string, unknown>, localProofLevel: string): VPECResult {
    // API returns "proof_distribution", SDK model uses "proofLevelBreakdown"
    const breakdownRaw = (data.proof_distribution ?? data.proof_level_breakdown ?? {}) as Record<string, number>;
    const breakdown: ProofLevelBreakdown = {
      mathematical: breakdownRaw.mathematical ?? 0,
      verifiable_inference: breakdownRaw.verifiable_inference ?? 0,
      execution: breakdownRaw.execution ?? 0,
      witnessed: breakdownRaw.witnessed ?? 0,
      attestation: breakdownRaw.attestation ?? 0,
    };

    // API returns "gaps", SDK model uses "governanceGaps"
    const gapsRaw = (data.gaps ?? data.governance_gaps ?? []) as Record<string, unknown>[];
    const gaps: GovernanceGap[] = gapsRaw.map(g => ({
      gapId: (g.gap_id as string) ?? '',
      gapType: (g.gap_type as string) ?? '',
      severity: (g.severity as string) ?? '',
      check: g.check as string | undefined,
      sequence: g.sequence as number | undefined,
      timestamp: (g.timestamp as string) ?? '',
    }));

    // API nests coverage stats under "coverage" dict
    const coverage = (data.coverage ?? {}) as Record<string, number>;
    const totalChecks = coverage.records_total ?? (data.total_checks_run as number) ?? this._recordIds.length;
    const checksPassed = coverage.records_pass ?? (data.checks_passed as number) ?? 0;
    const checksFailed = coverage.records_fail ?? (data.checks_failed as number) ?? 0;
    const coveragePct = coverage.policy_coverage_pct ?? (data.coverage_verified_pct as number) ?? 0.0;

    return {
      vpecId: (data.vpec_id as string) ?? `vpec_${this.runId}`,
      runId: this.runId,
      workflowId: this.workflowId,
      orgId: (data.org_id as string) ?? this.orgId,
      issuedAt: (data.issued_at as string) ?? '',
      proofLevel: (data.proof_level as string) ?? localProofLevel,
      proofLevelBreakdown: breakdown,
      coverageVerifiedPct: coveragePct,
      totalChecksRun: totalChecks,
      checksPassed,
      checksFailed,
      governanceGaps: gaps,
      chainIntact: (data.chain_intact as boolean) ?? true,
      merkleRoot: (data.merkle_root as string) ?? '',
      signature: (data.signature as string) ?? '',
      timestampRfc3161: (data.timestamp_rfc3161 as string) ?? '',
      testMode: this._testMode,
      raw: data,
    };
  }

  private async _api(
    method: string,
    path: string,
    body?: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const resp = await this._fetch(`${this._baseUrl}${path}`, {
      method,
      headers: {
        'X-API-Key': this._apiKey,
        'Content-Type': 'application/json',
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`API ${resp.status}: ${text}`);
    }
    return resp.json() as Promise<Record<string, unknown>>;
  }
}

// ── Type guard ──

function _isReviewSession(session: CheckSession | ReviewSession): session is ReviewSession {
  return 'reviewerKeyId' in session;
}
