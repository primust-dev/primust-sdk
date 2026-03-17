/**
 * Primust TypeScript SDK — Pipeline class.
 *
 * Privacy invariant: raw content NEVER leaves the customer environment.
 * Only commitment hashes (poseidon2/sha256) transit to the Primust API.
 */

import {
  commit,
  commitOutput,
  ZK_IS_BLOCKING,
  canonical,
} from '@primust/artifact-core';
import type { CommitmentResult } from '@primust/artifact-core';

import { Run } from './run.js';

// Re-export constant
export { ZK_IS_BLOCKING };

// ── Types ──

export interface PipelineConfig {
  apiKey: string; // pk_live_xxx | pk_sb_xxx
  workflowId: string;
  policy?: string[] | string;
  processContextHash?: string;
  baseUrl?: string;
  fetch?: typeof globalThis.fetch;
}

export interface CheckSession {
  checkName: string;
  manifestId: string;
  manifestHash: string | null;
  checkOpenTst: string | null;
}

export interface ReviewSession extends CheckSession {
  reviewerKeyId: string;
  minDurationSeconds: number;
  openedAt: string;
}

export interface RecordResult {
  recordId: string;
  chainHash: string;
  commitmentHash: string;
  outputCommitment: string | null;
}

export interface RecordOptions {
  output?: unknown;
  reviewerSignature?: string;
  displayContent?: unknown;
  rationale?: string;
  skipRationale?: string;
}

export interface CloseOptions {
  partial?: boolean;
  requestZk?: boolean;
}

export interface ResumedContext {
  runId: string;
  surfaceId: string;
  delegationContext: Record<string, unknown>;
}

export interface PrimustLogEvent {
  primust_record_id: string;
  primust_commitment_hash: string;   // poseidon2:hex — linkage anchor
  primust_check_result: string;
  primust_proof_level: string;
  primust_workflow_id: string;
  primust_run_id: string;
  primust_recorded_at: string;       // ISO 8601
  gap_types_emitted?: string[];      // only if options.includeGapTypes
}

export interface LoggerOptions {
  includeGapTypes?: boolean;         // default false
}

// ── Helpers ──

function toBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (typeof value === 'string') return new TextEncoder().encode(value);
  return new TextEncoder().encode(canonical(value));
}

// ── Pipeline ──

export class Pipeline {
  private readonly apiKey: string;
  private readonly workflowId: string;
  private readonly policy: string[] | string | undefined;
  private readonly processContextHash: string | undefined;
  private readonly baseUrl: string;
  private readonly _fetch: typeof globalThis.fetch;
  private runId: string | null = null;
  private surfaceId: string | null = null;
  private closed = false;

  /** @internal For config drift detection */
  _priorManifestHashes: Record<string, string> = {};
  /** @internal Current manifest hashes */
  _manifestHashes: Record<string, string> = {};

  private _loggerCallback: ((event: PrimustLogEvent) => void) | null = null;
  private _loggerOptions: LoggerOptions = {};

  constructor(config: PipelineConfig) {
    this.apiKey = config.apiKey;
    this.workflowId = config.workflowId;
    this.policy = config.policy;
    this.processContextHash = config.processContextHash;
    this.baseUrl = (config.baseUrl ?? 'https://api.primust.com').replace(/\/+$/, '');
    this._fetch = config.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /**
   * Register a log callback for SIEM linkage.
   *
   * The callback receives a PrimustLogEvent on every p.record() call.
   * Write primust_commitment_hash to your existing logging infrastructure
   * (Splunk, Datadog, CloudWatch, etc.) to create an auditable linkage
   * between your application logs and the Primust VPEC.
   *
   * Auditor verification:
   *   1. Search SIEM: WHERE primust_commitment_hash = <value>
   *   2. primust-verify hash <plaintext_input> → confirms hash matches
   *   3. Primust VPEC proves chain integrity and timestamp independence
   *
   * Raw content is never passed to this callback.
   */
  setLogger(
    callback: (event: PrimustLogEvent) => void,
    options?: LoggerOptions,
  ): void {
    this._loggerCallback = callback;
    if (options) this._loggerOptions = options;
  }

  private _invokeLogger(event: PrimustLogEvent): void {
    if (!this._loggerCallback) return;
    try {
      this._loggerCallback(event);
    } catch {
      // Exceptions in callback are caught — never propagate.
    }
  }

  private async api(
    method: string,
    path: string,
    body?: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const resp = await this._fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        'X-API-Key': this.apiKey,
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

  private async ensureRun(surfaceId = 'default'): Promise<string> {
    if (this.runId) return this.runId;

    const body: Record<string, unknown> = {
      workflow_id: this.workflowId,
      surface_id: surfaceId,
      policy_pack_id: typeof this.policy === 'string' ? this.policy : 'default',
    };
    if (this.processContextHash) {
      body.process_context_hash = this.processContextHash;
    }

    const data = await this.api('POST', '/api/v1/runs', body);
    this.runId = data.run_id as string;
    return this.runId;
  }

  /**
   * Open a new governed process run.
   * Returns a Run. Call run.record() for each governance check.
   * Close with run.close() to issue the VPEC.
   */
  async open(policyPackId?: string): Promise<Run> {
    const body: Record<string, unknown> = {
      workflow_id: this.workflowId,
      environment: this.apiKey.startsWith('pk_test_') || this.apiKey.startsWith('pk_sb_') ? 'test' : 'production',
      opened_at: new Date().toISOString(),
    };
    if (policyPackId) {
      body.policy_pack_id = policyPackId;
    }

    const data = await this.api('POST', '/api/v1/runs', body);
    const serverRunId = (data.run_id as string) ?? `run_${crypto.randomUUID().replace(/-/g, '')}`;
    const orgId = (data.org_id as string) ?? 'unknown';
    const policySnapshotHash = (data.policy_snapshot_hash as string) ?? '';
    const testMode = this.apiKey.startsWith('pk_test_') || this.apiKey.startsWith('pk_sb_');

    return new Run({
      runId: serverRunId,
      workflowId: this.workflowId,
      orgId,
      policySnapshotHash,
      fetch: this._fetch,
      baseUrl: this.baseUrl,
      apiKey: this.apiKey,
      testMode,
      loggerCallback: this._loggerCallback,
      loggerOptions: this._loggerOptions,
    });
  }

  async openCheck(
    check: string,
    manifestId: string,
    _options?: Record<string, unknown>,
  ): Promise<CheckSession> {
    await this.ensureRun();
    const now = new Date().toISOString();

    // Populate _manifestHashes: compute hash from manifest data if provided,
    // otherwise use manifestId as the hash identity.
    if (_options && Object.keys(_options).length > 0) {
      const manifestBytes = new TextEncoder().encode(canonical(_options));
      const { hash } = commit(manifestBytes);
      this._manifestHashes[manifestId] = hash;
    } else if (!this._manifestHashes[manifestId]) {
      const { hash } = commit(new TextEncoder().encode(manifestId));
      this._manifestHashes[manifestId] = hash;
    }

    return {
      checkName: check,
      manifestId,
      manifestHash: this._manifestHashes[manifestId] ?? manifestId,
      checkOpenTst: now,
    };
  }

  async openReview(
    check: string,
    manifestId: string,
    options: { reviewerKeyId: string; minDurationSeconds?: number },
  ): Promise<ReviewSession> {
    await this.ensureRun();
    const now = new Date().toISOString();

    // Populate _manifestHashes if not already present
    if (!this._manifestHashes[manifestId]) {
      const { hash } = commit(new TextEncoder().encode(manifestId));
      this._manifestHashes[manifestId] = hash;
    }

    return {
      checkName: check,
      manifestId,
      manifestHash: this._manifestHashes[manifestId] ?? manifestId,
      checkOpenTst: now,
      reviewerKeyId: options.reviewerKeyId,
      minDurationSeconds: options.minDurationSeconds ?? 1800,
      openedAt: now,
    };
  }

  async record(
    checkSession: CheckSession,
    input: unknown,
    checkResult: string,
    options: RecordOptions = {},
  ): Promise<RecordResult> {
    if (!this.runId) throw new Error('Pipeline not opened');

    const now = new Date().toISOString();

    // Compute commitment hashes locally — raw content NEVER sent
    const inputBytes = toBytes(input);
    const { hash: commitmentHash, algorithm: commitmentAlgorithm } = commit(inputBytes);

    let outputCommitment: string | null = null;
    if (options.output !== undefined) {
      const outputBytes = toBytes(options.output);
      const result = commitOutput(outputBytes);
      outputCommitment = result.hash;
    }

    let skipRationaleHash: string | null = null;
    if (options.skipRationale !== undefined) {
      const { hash } = commit(new TextEncoder().encode(options.skipRationale));
      skipRationaleHash = hash;
    }

    // Enforce min_duration_seconds for review sessions at record() time
    if ('reviewerKeyId' in checkSession) {
      const rs = checkSession as ReviewSession;
      const openedMs = new Date(rs.openedAt).getTime();
      const nowMs = new Date(now).getTime();
      const elapsedSec = (nowMs - openedMs) / 1000;
      if (elapsedSec < rs.minDurationSeconds) {
        throw new Error(
          `Review duration ${elapsedSec.toFixed(1)}s is below minimum ${rs.minDurationSeconds}s (check_timing_suspect)`,
        );
      }
    }

    // Build reviewer_credential for witnessed records
    let reviewerCredential: Record<string, unknown> | undefined;
    if (options.reviewerSignature && 'reviewerKeyId' in checkSession) {
      const rs = checkSession as ReviewSession;
      let displayHash = '';
      let rationaleHash = '';

      if (options.displayContent !== undefined) {
        const { hash } = commit(toBytes(options.displayContent));
        displayHash = hash;
      }
      if (options.rationale !== undefined) {
        const { hash } = commit(new TextEncoder().encode(options.rationale));
        rationaleHash = hash;
      }

      reviewerCredential = {
        reviewer_key_id: rs.reviewerKeyId,
        key_binding: 'software',
        role: 'reviewer',
        org_credential_ref: null,
        reviewer_signature: options.reviewerSignature,
        display_hash: displayHash,
        rationale_hash: rationaleHash,
        signed_content_hash: commitmentHash,
        open_tst: checkSession.checkOpenTst ?? '',
        close_tst: now,
      };
    }

    const proofLevel = reviewerCredential ? 'witnessed' : 'execution';

    const body: Record<string, unknown> = {
      manifest_id: checkSession.manifestId,
      commitment_hash: commitmentHash,
      commitment_algorithm: commitmentAlgorithm,
      commitment_type: 'input_commitment',
      check_result: checkResult,
      proof_level_achieved: proofLevel,
      check_open_tst: checkSession.checkOpenTst,
      check_close_tst: now,
      idempotency_key: `idem_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`,
    };

    if (outputCommitment) body.output_commitment = outputCommitment;
    if (skipRationaleHash) body.skip_rationale_hash = skipRationaleHash;
    if (reviewerCredential) body.reviewer_credential = reviewerCredential;

    // Logger callback — called after commitment_hash computed, before API call.
    this._invokeLogger({
      primust_record_id: body.idempotency_key as string,
      primust_commitment_hash: commitmentHash,
      primust_check_result: checkResult,
      primust_proof_level: proofLevel,
      primust_workflow_id: this.workflowId,
      primust_run_id: this.runId!,
      primust_recorded_at: now,
      gap_types_emitted: [],
    });

    const data = await this.api('POST', `/api/v1/runs/${this.runId}/records`, body);

    return {
      recordId: data.record_id as string,
      chainHash: data.chain_hash as string,
      commitmentHash,
      outputCommitment,
    };
  }

  async recordDelegation(
    context: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    if (!this.runId) throw new Error('Pipeline not opened');

    return {
      token: `lt_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`,
      run_id: this.runId,
      surface_id: this.surfaceId ?? 'default',
      delegation_context: context,
      issued_at: new Date().toISOString(),
    };
  }

  async resumeFromLineage(
    token: Record<string, unknown>,
  ): Promise<ResumedContext> {
    return {
      runId: (token.run_id as string) ?? '',
      surfaceId: (token.surface_id as string) ?? '',
      delegationContext: (token.delegation_context as Record<string, unknown>) ?? {},
    };
  }

  async close(options: CloseOptions = {}): Promise<Record<string, unknown>> {
    if (!this.runId) throw new Error('Pipeline not opened');
    if (this.closed) throw new Error('Pipeline already closed');

    const data = await this.api('POST', `/api/v1/runs/${this.runId}/close`, {
      partial: options.partial ?? false,
      request_zk: options.requestZk ?? false,
    });

    this.closed = true;
    return data;
  }
}
