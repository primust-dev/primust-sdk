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

// Re-export constant
export { ZK_IS_BLOCKING };

// ── Types ──

export interface PipelineConfig {
  apiKey: string; // pk_live_xxx | pk_test_xxx
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

// ── Helpers ──

function toBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (typeof value === 'string') return new TextEncoder().encode(value);
  const json = JSON.stringify(value, Object.keys(value as Record<string, unknown>).sort());
  return new TextEncoder().encode(json);
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

  constructor(config: PipelineConfig) {
    this.apiKey = config.apiKey;
    this.workflowId = config.workflowId;
    this.policy = config.policy;
    this.processContextHash = config.processContextHash;
    this.baseUrl = (config.baseUrl ?? 'https://api.primust.com').replace(/\/+$/, '');
    this._fetch = config.fetch ?? globalThis.fetch.bind(globalThis);
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

  async openCheck(
    check: string,
    manifestId: string,
    _options?: Record<string, unknown>,
  ): Promise<CheckSession> {
    await this.ensureRun();
    const now = new Date().toISOString();

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
    const { hash: commitmentHash } = commit(inputBytes);

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
        key_binding: 'org_managed',
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
      commitment_algorithm: 'poseidon2',
      commitment_type: options.output === undefined ? 'input_only' : 'input_output',
      check_result: checkResult,
      proof_level_achieved: proofLevel,
      check_open_tst: checkSession.checkOpenTst,
      check_close_tst: now,
      idempotency_key: `idem_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`,
    };

    if (outputCommitment) body.output_commitment = outputCommitment;
    if (skipRationaleHash) body.skip_rationale_hash = skipRationaleHash;
    if (reviewerCredential) body.reviewer_credential = reviewerCredential;

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
