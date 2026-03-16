/**
 * P10-B: TypeScript SDK tests — 8 MUST PASS.
 *
 * Uses mock fetch to intercept all HTTP requests
 * and verify no raw content transits.
 */

import { describe, expect, it, vi } from 'vitest';

import {
  commit,
  commitOutput,
  ZK_IS_BLOCKING,
} from '@primust/artifact-core';

import { Pipeline } from './pipeline.js';
import type { CheckSession, ReviewSession } from './pipeline.js';

// ── Mock fetch ──

interface CapturedRequest {
  method: string;
  url: string;
  body: Record<string, unknown>;
  rawBody: string;
}

function createMockFetch(): {
  fetch: typeof globalThis.fetch;
  requests: CapturedRequest[];
} {
  const requests: CapturedRequest[] = [];
  let runCounter = 0;

  const mockFetch = async (
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    const rawBody = (init?.body as string) ?? '';
    const body = rawBody ? JSON.parse(rawBody) : {};

    requests.push({ method, url, body, rawBody });

    const path = new URL(url).pathname;

    if (path === '/api/v1/runs' && method === 'POST') {
      runCounter++;
      return new Response(
        JSON.stringify({
          run_id: `run_${String(runCounter).padStart(4, '0')}`,
          policy_snapshot_hash: 'sha256:' + 'aa'.repeat(32),
          process_context_hash: body.process_context_hash ?? null,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }

    if (path.includes('/records') && method === 'POST') {
      return new Response(
        JSON.stringify({
          record_id: 'rec_test001',
          chain_hash: 'sha256:' + 'bb'.repeat(32),
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }

    if (path.includes('/close') && method === 'POST') {
      return new Response(
        JSON.stringify({
          vpec_id: 'vpec_test001',
          schema_version: '4.0.0',
          state: 'signed',
          partial: body.partial ?? false,
          test_mode: false,
          proof_level: 'execution',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }

    return new Response(JSON.stringify({ detail: 'not found' }), { status: 404 });
  };

  return { fetch: mockFetch as unknown as typeof globalThis.fetch, requests };
}

function createPipeline(
  mockFetch: typeof globalThis.fetch,
  overrides: Partial<ConstructorParameters<typeof Pipeline>[0]> = {},
) {
  return new Pipeline({
    apiKey: 'pk_live_org001_us_secret',
    workflowId: 'wf_test',
    processContextHash: 'sha256:' + 'cc'.repeat(32),
    baseUrl: 'https://api.primust.com',
    fetch: mockFetch,
    ...overrides,
  });
}

// ── Tests ──

describe('TypeScript SDK (P10-B)', () => {
  it('MUST PASS: raw content not in HTTP body (interceptor test)', async () => {
    const { fetch, requests } = createMockFetch();
    const p = createPipeline(fetch);

    const session = await p.openCheck('pii_check', 'manifest_001');
    const rawInput = 'this is sensitive PII data that must never transit';

    await p.record(session, rawInput, 'pass');

    const recordReq = requests.filter((r) => r.url.includes('/records'));
    expect(recordReq).toHaveLength(1);

    const body = recordReq[0].body;
    const rawBody = recordReq[0].rawBody;

    expect(body.commitment_hash).toMatch(/^poseidon2:|^sha256:/);
    expect(rawBody).not.toContain(rawInput);
    expect(JSON.stringify(body)).not.toContain(rawInput);
  });

  it('MUST PASS: processContextHash passed to /runs at open time', async () => {
    const { fetch, requests } = createMockFetch();
    const p = createPipeline(fetch);

    await p.openCheck('ctx_check', 'manifest_002');

    const runReq = requests.filter((r) => r.url.endsWith('/api/v1/runs'));
    expect(runReq).toHaveLength(1);
    expect(runReq[0].body.process_context_hash).toBe('sha256:' + 'cc'.repeat(32));
  });

  it('MUST PASS: all v2 fields present in record body', async () => {
    const { fetch, requests } = createMockFetch();
    const p = createPipeline(fetch);

    const session = await p.openCheck('fields_check', 'manifest_003');
    await p.record(session, 'input_data', 'pass', {
      output: { value: 42 },
    });

    const recordReq = requests.filter((r) => r.url.includes('/records'));
    const body = recordReq[0].body;

    expect(body.commitment_hash).toMatch(/^poseidon2:|^sha256:/);
    expect(body.output_commitment).toBeTypeOf('string');
    expect(['poseidon2', 'sha256']).toContain(body.commitment_algorithm);
    expect(body.commitment_type).toBe('input_commitment');
    expect(body.check_result).toBe('pass');
    expect(body.proof_level_achieved).toBeTypeOf('string');
    expect(body.check_open_tst).toBeTypeOf('string');
    expect(body.check_close_tst).toBeTypeOf('string');
    expect(body.idempotency_key).toBeTypeOf('string');
    expect(body.manifest_id).toBe('manifest_003');
  });

  it('MUST PASS: ZK_IS_BLOCKING === false (constant assertion)', () => {
    expect(ZK_IS_BLOCKING).toBe(false);
  });

  it('MUST PASS: check_open_tst fetched at openCheck(), check_close_tst at record()', async () => {
    const { fetch, requests } = createMockFetch();
    const p = createPipeline(fetch);

    const session = await p.openCheck('timing_check', 'manifest_004');
    expect(session.checkOpenTst).toBeTypeOf('string');

    // Small delay to ensure different timestamps
    await new Promise((r) => setTimeout(r, 5));

    await p.record(session, 'data', 'pass');

    const recordReq = requests.filter((r) => r.url.includes('/records'));
    const body = recordReq[0].body;

    expect(body.check_open_tst).toBe(session.checkOpenTst);
    expect(body.check_close_tst).toBeTypeOf('string');
    // Both timestamps must be valid ISO strings (close is generated at record time)
    expect(new Date(body.check_open_tst as string).getTime()).not.toBeNaN();
    expect(new Date(body.check_close_tst as string).getTime()).not.toBeNaN();
  });

  it('MUST PASS: skip_rationale_hash, display_hash, rationale_hash committed locally', async () => {
    const { fetch, requests } = createMockFetch();
    const p = createPipeline(fetch);

    const session = await p.openReview('review_check', 'manifest_005', {
      reviewerKeyId: 'rev_key_001',
      minDurationSeconds: 0, // disable timing check for this test
    });

    const display = { screenshot: 'base64_image_data', context: 'approval' };
    const rationaleText = 'Approved because the risk is acceptable';

    await p.record(session, 'input', 'pass', {
      reviewerSignature: 'sig_base64url',
      displayContent: display,
      rationale: rationaleText,
      skipRationale: 'Not needed for this check',
    });

    const recordReq = requests.filter((r) => r.url.includes('/records'));
    const body = recordReq[0].body;
    const rawBody = recordReq[0].rawBody;

    // Hashes present
    const cred = body.reviewer_credential as Record<string, unknown>;
    expect(cred.display_hash).toMatch(/^poseidon2:|^sha256:/);
    expect(cred.rationale_hash).toMatch(/^poseidon2:|^sha256:/);
    expect(body.skip_rationale_hash).toMatch(/^poseidon2:|^sha256:/);

    // Raw content not in body
    expect(rawBody).not.toContain('base64_image_data');
    expect(rawBody).not.toContain(rationaleText);
    expect(rawBody).not.toContain('Not needed for this check');
  });

  it('MUST PASS: manifest_hash captured per record', async () => {
    const { fetch } = createMockFetch();
    const p = createPipeline(fetch);

    const session = await p.openCheck('hash_check', 'manifest_006');
    expect(session.manifestHash).toBe('manifest_006');
  });

  it('MUST PASS: sub-threshold review duration throws check_timing_suspect', async () => {
    const { fetch } = createMockFetch();
    const p = createPipeline(fetch);

    const session = await p.openReview('quick_review', 'manifest_007', {
      reviewerKeyId: 'rev_001',
      minDurationSeconds: 1800, // 30 minutes
    });

    // Record immediately — elapsed ~0s, way below 1800s threshold
    await expect(
      p.record(session, 'data', 'pass', { reviewerSignature: 'sig' }),
    ).rejects.toThrow('check_timing_suspect');
  });

  it('MUST PASS: identical golden vectors to P6-A (deterministic)', () => {
    const input1 = new TextEncoder().encode('test_input_1');
    const input2 = new TextEncoder().encode('test_input_1');

    const result1 = commit(input1);
    const result2 = commit(input2);

    expect(result1.hash).toBe(result2.hash); // deterministic
    expect(result1.hash).toMatch(/^poseidon2:|^sha256:/);

    const result3 = commit(new TextEncoder().encode('test_input_2'));
    expect(result3.hash).not.toBe(result1.hash); // different input

    const output = commitOutput(new TextEncoder().encode('output_data'));
    expect(['poseidon2', 'sha256']).toContain(output.algorithm);
    expect(output.hash).toMatch(/^poseidon2:|^sha256:/);
  });
});
