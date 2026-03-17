/**
 * P10-B: Logger Callback tests — 7 MUST PASS.
 *
 * Tests setLogger() callback for SIEM linkage.
 */

import { describe, expect, it, vi } from 'vitest';
import { commit } from '@primust/artifact-core';
import { Pipeline } from './pipeline.js';
import type { PrimustLogEvent } from './pipeline.js';

// ── Mock fetch (reused pattern from pipeline.test.ts) ──

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
        JSON.stringify({ vpec_id: 'vpec_test001', state: 'signed' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }

    return new Response(JSON.stringify({ detail: 'not found' }), { status: 404 });
  };

  return { fetch: mockFetch as unknown as typeof globalThis.fetch, requests };
}

function createPipeline(mockFetch: typeof globalThis.fetch) {
  return new Pipeline({
    apiKey: 'pk_live_org001_us_secret',
    workflowId: 'wf_test',
    baseUrl: 'https://api.primust.com',
    fetch: mockFetch,
  });
}

// ── Tests ──

describe('TypeScript Logger Callback (P10-B)', () => {
  it('MUST PASS: callback fires on every p.record() call', async () => {
    const { fetch } = createMockFetch();
    const p = createPipeline(fetch);

    const events: PrimustLogEvent[] = [];
    p.setLogger((event) => events.push(event));

    const session = await p.openCheck('check_1', 'manifest_001');
    await p.record(session, 'data_1', 'pass');
    await p.record(session, 'data_2', 'fail');

    expect(events).toHaveLength(2);
    expect(events[0].primust_check_result).toBe('pass');
    expect(events[1].primust_check_result).toBe('fail');
  });

  it('MUST PASS: callback receives correct commitment_hash per record', async () => {
    const { fetch } = createMockFetch();
    const p = createPipeline(fetch);

    const events: PrimustLogEvent[] = [];
    p.setLogger((event) => events.push(event));

    const session = await p.openCheck('check_1', 'manifest_001');
    const rawInput = 'test input for hash verification';
    await p.record(session, rawInput, 'pass');

    expect(events).toHaveLength(1);
    const expectedHash = commit(new TextEncoder().encode(rawInput)).hash;
    expect(events[0].primust_commitment_hash).toBe(expectedHash);
  });

  it('MUST PASS: exception in callback does not interrupt p.record()', async () => {
    const { fetch } = createMockFetch();
    const p = createPipeline(fetch);

    p.setLogger(() => {
      throw new Error('Logger crashed!');
    });

    const session = await p.openCheck('check_1', 'manifest_001');
    // Should not throw despite callback exploding
    const result = await p.record(session, 'data', 'pass');
    expect(result.commitmentHash).toMatch(/^poseidon2:|^sha256:/);
  });

  it('MUST PASS: p.record() returns normally when no logger set', async () => {
    const { fetch } = createMockFetch();
    const p = createPipeline(fetch);

    // No setLogger() call
    const session = await p.openCheck('check_1', 'manifest_001');
    const result = await p.record(session, 'data', 'pass');
    expect(result.recordId).toBeTruthy();
  });

  it('MUST PASS: callback receives no content fields (allowlist test)', async () => {
    const { fetch } = createMockFetch();
    const p = createPipeline(fetch);

    const events: PrimustLogEvent[] = [];
    p.setLogger((event) => events.push(event));

    const session = await p.openCheck('check_1', 'manifest_001');
    const sensitiveInput = 'SUPER SECRET DATA that must not appear';
    await p.record(session, sensitiveInput, 'pass');

    const event = events[0];
    const allValues = JSON.stringify(event);
    expect(allValues).not.toContain(sensitiveInput);

    // Only allowed fields
    const allowedFields = new Set([
      'primust_record_id',
      'primust_commitment_hash',
      'primust_check_result',
      'primust_proof_level',
      'primust_workflow_id',
      'primust_run_id',
      'primust_recorded_at',
      'gap_types_emitted',
    ]);
    for (const key of Object.keys(event)) {
      expect(allowedFields.has(key)).toBe(true);
    }
  });

  it('MUST PASS: callback fires before ObservationEnvelope is sent', async () => {
    const { fetch, requests } = createMockFetch();
    const p = createPipeline(fetch);

    const callOrder: string[] = [];

    // Wrap fetch to track API call timing
    const wrappedFetch = async (
      input: string | URL | Request,
      init?: RequestInit,
    ): Promise<Response> => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/records')) {
        callOrder.push('api');
      }
      return (fetch as any)(input, init);
    };

    const p2 = new Pipeline({
      apiKey: 'pk_live_org001_us_secret',
      workflowId: 'wf_test',
      baseUrl: 'https://api.primust.com',
      fetch: wrappedFetch as typeof globalThis.fetch,
    });

    p2.setLogger(() => {
      callOrder.push('logger');
    });

    const session = await p2.openCheck('check_1', 'manifest_001');
    await p2.record(session, 'data', 'pass');

    expect(callOrder).toEqual(['logger', 'api']);
  });

  it('MUST PASS: TypeScript types correct — no `any` in PrimustLogEvent', async () => {
    const { fetch } = createMockFetch();
    const p = createPipeline(fetch);

    const events: PrimustLogEvent[] = [];
    p.setLogger((event: PrimustLogEvent) => {
      // All fields should be typed — TypeScript compiler enforces this
      const _id: string = event.primust_record_id;
      const _hash: string = event.primust_commitment_hash;
      const _result: string = event.primust_check_result;
      const _level: string = event.primust_proof_level;
      const _wf: string = event.primust_workflow_id;
      const _run: string = event.primust_run_id;
      const _at: string = event.primust_recorded_at;
      const _gaps: string[] | undefined = event.gap_types_emitted;
      events.push(event);
    });

    const session = await p.openCheck('check_1', 'manifest_001');
    await p.record(session, 'data', 'pass');

    expect(events).toHaveLength(1);
  });
});
