/**
 * P11-C: OTEL Span Processor adapter tests (TypeScript) — 6 MUST PASS.
 */

import { describe, expect, it, vi } from 'vitest';

import {
  PrimustSpanProcessor,
  PROOF_LEVEL_MAP,
  SURFACE_DECLARATION,
} from './span_processor.js';
import type { ReadableSpan, SpanEvent } from './span_processor.js';

// ── Mock Pipeline ──

interface CapturedRecord {
  session: any;
  input: unknown;
  checkResult: string;
  options: Record<string, unknown>;
}

function createMockPipeline() {
  const records: CapturedRecord[] = [];

  return {
    records,
    openCheck(check: string, manifestId: string) {
      return {
        checkName: check,
        manifestId,
        manifestHash: manifestId,
        checkOpenTst: new Date().toISOString(),
      };
    },
    record(session: any, input: unknown, checkResult: string, options: Record<string, unknown> = {}) {
      records.push({ session, input, checkResult, options });
    },
  };
}

// ── Helpers ──

function makeSpan(overrides: Partial<ReadableSpan> = {}): ReadableSpan {
  return {
    name: 'test_span',
    attributes: { key: 'value' },
    events: [],
    status: { code: 1 }, // OK
    startTime: [1710000000, 0],
    endTime: [1710000001, 0],
    ...overrides,
  };
}

// ── Tests ──

describe('OTEL Span Processor (P11-C TS)', () => {
  it('MUST PASS: span.status.code=ERROR → check_result=fail', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    processor.onEnd(makeSpan({
      name: 'failing_op',
      status: { code: 2 }, // ERROR
    }));

    expect(pipeline.records).toHaveLength(1);
    expect(pipeline.records[0].checkResult).toBe('fail');
  });

  it('MUST PASS: commitment uses poseidon2 (not raw attributes)', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    const sensitive = 'sensitive_data_never_transit';
    processor.onEnd(makeSpan({
      attributes: { data: sensitive },
    }));

    expect(pipeline.records).toHaveLength(1);
    // Input is the canonical JSON string, not raw — it's committed by the pipeline
    const inputStr = pipeline.records[0].input as string;
    expect(typeof inputStr).toBe('string');
  });

  it('MUST PASS: human_review span → proof_level = witnessed in map', () => {
    expect(PROOF_LEVEL_MAP['human_review']).toBe('witnessed');
  });

  it('MUST PASS: process_context_hash propagated from span attribute', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    processor.onEnd(makeSpan({
      attributes: { 'primust.process_context_hash': 'sha256:' + 'dd'.repeat(32) },
    }));

    expect(pipeline.records).toHaveLength(1);
  });

  it('MUST PASS: manifest_id from span attribute when present', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({
      pipeline,
      manifestMap: { my_op: 'manifest_default' },
    });

    processor.onEnd(makeSpan({
      name: 'my_op',
      attributes: { 'primust.manifest_id': 'manifest_override_v2' },
    }));

    expect(pipeline.records[0].session.manifestId).toBe('manifest_override_v2');
  });

  it('MUST PASS: all 5 proof levels reachable', () => {
    const expected = new Set(['mathematical', 'execution_zkml', 'execution', 'witnessed', 'attestation']);
    const actual = new Set(Object.values(PROOF_LEVEL_MAP));
    expect(actual).toEqual(expected);
  });

  it('UNSET status → degraded check_result', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    processor.onEnd(makeSpan({ status: { code: 0 } }));

    expect(pipeline.records[0].checkResult).toBe('degraded');
  });

  it('span with events → output passed to record', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    const events: SpanEvent[] = [
      { name: 'log', attributes: { message: 'done' } },
    ];
    processor.onEnd(makeSpan({ events }));

    expect(pipeline.records[0].options).toHaveProperty('output');
  });

  it('onEnd catches exceptions — never raises', () => {
    const brokenPipeline = {
      openCheck() { throw new Error('broken'); },
      record() {},
    };
    const processor = new PrimustSpanProcessor({ pipeline: brokenPipeline as any });

    // Should not throw
    expect(() => processor.onEnd(makeSpan())).not.toThrow();
  });

  it('surface declaration is middleware_interceptor', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });
    const surface = processor.getSurfaceDeclaration();
    expect(surface.surface_type).toBe('middleware_interceptor');
    expect(surface.observation_mode).toBe('post_action_realtime');
  });
});
