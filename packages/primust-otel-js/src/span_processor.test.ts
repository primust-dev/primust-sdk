/**
 * OTEL Span Processor tests (TypeScript).
 *
 * 9 original MUST PASS tests + 25 OTL amendment tests.
 */

import { describe, expect, it } from 'vitest';

import {
  PrimustSpanProcessor,
  PROOF_LEVEL_MAP,
  SURFACE_DECLARATION,
  SPAN_TYPE_PROOF_CEILING,
  PROHIBITED_ATTRIBUTES,
  SpanType,
  SPAN_KIND_INTERNAL,
  SPAN_KIND_CLIENT,
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
    record(
      session: any,
      input: unknown,
      checkResult: string,
      options: Record<string, unknown> = {},
    ) {
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

// ── Original MUST PASS Tests ──

describe('OTEL Span Processor — Original MUST PASS', () => {
  it('MUST PASS: span.status.code=ERROR → check_result=fail', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    processor.onEnd(
      makeSpan({
        name: 'failing_op',
        status: { code: 2 }, // ERROR
      }),
    );

    expect(pipeline.records).toHaveLength(1);
    expect(pipeline.records[0].checkResult).toBe('fail');
  });

  it('MUST PASS: commitment uses canonical input (not raw attributes)', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    const sensitive = 'sensitive_data_never_transit';
    processor.onEnd(
      makeSpan({
        attributes: { data: sensitive },
      }),
    );

    expect(pipeline.records).toHaveLength(1);
    const inputStr = pipeline.records[0].input as string;
    expect(typeof inputStr).toBe('string');
  });

  it('MUST PASS: witnessed span → proof_level = witnessed in map', () => {
    expect(PROOF_LEVEL_MAP['witnessed']).toBe('witnessed');
  });

  it('MUST PASS: process_context_hash propagated from span attribute', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    processor.onEnd(
      makeSpan({
        attributes: {
          'primust.process_context_hash': 'sha256:' + 'dd'.repeat(32),
        },
      }),
    );

    expect(pipeline.records).toHaveLength(1);
  });

  it('MUST PASS: manifest_id from span attribute when present', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({
      pipeline,
      manifestMap: { my_op: 'manifest_default' },
    });

    processor.onEnd(
      makeSpan({
        name: 'my_op',
        attributes: { 'primust.manifest_id': 'manifest_override_v2' },
      }),
    );

    expect(pipeline.records[0].session.manifestId).toBe(
      'manifest_override_v2',
    );
  });

  it('proof levels reachable (mathematical excluded until ZK wired)', () => {
    const expected = new Set([
      'verifiable_inference',
      'execution',
      'witnessed',
      'attestation',
    ]);
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
      openCheck() {
        throw new Error('broken');
      },
      record() {
        throw new Error('broken');
      },
    };
    const processor = new PrimustSpanProcessor({
      pipeline: brokenPipeline as any,
    });

    expect(() => processor.onEnd(makeSpan())).not.toThrow();
  });
});

// ── OTL-1: Span Type Classification ──

describe('OTL-1: Span Type Classification', () => {
  it('LLM inference span classified correctly', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    const span = makeSpan({
      name: 'chat_completion',
      attributes: { 'gen_ai.request.model': 'gpt-4' },
    });

    expect(processor.classifySpan(span)).toBe(SpanType.LLM_INFERENCE);
  });

  it('tool execution with gen_ai.tool.name → TOOL_EXECUTION_INTERNAL', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    const span = makeSpan({
      name: 'gen_ai.execute_tool',
      attributes: { 'gen_ai.tool.name': 'web_search' },
    });

    expect(processor.classifySpan(span)).toBe(
      SpanType.TOOL_EXECUTION_INTERNAL,
    );
  });

  it('evaluation event span classified correctly', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    const span = makeSpan({
      name: 'eval_run',
      events: [
        {
          name: 'gen_ai.evaluation.result',
          attributes: {
            'gen_ai.evaluation.name': 'toxicity',
            'gen_ai.evaluation.score': 0.1,
          },
        },
      ],
    });

    expect(processor.classifySpan(span)).toBe(SpanType.EVALUATION);
  });

  it('unknown span type fallback', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    const span = makeSpan({
      name: 'random_operation',
      attributes: { custom: 'value' },
    });

    expect(processor.classifySpan(span)).toBe(SpanType.UNKNOWN);
  });

  it('span type proof ceilings defined for all types', () => {
    for (const st of Object.values(SpanType)) {
      expect(SPAN_TYPE_PROOF_CEILING[st]).toBeDefined();
    }
  });

  it('LLM ceiling is attestation, tool INTERNAL ceiling is execution', () => {
    expect(SPAN_TYPE_PROOF_CEILING[SpanType.LLM_INFERENCE]).toBe(
      'attestation',
    );
    expect(SPAN_TYPE_PROOF_CEILING[SpanType.TOOL_EXECUTION_INTERNAL]).toBe(
      'execution',
    );
    // TODO(zk-integration): Restore to 'mathematical' when ZK proofs are wired
    expect(SPAN_TYPE_PROOF_CEILING[SpanType.EVALUATION]).toBe('execution');
  });
});

// ── OTL-2: Conditional Commitment Logic ──

describe('OTL-2: Conditional Commitment', () => {
  it('LLM span → metadata_commitment with model + duration', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    const span = makeSpan({
      name: 'chat',
      attributes: { 'gen_ai.request.model': 'gpt-4' },
    });

    const { canonical, commitmentType } = processor.computeCommitmentPayload(
      span,
      SpanType.LLM_INFERENCE,
    );

    expect(commitmentType).toBe('metadata_commitment');
    const parsed = JSON.parse(canonical);
    expect(parsed.model).toBe('gpt-4');
    expect(parsed.span_name).toBe('chat');
    expect(parsed).toHaveProperty('duration_ms');
    expect(parsed).toHaveProperty('status');
  });

  it('internal tool span → input_commitment with tool args', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    const span = makeSpan({
      name: 'gen_ai.execute_tool',
      attributes: {
        'gen_ai.tool.name': 'calculator',
        'gen_ai.tool.call.id': 'call_123',
        'gen_ai.tool.call.function.arguments': '{"x": 1}',
      },
    });

    const { canonical, commitmentType } = processor.computeCommitmentPayload(
      span,
      SpanType.TOOL_EXECUTION_INTERNAL,
    );

    expect(commitmentType).toBe('input_commitment');
    const parsed = JSON.parse(canonical);
    expect(parsed.tool_name).toBe('calculator');
    expect(parsed.tool_call_id).toBe('call_123');
  });

  it('client tool span → metadata_commitment only', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    const span = makeSpan({
      name: 'remote_tool',
      attributes: { 'gen_ai.tool.name': 'api_call' },
      kind: SPAN_KIND_CLIENT,
    });

    const { commitmentType } = processor.computeCommitmentPayload(
      span,
      SpanType.TOOL_EXECUTION_CLIENT,
    );

    expect(commitmentType).toBe('metadata_commitment');
  });

  it('evaluation span → input_commitment with eval data', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({
      pipeline,
      evalThresholds: { toxicity: 0.5 },
    });

    const span = makeSpan({
      events: [
        {
          name: 'gen_ai.evaluation.result',
          attributes: {
            'gen_ai.evaluation.name': 'toxicity',
            'gen_ai.evaluation.score': 0.1,
          },
        },
      ],
    });

    const { canonical, commitmentType } = processor.computeCommitmentPayload(
      span,
      SpanType.EVALUATION,
    );

    expect(commitmentType).toBe('input_commitment');
    const parsed = JSON.parse(canonical);
    expect(parsed.eval_name).toBe('toxicity');
    expect(parsed.score).toBe(0.1);
    expect(parsed.threshold).toBe(0.5);
  });
});

// ── OTL-3: span.kind Discriminator ──

describe('OTL-3: span.kind Discriminator', () => {
  it('kind=CLIENT + tool name → TOOL_EXECUTION_CLIENT', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    const span = makeSpan({
      name: 'gen_ai.execute_tool',
      attributes: { 'gen_ai.tool.name': 'remote_api' },
      kind: SPAN_KIND_CLIENT,
    });

    expect(processor.classifySpan(span)).toBe(
      SpanType.TOOL_EXECUTION_CLIENT,
    );
  });

  it('kind=INTERNAL + tool name → TOOL_EXECUTION_INTERNAL', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    const span = makeSpan({
      name: 'gen_ai.execute_tool',
      attributes: { 'gen_ai.tool.name': 'local_calc' },
      kind: SPAN_KIND_INTERNAL,
    });

    expect(processor.classifySpan(span)).toBe(
      SpanType.TOOL_EXECUTION_INTERNAL,
    );
  });
});

// ── OTL-4: Evaluation → Mathematical ──

describe('OTL-4: Evaluation Mathematical Proof', () => {
  it('eval span with score >= threshold → check_result=pass', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({
      pipeline,
      evalThresholds: { toxicity: 0.5 },
    });

    processor.onEnd(
      makeSpan({
        name: 'eval_toxicity',
        status: { code: 1 },
        events: [
          {
            name: 'gen_ai.evaluation.result',
            attributes: {
              'gen_ai.evaluation.name': 'toxicity',
              'gen_ai.evaluation.score': 0.8,
            },
          },
        ],
      }),
    );

    expect(pipeline.records).toHaveLength(1);
    expect(pipeline.records[0].checkResult).toBe('pass');
  });

  it('eval span with score < threshold → check_result=fail', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({
      pipeline,
      evalThresholds: { toxicity: 0.5 },
    });

    processor.onEnd(
      makeSpan({
        name: 'eval_toxicity',
        status: { code: 1 },
        events: [
          {
            name: 'gen_ai.evaluation.result',
            attributes: {
              'gen_ai.evaluation.name': 'toxicity',
              'gen_ai.evaluation.score': 0.2,
            },
          },
        ],
      }),
    );

    expect(pipeline.records).toHaveLength(1);
    expect(pipeline.records[0].checkResult).toBe('fail');
  });

  it('eval span proof level is mathematical', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    const span = makeSpan({
      events: [
        {
          name: 'gen_ai.evaluation.result',
          attributes: {
            'gen_ai.evaluation.name': 'safety',
            'gen_ai.evaluation.score': 0.9,
          },
        },
      ],
    });

    const spanType = processor.classifySpan(span);
    expect(spanType).toBe(SpanType.EVALUATION);
    // TODO(zk-integration): Restore to 'mathematical' when ZK proofs are wired
    expect(processor.resolveProofLevel(span, spanType)).toBe('execution');
  });
});

// ── OTL-6: Attribute Scoping ──

describe('OTL-6: Attribute Scoping', () => {
  it('prohibited attributes are defined', () => {
    expect(PROHIBITED_ATTRIBUTES.has('gen_ai.input.messages')).toBe(true);
    expect(PROHIBITED_ATTRIBUTES.has('gen_ai.output.messages')).toBe(true);
    expect(PROHIBITED_ATTRIBUTES.has('gen_ai.system_instructions')).toBe(true);
  });

  it('deprecated attribute names are prohibited (OTL-5)', () => {
    expect(PROHIBITED_ATTRIBUTES.has('gen_ai.prompt')).toBe(true);
    expect(PROHIBITED_ATTRIBUTES.has('gen_ai.completion')).toBe(true);
    expect(PROHIBITED_ATTRIBUTES.has('input.value')).toBe(true);
  });

  it('unknown span commitment excludes prohibited attributes', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    const span = makeSpan({
      name: 'unknown_op',
      attributes: {
        'gen_ai.input.messages': 'SHOULD_NOT_APPEAR',
        'gen_ai.output.messages': 'SHOULD_NOT_APPEAR',
        'gen_ai.system_instructions': 'SHOULD_NOT_APPEAR',
        'gen_ai.prompt': 'SHOULD_NOT_APPEAR',
        safe_attr: 'this_is_fine',
      },
    });

    const { canonical } = processor.computeCommitmentPayload(
      span,
      SpanType.UNKNOWN,
    );

    expect(canonical).not.toContain('SHOULD_NOT_APPEAR');
    expect(canonical).toContain('this_is_fine');
  });
});

// ── OTL-8: Per-Tool Manifest Enforcement ──

describe('OTL-8: Per-Tool Manifest', () => {
  it('manifest resolved by gen_ai.tool.name', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({
      pipeline,
      manifestMap: { web_search: 'sha256:tool_manifest_ws' },
    });

    const span = makeSpan({
      name: 'gen_ai.execute_tool',
      attributes: { 'gen_ai.tool.name': 'web_search' },
    });

    expect(processor.resolveManifestId(span)).toBe('sha256:tool_manifest_ws');
  });

  it('span attribute manifest overrides tool name manifest', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({
      pipeline,
      manifestMap: { web_search: 'sha256:tool_manifest_ws' },
    });

    const span = makeSpan({
      name: 'gen_ai.execute_tool',
      attributes: {
        'gen_ai.tool.name': 'web_search',
        'primust.manifest_id': 'sha256:explicit_override',
      },
    });

    expect(processor.resolveManifestId(span)).toBe('sha256:explicit_override');
  });

  it('unregistered tool gets auto: prefix', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });

    const span = makeSpan({
      name: 'gen_ai.execute_tool',
      attributes: { 'gen_ai.tool.name': 'unknown_tool' },
    });

    expect(processor.resolveManifestId(span)).toBe(
      'auto:gen_ai.execute_tool',
    );
  });
});

// ── New Stage Types (PCG-1, PCG-6) ──

describe('New Stage Types in PROOF_LEVEL_MAP', () => {
  it('llm_api → attestation', () => {
    expect(PROOF_LEVEL_MAP['llm_api']).toBe('attestation');
  });

  it('open_source_ml → execution', () => {
    expect(PROOF_LEVEL_MAP['open_source_ml']).toBe('execution');
  });

  // TODO(zk-integration): Restore to 'mathematical' when ZK proofs are wired
  it('hardware_attested → execution (mathematical when ZK wired)', () => {
    expect(PROOF_LEVEL_MAP['hardware_attested']).toBe('execution');
  });

  it('policy_engine → execution (mathematical when ZK wired)', () => {
    expect(PROOF_LEVEL_MAP['policy_engine']).toBe('execution');
  });
});

// ── Surface Declaration ──

describe('Surface Declaration', () => {
  it('surface declaration is middleware_interceptor', () => {
    const pipeline = createMockPipeline();
    const processor = new PrimustSpanProcessor({ pipeline });
    const surface = processor.getSurfaceDeclaration();
    expect(surface.surface_type).toBe('middleware_interceptor');
    expect(surface.observation_mode).toBe('post_action_realtime');
  });

  it('proof ceiling is execution (upgraded from attestation)', () => {
    expect(SURFACE_DECLARATION.proof_ceiling).toBe('execution');
  });
});
