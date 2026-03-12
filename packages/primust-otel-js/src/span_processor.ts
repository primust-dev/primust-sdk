/**
 * Primust OpenTelemetry Span Processor (TypeScript).
 *
 * Maps OTEL spans to Primust CheckExecutionRecords with span-type-aware
 * proof ceilings, conditional commitment logic, and attribute scoping.
 *
 * Per-span-type proof ceilings (OTL-1):
 *   LLM inference spans     → attestation (gen_ai.request.model is a name string)
 *   Tool execution INTERNAL → execution (input_commitment computable locally)
 *   Tool execution CLIENT   → attestation (crosses process boundary)
 *   Evaluation result spans → mathematical (deterministic threshold rule)
 *   Unknown                 → attestation (fallback)
 *
 * span.kind is the proof-level discriminator (OTL-3):
 *   INTERNAL → eligible for input_commitment → execution ceiling
 *   CLIENT   → metadata_commitment only → attestation ceiling
 *
 * Attribute reading rules (OTL-6):
 *   NEVER read: gen_ai.input.messages, gen_ai.output.messages, gen_ai.system_instructions
 *   ALWAYS read: gen_ai.tool.name, gen_ai.tool.call.id, gen_ai.tool.call.function.arguments,
 *                gen_ai.evaluation.result events
 *
 * MCP tool spans (OTL-7):
 *   In-process MCP clients emit standard gen_ai.execute_tool spans with INTERNAL kind.
 *   No MCP-specific code needed — classified as TOOL_EXECUTION_INTERNAL automatically.
 *
 * Surface declaration:
 *   surface_type: middleware_interceptor
 *   observation_mode: post_action_realtime
 *   scope_type: orchestration_boundary
 *   proof_ceiling: execution (tool spans), attestation (LLM spans)
 */

import { commit, commitOutput, canonical } from '@primust/artifact-core';

// ── Span Type Classification (OTL-1, OTL-3) ──

export enum SpanType {
  LLM_INFERENCE = 'llm_inference',
  TOOL_EXECUTION_INTERNAL = 'tool_execution_internal',
  TOOL_EXECUTION_CLIENT = 'tool_execution_client',
  EVALUATION = 'evaluation',
  UNKNOWN = 'unknown',
}

// ── Types matching OTEL SDK interfaces ──

export interface SpanStatus {
  code: number; // 0=UNSET, 1=OK, 2=ERROR
}

export interface SpanEvent {
  name: string;
  time?: [number, number]; // [seconds, nanoseconds]
  attributes?: Record<string, unknown>;
}

export interface ReadableSpan {
  name: string;
  attributes: Record<string, unknown>;
  events: SpanEvent[];
  status: SpanStatus;
  startTime: [number, number]; // [seconds, nanoseconds]
  endTime: [number, number];
  kind?: number; // SpanKind (OTL-3)
}

// ── Constants ──

const STATUS_UNSET = 0;
const STATUS_OK = 1;
const STATUS_ERROR = 2;

// OTEL SpanKind values
export const SPAN_KIND_INTERNAL = 0;
export const SPAN_KIND_SERVER = 1;
export const SPAN_KIND_CLIENT = 2;
export const SPAN_KIND_PRODUCER = 3;
export const SPAN_KIND_CONSUMER = 4;

// Proof level mapping — includes PCG-1, PCG-6 new stage types
export const PROOF_LEVEL_MAP: Record<string, string> = {
  deterministic_rule: 'mathematical',
  policy_engine: 'mathematical',
  hardware_attested: 'mathematical',
  zkml_model: 'execution_zkml',
  ml_model: 'execution',
  open_source_ml: 'execution',
  statistical_test: 'execution',
  custom_code: 'execution',
  human_review: 'witnessed',
  byollm: 'attestation',
  default: 'attestation',
};

// Per-span-type proof ceilings (OTL-1)
export const SPAN_TYPE_PROOF_CEILING: Record<SpanType, string> = {
  [SpanType.LLM_INFERENCE]: 'attestation',
  [SpanType.TOOL_EXECUTION_INTERNAL]: 'execution',
  [SpanType.TOOL_EXECUTION_CLIENT]: 'attestation',
  [SpanType.EVALUATION]: 'mathematical',
  [SpanType.UNKNOWN]: 'attestation',
};

export const SURFACE_DECLARATION = {
  surface_type: 'middleware_interceptor',
  surface_name: 'otel_span_processor',
  observation_mode: 'post_action_realtime',
  scope_type: 'orchestration_boundary',
  proof_ceiling: 'execution',
  surface_coverage_statement:
    'All OTEL-instrumented spans processed via SpanProcessor.onEnd(). ' +
    'Tool execution spans (INTERNAL kind) achieve execution-level proof. ' +
    'LLM inference spans achieve attestation-level proof. ' +
    'gen_ai.evaluation.result events achieve mathematical-level proof. ' +
    'Covers LangChain, AutoGen, Semantic Kernel, smolagents, Haystack, ' +
    'Vertex AI, Amazon Bedrock, CrewAI, MCP clients.',
};

// Attributes that MUST NEVER be included in commitments (OTL-6)
export const PROHIBITED_ATTRIBUTES = new Set([
  'gen_ai.input.messages',
  'gen_ai.output.messages',
  'gen_ai.system_instructions',
  // Deprecated names (OTL-5) — filter out if present
  'gen_ai.prompt',
  'gen_ai.completion',
  'input.value',
]);

// ── Helpers ──

interface PipelineLike {
  openCheck(
    check: string,
    manifestId: string,
  ):
    | {
        checkOpenTst: string | null;
        manifestId: string;
        manifestHash: string | null;
        checkName: string;
      }
    | Promise<{
        checkOpenTst: string | null;
        manifestId: string;
        manifestHash: string | null;
        checkName: string;
      }>;
  record(
    session: any,
    input: unknown,
    checkResult: string,
    options?: Record<string, unknown>,
  ): any;
}

function hrtimeToIso(hrtime: [number, number]): string {
  const ms = hrtime[0] * 1000 + hrtime[1] / 1e6;
  return new Date(ms).toISOString();
}

function durationMs(span: ReadableSpan): number {
  const startMs = span.startTime[0] * 1000 + span.startTime[1] / 1e6;
  const endMs = span.endTime[0] * 1000 + span.endTime[1] / 1e6;
  return endMs - startMs;
}

function statusName(span: ReadableSpan): string {
  if (span.status.code === STATUS_OK) return 'OK';
  if (span.status.code === STATUS_ERROR) return 'ERROR';
  return 'UNSET';
}

function canonicalJson(obj: unknown): string {
  return JSON.stringify(obj, Object.keys(obj as any).sort());
}

// ── Span Processor ──

export class PrimustSpanProcessor {
  private readonly pipeline: PipelineLike;
  private readonly manifestMap: Record<string, string>;
  private readonly evalThresholds: Record<string, number>;

  constructor(config: {
    pipeline: PipelineLike;
    manifestMap?: Record<string, string>;
    evalThresholds?: Record<string, number>;
  }) {
    this.pipeline = config.pipeline;
    this.manifestMap = config.manifestMap ?? {};
    this.evalThresholds = config.evalThresholds ?? {};
  }

  onStart(_span: unknown, _parentContext?: unknown): void {
    // no-op
  }

  onEnd(span: ReadableSpan): void {
    try {
      this._processSpan(span);
    } catch {
      // never raise into OTEL pipeline
    }
  }

  shutdown(): Promise<void> {
    return Promise.resolve();
  }

  forceFlush(): Promise<void> {
    return Promise.resolve();
  }

  /**
   * Classify span type for proof level determination (OTL-1, OTL-3).
   */
  classifySpan(span: ReadableSpan): SpanType {
    const attrs = span.attributes ?? {};
    const kind = span.kind;

    // Check for evaluation events first (OTL-4)
    if (span.events && span.events.length > 0) {
      for (const event of span.events) {
        if (event.name === 'gen_ai.evaluation.result') {
          return SpanType.EVALUATION;
        }
      }
    }

    // Tool execution spans (OTL-3: span.kind discriminates INTERNAL vs CLIENT)
    const nameLower = span.name.toLowerCase();
    const hasToolName = 'gen_ai.tool.name' in attrs;
    const isToolSpan =
      hasToolName || nameLower.includes('tool') || nameLower.includes('execute');

    if (isToolSpan) {
      if (kind === SPAN_KIND_CLIENT) {
        return SpanType.TOOL_EXECUTION_CLIENT;
      }
      // INTERNAL or unset kind with tool attributes → INTERNAL
      if (hasToolName) {
        return SpanType.TOOL_EXECUTION_INTERNAL;
      }
    }

    // LLM inference spans
    if (attrs['gen_ai.request.model']) {
      return SpanType.LLM_INFERENCE;
    }

    return SpanType.UNKNOWN;
  }

  /**
   * Compute commitment payload and type based on span classification (OTL-2).
   */
  computeCommitmentPayload(
    span: ReadableSpan,
    spanType: SpanType,
  ): { canonical: string; commitmentType: string } {
    const attrs = span.attributes ?? {};

    if (spanType === SpanType.LLM_INFERENCE) {
      // Metadata commitment — only safe fields (OTL-2, OTL-6)
      const payload = {
        duration_ms: durationMs(span),
        model: String(attrs['gen_ai.request.model'] ?? 'unknown'),
        span_name: span.name,
        status: statusName(span),
      };
      return {
        canonical: JSON.stringify(payload),
        commitmentType: 'metadata_commitment',
      };
    }

    if (spanType === SpanType.TOOL_EXECUTION_INTERNAL) {
      // Input commitment — structured tool arguments (OTL-2, OTL-6)
      const payload = {
        arguments: attrs['gen_ai.tool.call.function.arguments'] ?? {},
        tool_call_id: String(attrs['gen_ai.tool.call.id'] ?? ''),
        tool_name: String(attrs['gen_ai.tool.name'] ?? span.name),
      };
      return {
        canonical: JSON.stringify(payload),
        commitmentType: 'input_commitment',
      };
    }

    if (spanType === SpanType.TOOL_EXECUTION_CLIENT) {
      // Metadata commitment only — crosses process boundary (OTL-3)
      const payload = {
        duration_ms: durationMs(span),
        span_name: span.name,
        status: statusName(span),
        tool_name: String(attrs['gen_ai.tool.name'] ?? span.name),
      };
      return {
        canonical: JSON.stringify(payload),
        commitmentType: 'metadata_commitment',
      };
    }

    if (spanType === SpanType.EVALUATION) {
      // Input commitment over evaluation data (OTL-4)
      const evalData = this._extractEvalData(span);
      return {
        canonical: JSON.stringify(evalData),
        commitmentType: 'input_commitment',
      };
    }

    // Unknown — filter prohibited attributes, commit the rest (OTL-6)
    const safeAttrs: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(attrs)) {
      if (!PROHIBITED_ATTRIBUTES.has(k)) {
        safeAttrs[k] = v;
      }
    }
    return {
      canonical: JSON.stringify(safeAttrs, Object.keys(safeAttrs).sort()),
      commitmentType: 'metadata_commitment',
    };
  }

  /**
   * Extract evaluation event data for mathematical proof (OTL-4).
   */
  private _extractEvalData(span: ReadableSpan): Record<string, unknown> {
    for (const event of span.events ?? []) {
      if (event.name === 'gen_ai.evaluation.result') {
        const eventAttrs = event.attributes ?? {};
        const evalName = String(eventAttrs['gen_ai.evaluation.name'] ?? '');
        const score = eventAttrs['gen_ai.evaluation.score'];
        const threshold =
          evalName in this.evalThresholds
            ? this.evalThresholds[evalName]
            : undefined;
        return {
          eval_name: evalName,
          score,
          threshold: threshold ?? null,
        };
      }
    }
    return { span_name: span.name };
  }

  /**
   * Resolve proof level from stage_type attribute or span type ceiling (OTL-1).
   */
  resolveProofLevel(span: ReadableSpan, spanType: SpanType): string {
    const attrs = span.attributes ?? {};
    const ceiling = SPAN_TYPE_PROOF_CEILING[spanType] ?? 'attestation';

    const stageType = String(attrs['primust.stage_type'] ?? '');
    if (stageType && stageType in PROOF_LEVEL_MAP) {
      return PROOF_LEVEL_MAP[stageType];
    }

    // Evaluation spans → mathematical (OTL-4)
    if (spanType === SpanType.EVALUATION) {
      return 'mathematical';
    }

    return ceiling;
  }

  /**
   * Resolve manifest ID from span attribute, tool name, or manifestMap (OTL-8).
   *
   * Priority: primust.manifest_id attr > manifestMap[tool_name] > manifestMap[span.name] > auto
   */
  resolveManifestId(span: ReadableSpan): string {
    const attrs = span.attributes ?? {};

    // Explicit override
    if ('primust.manifest_id' in attrs) {
      return String(attrs['primust.manifest_id']);
    }

    // Per-tool manifest (OTL-8)
    const toolName = String(attrs['gen_ai.tool.name'] ?? '');
    if (toolName && toolName in this.manifestMap) {
      return this.manifestMap[toolName];
    }

    // Span name fallback
    if (span.name in this.manifestMap) {
      return this.manifestMap[span.name];
    }

    return `auto:${span.name}`;
  }

  private _processSpan(span: ReadableSpan): void {
    const spanType = this.classifySpan(span);
    const manifestId = this.resolveManifestId(span);

    // Map status to check_result
    let checkResult: string;
    if (spanType === SpanType.EVALUATION) {
      // For eval spans, derive check_result from score vs threshold (OTL-4)
      const evalData = this._extractEvalData(span);
      const score = evalData.score as number | undefined;
      const threshold = evalData.threshold as number | undefined | null;
      if (score !== undefined && threshold !== undefined && threshold !== null) {
        checkResult = score >= threshold ? 'pass' : 'fail';
      } else if (span.status.code === STATUS_OK) {
        checkResult = 'pass';
      } else if (span.status.code === STATUS_ERROR) {
        checkResult = 'fail';
      } else {
        checkResult = 'degraded';
      }
    } else if (span.status.code === STATUS_OK) {
      checkResult = 'pass';
    } else if (span.status.code === STATUS_ERROR) {
      checkResult = 'fail';
    } else {
      checkResult = 'degraded';
    }

    // Compute commitment (OTL-2)
    const { canonical: inputCanonical } = this.computeCommitmentPayload(
      span,
      spanType,
    );

    // Timestamps
    const checkOpenTst = hrtimeToIso(span.startTime);
    const checkCloseTst = hrtimeToIso(span.endTime);

    const session = {
      checkName: span.name,
      manifestId,
      manifestHash: manifestId,
      checkOpenTst,
    };

    // Build output from events if present
    const options: Record<string, unknown> = {};
    if (span.events && span.events.length > 0) {
      options.output = span.events;
    }

    this.pipeline.record(session, inputCanonical, checkResult, options);
  }

  getSurfaceDeclaration(): Record<string, string> {
    return { ...SURFACE_DECLARATION };
  }
}
