/**
 * Primust OpenTelemetry Span Processor (TypeScript).
 *
 * Maps OTEL spans to Primust CheckExecutionRecords.
 * commitment_hash = poseidon2(canonical(span.attributes)) — never raw span data.
 *
 * Surface declaration:
 *   surface_type: middleware_interceptor
 *   observation_mode: post_action_realtime
 *   scope_type: orchestration_boundary
 *   proof_ceiling: attestation
 */

import { commit, commitOutput, canonical } from '@primust/artifact-core';

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
}

// ── Constants ──

const STATUS_UNSET = 0;
const STATUS_OK = 1;
const STATUS_ERROR = 2;

export const PROOF_LEVEL_MAP: Record<string, string> = {
  deterministic_rule: 'mathematical',
  zkml_model: 'execution_zkml',
  ml_model: 'execution',
  human_review: 'witnessed',
  default: 'attestation',
};

export const SURFACE_DECLARATION = {
  surface_type: 'middleware_interceptor',
  surface_name: 'otel_span_processor',
  observation_mode: 'post_action_realtime',
  scope_type: 'orchestration_boundary',
  proof_ceiling: 'attestation',
  surface_coverage_statement:
    'All OTEL-instrumented spans processed via SpanProcessor.onEnd(). ' +
    'Provides attestation-level coverage for LangChain, AutoGen, Semantic Kernel, ' +
    'smolagents, Haystack, Vertex AI, Amazon Bedrock, CrewAI. ' +
    'Spans without OTEL instrumentation are not observed.',
};

// ── Helper ──

interface PipelineLike {
  openCheck(check: string, manifestId: string): { checkOpenTst: string | null; manifestId: string; manifestHash: string | null; checkName: string } | Promise<{ checkOpenTst: string | null; manifestId: string; manifestHash: string | null; checkName: string }>;
  record(session: any, input: unknown, checkResult: string, options?: Record<string, unknown>): any;
}

function hrtimeToIso(hrtime: [number, number]): string {
  const ms = hrtime[0] * 1000 + hrtime[1] / 1e6;
  return new Date(ms).toISOString();
}

// ── Span Processor ──

export class PrimustSpanProcessor {
  private readonly pipeline: PipelineLike;
  private readonly manifestMap: Record<string, string>;

  constructor(config: {
    pipeline: PipelineLike;
    manifestMap?: Record<string, string>;
  }) {
    this.pipeline = config.pipeline;
    this.manifestMap = config.manifestMap ?? {};
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

  private _processSpan(span: ReadableSpan): void {
    const attrs = span.attributes ?? {};

    const manifestId = String(
      attrs['primust.manifest_id'] ??
        this.manifestMap[span.name] ??
        `auto:${span.name}`,
    );

    // Map status to check_result
    let checkResult: string;
    if (span.status.code === STATUS_OK) {
      checkResult = 'pass';
    } else if (span.status.code === STATUS_ERROR) {
      checkResult = 'fail';
    } else {
      checkResult = 'degraded';
    }

    // Canonical JSON of attributes as input
    const inputStr = JSON.stringify(
      attrs,
      Object.keys(attrs).sort(),
    );
    const inputBytes = new TextEncoder().encode(inputStr);
    const { hash: commitmentHash } = commit(inputBytes);

    // Build output from events
    let outputCommitment: string | undefined;
    if (span.events && span.events.length > 0) {
      const eventsStr = JSON.stringify(span.events);
      const result = commitOutput(new TextEncoder().encode(eventsStr));
      outputCommitment = result.hash;
    }

    // Timestamps
    const checkOpenTst = hrtimeToIso(span.startTime);
    const checkCloseTst = hrtimeToIso(span.endTime);

    // We emit a synchronous record for simplicity in the span processor
    // The pipeline methods may return promises but we fire-and-forget
    const session = {
      checkName: span.name,
      manifestId,
      manifestHash: manifestId,
      checkOpenTst,
    };

    const body: Record<string, unknown> = {};
    if (outputCommitment) {
      body.output = span.events;
    }

    // Call pipeline.record directly (synchronous path for testing)
    this.pipeline.record(session, inputStr, checkResult, body.output ? { output: span.events } : {});
  }

  getSurfaceDeclaration(): Record<string, string> {
    return { ...SURFACE_DECLARATION };
  }
}
