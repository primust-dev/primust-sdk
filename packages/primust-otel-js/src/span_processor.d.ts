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
 *   Evaluation result spans → execution (mathematical when ZK proofs are wired)
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
export declare enum SpanType {
    LLM_INFERENCE = "llm_inference",
    TOOL_EXECUTION_INTERNAL = "tool_execution_internal",
    TOOL_EXECUTION_CLIENT = "tool_execution_client",
    EVALUATION = "evaluation",
    UNKNOWN = "unknown"
}
export interface SpanStatus {
    code: number;
}
export interface SpanEvent {
    name: string;
    time?: [number, number];
    attributes?: Record<string, unknown>;
}
export interface ReadableSpan {
    name: string;
    attributes: Record<string, unknown>;
    events: SpanEvent[];
    status: SpanStatus;
    startTime: [number, number];
    endTime: [number, number];
    kind?: number;
}
export declare const SPAN_KIND_INTERNAL = 0;
export declare const SPAN_KIND_SERVER = 1;
export declare const SPAN_KIND_CLIENT = 2;
export declare const SPAN_KIND_PRODUCER = 3;
export declare const SPAN_KIND_CONSUMER = 4;
export declare const PROOF_LEVEL_MAP: Record<string, string>;
export declare const SPAN_TYPE_PROOF_CEILING: Record<SpanType, string>;
export declare const SURFACE_DECLARATION: {
    surface_type: string;
    surface_name: string;
    observation_mode: string;
    scope_type: string;
    proof_ceiling: string;
    surface_coverage_statement: string;
};
export declare const PROHIBITED_ATTRIBUTES: Set<string>;
interface PipelineLike {
    openCheck(check: string, manifestId: string): {
        checkOpenTst: string | null;
        manifestId: string;
        manifestHash: string | null;
        checkName: string;
    } | Promise<{
        checkOpenTst: string | null;
        manifestId: string;
        manifestHash: string | null;
        checkName: string;
    }>;
    record(session: any, input: unknown, checkResult: string, options?: Record<string, unknown>): any;
}
export declare class PrimustSpanProcessor {
    private readonly pipeline;
    private readonly manifestMap;
    private readonly evalThresholds;
    constructor(config: {
        pipeline: PipelineLike;
        manifestMap?: Record<string, string>;
        evalThresholds?: Record<string, number>;
    });
    onStart(_span: unknown, _parentContext?: unknown): void;
    onEnd(span: ReadableSpan): void;
    shutdown(): Promise<void>;
    forceFlush(): Promise<void>;
    /**
     * Classify span type for proof level determination (OTL-1, OTL-3).
     */
    classifySpan(span: ReadableSpan): SpanType;
    /**
     * Compute commitment payload and type based on span classification (OTL-2).
     */
    computeCommitmentPayload(span: ReadableSpan, spanType: SpanType): {
        canonical: string;
        commitmentType: string;
    };
    /**
     * Extract evaluation event data for mathematical proof (OTL-4).
     */
    private _extractEvalData;
    /**
     * Resolve proof level from stage_type attribute or span type ceiling (OTL-1).
     */
    resolveProofLevel(span: ReadableSpan, spanType: SpanType): string;
    /**
     * Resolve manifest ID from span attribute, tool name, or manifestMap (OTL-8).
     *
     * Priority: primust.manifest_id attr > manifestMap[tool_name] > manifestMap[span.name] > auto
     */
    resolveManifestId(span: ReadableSpan): string;
    private _processSpan;
    getSurfaceDeclaration(): Record<string, string>;
}
export {};
//# sourceMappingURL=span_processor.d.ts.map