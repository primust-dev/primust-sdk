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
import { canonical } from '@primust/artifact-core';
// ── Span Type Classification (OTL-1, OTL-3) ──
export var SpanType;
(function (SpanType) {
    SpanType["LLM_INFERENCE"] = "llm_inference";
    SpanType["TOOL_EXECUTION_INTERNAL"] = "tool_execution_internal";
    SpanType["TOOL_EXECUTION_CLIENT"] = "tool_execution_client";
    SpanType["EVALUATION"] = "evaluation";
    SpanType["UNKNOWN"] = "unknown";
})(SpanType || (SpanType = {}));
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
export const PROOF_LEVEL_MAP = {
    deterministic_rule: 'mathematical',
    policy_engine: 'mathematical',
    hardware_attested: 'mathematical',
    zkml_model: 'verifiable_inference',
    ml_model: 'execution',
    open_source_ml: 'execution',
    statistical_test: 'execution',
    custom_code: 'execution',
    witnessed: 'witnessed',
    llm_api: 'attestation',
    default: 'attestation',
};
// Per-span-type proof ceilings (OTL-1)
export const SPAN_TYPE_PROOF_CEILING = {
    [SpanType.LLM_INFERENCE]: 'attestation',
    [SpanType.TOOL_EXECUTION_INTERNAL]: 'execution',
    [SpanType.TOOL_EXECUTION_CLIENT]: 'attestation',
    [SpanType.EVALUATION]: 'mathematical',
    [SpanType.UNKNOWN]: 'attestation',
};
const PROOF_RANK = {
    mathematical: 0,
    verifiable_inference: 1,
    execution: 2,
    witnessed: 3,
    attestation: 4,
};
function proofRank(level) {
    return PROOF_RANK[level] ?? 4;
}
export const SURFACE_DECLARATION = {
    surface_type: 'middleware_interceptor',
    surface_name: 'otel_span_processor',
    observation_mode: 'post_action_realtime',
    scope_type: 'orchestration_boundary',
    proof_ceiling: 'execution',
    surface_coverage_statement: 'All OTEL-instrumented spans processed via SpanProcessor.onEnd(). ' +
        'Tool execution spans (INTERNAL kind) achieve execution-level proof. ' +
        'LLM inference spans achieve attestation-level proof. ' +
        'gen_ai.evaluation.result events achieve execution-level proof ' +
        '(upgradeable to mathematical when ZK proofs are wired). ' +
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
function hrtimeToIso(hrtime) {
    const ms = hrtime[0] * 1000 + hrtime[1] / 1e6;
    return new Date(ms).toISOString();
}
function durationMs(span) {
    const startMs = span.startTime[0] * 1000 + span.startTime[1] / 1e6;
    const endMs = span.endTime[0] * 1000 + span.endTime[1] / 1e6;
    return endMs - startMs;
}
function statusName(span) {
    if (span.status.code === STATUS_OK)
        return 'OK';
    if (span.status.code === STATUS_ERROR)
        return 'ERROR';
    return 'UNSET';
}
function canonicalJson(obj) {
    return canonical(obj);
}
// ── Span Processor ──
export class PrimustSpanProcessor {
    pipeline;
    manifestMap;
    evalThresholds;
    constructor(config) {
        this.pipeline = config.pipeline;
        this.manifestMap = config.manifestMap ?? {};
        this.evalThresholds = config.evalThresholds ?? {};
    }
    onStart(_span, _parentContext) {
        // no-op
    }
    onEnd(span) {
        try {
            this._processSpan(span);
        }
        catch {
            // never raise into OTEL pipeline
        }
    }
    shutdown() {
        return Promise.resolve();
    }
    forceFlush() {
        return Promise.resolve();
    }
    /**
     * Classify span type for proof level determination (OTL-1, OTL-3).
     */
    classifySpan(span) {
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
        const isToolSpan = hasToolName || nameLower.includes('tool') || nameLower.includes('execute');
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
    computeCommitmentPayload(span, spanType) {
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
                action_unit_id: String(attrs['gen_ai.tool.call.id'] ?? ''),
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
        const safeAttrs = {};
        for (const [k, v] of Object.entries(attrs)) {
            if (!PROHIBITED_ATTRIBUTES.has(k)) {
                safeAttrs[k] = v;
            }
        }
        return {
            canonical: canonical(safeAttrs),
            commitmentType: 'metadata_commitment',
        };
    }
    /**
     * Extract evaluation event data for mathematical proof (OTL-4).
     */
    _extractEvalData(span) {
        for (const event of span.events ?? []) {
            if (event.name === 'gen_ai.evaluation.result') {
                const eventAttrs = event.attributes ?? {};
                const evalName = String(eventAttrs['gen_ai.evaluation.name'] ?? '');
                const score = eventAttrs['gen_ai.evaluation.score'];
                const threshold = evalName in this.evalThresholds
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
    resolveProofLevel(span, spanType) {
        const attrs = span.attributes ?? {};
        const ceiling = SPAN_TYPE_PROOF_CEILING[spanType] ?? 'attestation';
        const stageType = String(attrs['primust.stage_type'] ?? '');
        if (stageType && stageType in PROOF_LEVEL_MAP) {
            const mapped = PROOF_LEVEL_MAP[stageType];
            // Enforce ceiling cap — mapped level cannot exceed span type ceiling
            if (proofRank(mapped) < proofRank(ceiling)) {
                return mapped;
            }
            return ceiling;
        }
        return ceiling;
    }
    /**
     * Resolve manifest ID from span attribute, tool name, or manifestMap (OTL-8).
     *
     * Priority: primust.manifest_id attr > manifestMap[tool_name] > manifestMap[span.name] > auto
     */
    resolveManifestId(span) {
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
    _processSpan(span) {
        const spanType = this.classifySpan(span);
        const manifestId = this.resolveManifestId(span);
        // Map status to check_result
        let checkResult;
        if (spanType === SpanType.EVALUATION) {
            // For eval spans, derive check_result from score vs threshold (OTL-4)
            const evalData = this._extractEvalData(span);
            const score = evalData.score;
            const threshold = evalData.threshold;
            if (score !== undefined && threshold !== undefined && threshold !== null) {
                checkResult = score >= threshold ? 'pass' : 'fail';
            }
            else if (span.status.code === STATUS_OK) {
                checkResult = 'pass';
            }
            else if (span.status.code === STATUS_ERROR) {
                checkResult = 'fail';
            }
            else {
                checkResult = 'degraded';
            }
        }
        else if (span.status.code === STATUS_OK) {
            checkResult = 'pass';
        }
        else if (span.status.code === STATUS_ERROR) {
            checkResult = 'fail';
        }
        else {
            checkResult = 'degraded';
        }
        // Compute commitment (OTL-2)
        const { canonical: inputCanonical } = this.computeCommitmentPayload(span, spanType);
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
        const options = {};
        if (span.events && span.events.length > 0) {
            options.output = span.events;
        }
        this.pipeline.record(session, inputCanonical, checkResult, options);
    }
    getSurfaceDeclaration() {
        return { ...SURFACE_DECLARATION };
    }
}
//# sourceMappingURL=span_processor.js.map