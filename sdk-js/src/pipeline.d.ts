/**
 * Primust TypeScript SDK — Pipeline class.
 *
 * Privacy invariant: raw content NEVER leaves the customer environment.
 * Only commitment hashes (poseidon2/sha256) transit to the Primust API.
 */
import { ZK_IS_BLOCKING } from '@primust/artifact-core';
export { ZK_IS_BLOCKING };
export interface PipelineConfig {
    apiKey: string;
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
    primust_commitment_hash: string;
    primust_check_result: string;
    primust_proof_level: string;
    primust_workflow_id: string;
    primust_run_id: string;
    primust_recorded_at: string;
    gap_types_emitted?: string[];
}
export interface LoggerOptions {
    includeGapTypes?: boolean;
}
export declare class Pipeline {
    private readonly apiKey;
    private readonly workflowId;
    private readonly policy;
    private readonly processContextHash;
    private readonly baseUrl;
    private readonly _fetch;
    private runId;
    private surfaceId;
    private closed;
    /** @internal For config drift detection */
    _priorManifestHashes: Record<string, string>;
    /** @internal Current manifest hashes */
    _manifestHashes: Record<string, string>;
    private _loggerCallback;
    private _loggerOptions;
    constructor(config: PipelineConfig);
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
    setLogger(callback: (event: PrimustLogEvent) => void, options?: LoggerOptions): void;
    private _invokeLogger;
    private api;
    private ensureRun;
    openCheck(check: string, manifestId: string, _options?: Record<string, unknown>): Promise<CheckSession>;
    openReview(check: string, manifestId: string, options: {
        reviewerKeyId: string;
        minDurationSeconds?: number;
    }): Promise<ReviewSession>;
    record(checkSession: CheckSession, input: unknown, checkResult: string, options?: RecordOptions): Promise<RecordResult>;
    recordDelegation(context: Record<string, unknown>): Promise<Record<string, unknown>>;
    resumeFromLineage(token: Record<string, unknown>): Promise<ResumedContext>;
    close(options?: CloseOptions): Promise<Record<string, unknown>>;
}
//# sourceMappingURL=pipeline.d.ts.map