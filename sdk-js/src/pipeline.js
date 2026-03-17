/**
 * Primust TypeScript SDK — Pipeline class.
 *
 * Privacy invariant: raw content NEVER leaves the customer environment.
 * Only commitment hashes (poseidon2/sha256) transit to the Primust API.
 */
import { commit, commitOutput, ZK_IS_BLOCKING, canonical, } from '@primust/artifact-core';
// Re-export constant
export { ZK_IS_BLOCKING };
// ── Helpers ──
function toBytes(value) {
    if (value instanceof Uint8Array)
        return value;
    if (typeof value === 'string')
        return new TextEncoder().encode(value);
    return new TextEncoder().encode(canonical(value));
}
// ── Pipeline ──
export class Pipeline {
    apiKey;
    workflowId;
    policy;
    processContextHash;
    baseUrl;
    _fetch;
    runId = null;
    surfaceId = null;
    closed = false;
    /** @internal For config drift detection */
    _priorManifestHashes = {};
    /** @internal Current manifest hashes */
    _manifestHashes = {};
    _loggerCallback = null;
    _loggerOptions = {};
    constructor(config) {
        this.apiKey = config.apiKey;
        this.workflowId = config.workflowId;
        this.policy = config.policy;
        this.processContextHash = config.processContextHash;
        this.baseUrl = (config.baseUrl ?? 'https://api.primust.com').replace(/\/+$/, '');
        this._fetch = config.fetch ?? globalThis.fetch.bind(globalThis);
    }
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
    setLogger(callback, options) {
        this._loggerCallback = callback;
        if (options)
            this._loggerOptions = options;
    }
    _invokeLogger(event) {
        if (!this._loggerCallback)
            return;
        try {
            this._loggerCallback(event);
        }
        catch {
            // Exceptions in callback are caught — never propagate.
        }
    }
    async api(method, path, body) {
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
        return resp.json();
    }
    async ensureRun(surfaceId = 'default') {
        if (this.runId)
            return this.runId;
        const body = {
            workflow_id: this.workflowId,
            surface_id: surfaceId,
            policy_pack_id: typeof this.policy === 'string' ? this.policy : 'default',
        };
        if (this.processContextHash) {
            body.process_context_hash = this.processContextHash;
        }
        const data = await this.api('POST', '/api/v1/runs', body);
        this.runId = data.run_id;
        return this.runId;
    }
    async openCheck(check, manifestId, _options) {
        await this.ensureRun();
        const now = new Date().toISOString();
        return {
            checkName: check,
            manifestId,
            manifestHash: this._manifestHashes[manifestId] ?? manifestId,
            checkOpenTst: now,
        };
    }
    async openReview(check, manifestId, options) {
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
    async record(checkSession, input, checkResult, options = {}) {
        if (!this.runId)
            throw new Error('Pipeline not opened');
        const now = new Date().toISOString();
        // Compute commitment hashes locally — raw content NEVER sent
        const inputBytes = toBytes(input);
        const { hash: commitmentHash, algorithm: commitmentAlgorithm } = commit(inputBytes);
        let outputCommitment = null;
        if (options.output !== undefined) {
            const outputBytes = toBytes(options.output);
            const result = commitOutput(outputBytes);
            outputCommitment = result.hash;
        }
        let skipRationaleHash = null;
        if (options.skipRationale !== undefined) {
            const { hash } = commit(new TextEncoder().encode(options.skipRationale));
            skipRationaleHash = hash;
        }
        // Enforce min_duration_seconds for review sessions at record() time
        if ('reviewerKeyId' in checkSession) {
            const rs = checkSession;
            const openedMs = new Date(rs.openedAt).getTime();
            const nowMs = new Date(now).getTime();
            const elapsedSec = (nowMs - openedMs) / 1000;
            if (elapsedSec < rs.minDurationSeconds) {
                throw new Error(`Review duration ${elapsedSec.toFixed(1)}s is below minimum ${rs.minDurationSeconds}s (check_timing_suspect)`);
            }
        }
        // Build reviewer_credential for witnessed records
        let reviewerCredential;
        if (options.reviewerSignature && 'reviewerKeyId' in checkSession) {
            const rs = checkSession;
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
                key_binding: 'software',
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
        const body = {
            manifest_id: checkSession.manifestId,
            commitment_hash: commitmentHash,
            commitment_algorithm: commitmentAlgorithm,
            commitment_type: 'input_commitment',
            check_result: checkResult,
            proof_level_achieved: proofLevel,
            check_open_tst: checkSession.checkOpenTst,
            check_close_tst: now,
            idempotency_key: `idem_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`,
        };
        if (outputCommitment)
            body.output_commitment = outputCommitment;
        if (skipRationaleHash)
            body.skip_rationale_hash = skipRationaleHash;
        if (reviewerCredential)
            body.reviewer_credential = reviewerCredential;
        // Logger callback — called after commitment_hash computed, before API call.
        this._invokeLogger({
            primust_record_id: body.idempotency_key,
            primust_commitment_hash: commitmentHash,
            primust_check_result: checkResult,
            primust_proof_level: proofLevel,
            primust_workflow_id: this.workflowId,
            primust_run_id: this.runId,
            primust_recorded_at: now,
        });
        const data = await this.api('POST', `/api/v1/runs/${this.runId}/records`, body);
        return {
            recordId: data.record_id,
            chainHash: data.chain_hash,
            commitmentHash,
            outputCommitment,
        };
    }
    async recordDelegation(context) {
        if (!this.runId)
            throw new Error('Pipeline not opened');
        return {
            token: `lt_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`,
            run_id: this.runId,
            surface_id: this.surfaceId ?? 'default',
            delegation_context: context,
            issued_at: new Date().toISOString(),
        };
    }
    async resumeFromLineage(token) {
        return {
            runId: token.run_id ?? '',
            surfaceId: token.surface_id ?? '',
            delegationContext: token.delegation_context ?? {},
        };
    }
    async close(options = {}) {
        if (!this.runId)
            throw new Error('Pipeline not opened');
        if (this.closed)
            throw new Error('Pipeline already closed');
        const data = await this.api('POST', `/api/v1/runs/${this.runId}/close`, {
            partial: options.partial ?? false,
            request_zk: options.requestZk ?? false,
        });
        this.closed = true;
        return data;
    }
}
//# sourceMappingURL=pipeline.js.map