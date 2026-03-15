/**
 * Primust ZK Core — Modal Prover Client
 *
 * ProverClient implementation that submits proof jobs to a Modal
 * serverless function via HTTP. Non-blocking: submitProof() returns
 * immediately with a job handle; proof completes asynchronously.
 *
 * Environment variables:
 *   PRIMUST_MODAL_ENDPOINT  — Base URL of the Modal proof worker
 *   PRIMUST_MODAL_AUTH_TOKEN — Bearer token for Modal webhook auth
 */
export class ModalProverClient {
    endpoint;
    authToken;
    requestTimeoutMs;
    constructor(options = {}) {
        this.endpoint =
            options.endpoint ??
                process.env.PRIMUST_MODAL_ENDPOINT ??
                'https://primust--zk-worker-prove-ultrahonk.modal.run';
        this.authToken =
            options.authToken ?? process.env.PRIMUST_MODAL_AUTH_TOKEN ?? '';
        this.requestTimeoutMs = options.requestTimeoutMs ?? 30_000;
    }
    async submitProof(witness, config) {
        const body = JSON.stringify({
            witness,
            circuit: config.circuit,
            prover_system: config.prover_system,
            timeout_ms: config.timeout_ms,
        });
        const response = await fetch(`${this.endpoint}/submit`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...(this.authToken
                    ? { Authorization: `Bearer ${this.authToken}` }
                    : {}),
            },
            body,
            signal: AbortSignal.timeout(this.requestTimeoutMs),
        });
        if (!response.ok) {
            throw new Error(`Modal proof submission failed: ${response.status} ${response.statusText}`);
        }
        const result = (await response.json());
        return {
            job_id: result.job_id,
            submitted_at: result.submitted_at,
            status: 'pending',
        };
    }
    async getStatus(jobId) {
        const response = await fetch(`${this.endpoint}/status/${jobId}`, {
            headers: {
                ...(this.authToken
                    ? { Authorization: `Bearer ${this.authToken}` }
                    : {}),
            },
            signal: AbortSignal.timeout(this.requestTimeoutMs),
        });
        if (!response.ok) {
            throw new Error(`Modal status check failed: ${response.status} ${response.statusText}`);
        }
        return (await response.json());
    }
    async getProof(jobId) {
        const response = await fetch(`${this.endpoint}/proof/${jobId}`, {
            headers: {
                ...(this.authToken
                    ? { Authorization: `Bearer ${this.authToken}` }
                    : {}),
            },
            signal: AbortSignal.timeout(this.requestTimeoutMs),
        });
        if (!response.ok) {
            if (response.status === 404)
                return null;
            throw new Error(`Modal proof retrieval failed: ${response.status} ${response.statusText}`);
        }
        return (await response.json());
    }
}
//# sourceMappingURL=modal-prover-client.js.map