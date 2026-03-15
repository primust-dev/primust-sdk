/**
 * Primust ZK Core — Prover Routing and Async Proving (P6-B)
 *
 * Routes proof levels to prover systems and submits non-blocking proof jobs.
 * ZK_IS_BLOCKING = false — proofs NEVER block VPEC issuance.
 */
/** Proof generation timeout: 5 minutes. */
export const PROOF_TIMEOUT_MS = 300_000;
/**
 * Route a proof level to the appropriate prover system.
 *
 * mathematical   → UltraHonk → Modal CPU
 * verifiable_inference → EZKL      → Modal GPU (Tier 2)
 * execution      → no ZK proof needed (returns null)
 * witnessed      → no ZK proof needed (returns null)
 * attestation    → no ZK proof needed (returns null)
 */
export function routeProver(proofLevel) {
    switch (proofLevel) {
        case 'mathematical':
            return { prover: 'modal_cpu', prover_system: 'ultrahonk' };
        case 'verifiable_inference':
            return { prover: 'modal_gpu', prover_system: 'ezkl' };
        case 'execution':
        case 'witnessed':
        case 'attestation':
            return null;
    }
}
/**
 * Submit a proof asynchronously. Non-blocking per ZK_IS_BLOCKING = false.
 * Returns a handle; the caller polls or receives a webhook.
 *
 * Returns null if the proof level does not require ZK proof generation.
 */
export async function proveAsync(witness, runId, proofLevel, client, circuit = 'primust_governance_v1') {
    const routing = routeProver(proofLevel);
    if (routing === null)
        return null;
    const circuitRouting = getCircuitRouting(circuit);
    const config = {
        prover: circuitRouting?.prover ?? routing.prover,
        prover_system: circuitRouting?.prover_system ?? routing.prover_system,
        circuit,
        timeout_ms: PROOF_TIMEOUT_MS,
    };
    return client.submitProof(witness, config);
}
/**
 * Stub ProverClient for testing and development.
 * Resolves immediately with a mock job handle.
 */
export class StubProverClient {
    jobs = new Map();
    async submitProof(_witness, _config) {
        const handle = {
            job_id: `job_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
            submitted_at: new Date().toISOString(),
            status: 'pending',
        };
        this.jobs.set(handle.job_id, handle);
        return handle;
    }
    async getStatus(jobId) {
        return (this.jobs.get(jobId) ?? {
            job_id: jobId,
            submitted_at: '',
            status: 'failed',
        });
    }
    async getProof(_jobId) {
        return null;
    }
    /** Test helper: simulate job completion. */
    completeJob(jobId) {
        const job = this.jobs.get(jobId);
        if (job)
            job.status = 'complete';
    }
    /** Test helper: simulate job timeout. */
    timeoutJob(jobId) {
        const job = this.jobs.get(jobId);
        if (job)
            job.status = 'timed_out';
    }
}
// ── Circuit Registry ──
/**
 * Registry mapping circuit names to their prover routing.
 * All current circuits use UltraHonk on Modal CPU.
 */
export const CIRCUIT_REGISTRY = {
    primust_governance_v1: { prover: 'modal_cpu', prover_system: 'ultrahonk' },
    skip_condition_proof: { prover: 'modal_cpu', prover_system: 'ultrahonk' },
    config_epoch_continuity: { prover: 'modal_cpu', prover_system: 'ultrahonk' },
    coverage_check: { prover: 'modal_cpu', prover_system: 'ultrahonk' },
    ordering_proof: { prover: 'modal_cpu', prover_system: 'ultrahonk' },
    threshold_application: { prover: 'modal_cpu', prover_system: 'ultrahonk' },
    policy_config_integrity: { prover: 'modal_cpu', prover_system: 'ultrahonk' },
    model_execution_coverage: { prover: 'modal_cpu', prover_system: 'ultrahonk' },
};
/**
 * Maps stage types to the circuits that should be proven.
 * Used by multi-circuit proving to determine which circuits
 * to run for a given pipeline close.
 */
export const STAGE_CIRCUIT_MAP = {
    governance: ['primust_governance_v1', 'coverage_check', 'ordering_proof'],
    policy: ['policy_config_integrity'],
    threshold: ['threshold_application'],
    skip: ['skip_condition_proof'],
    config: ['config_epoch_continuity'],
    model: ['model_execution_coverage'],
};
/**
 * Look up prover routing for a named circuit.
 * Returns null if the circuit is not registered.
 */
export function getCircuitRouting(circuitName) {
    return CIRCUIT_REGISTRY[circuitName] ?? null;
}
//# sourceMappingURL=prover.js.map