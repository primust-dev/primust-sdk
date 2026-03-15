export { buildWitness, MAX_RECORDS } from './witness.js';
export { proveAsync, routeProver, StubProverClient, PROOF_TIMEOUT_MS, CIRCUIT_REGISTRY, STAGE_CIRCUIT_MAP, getCircuitRouting, } from './prover.js';
export { ProofLifecycleManager } from './proof-lifecycle.js';
export type { ProofState, ProofLifecycleCallbacks, VPECProofStatus, } from './proof-lifecycle.js';
export { buildSkipConditionWitness } from './witnesses/skip_condition_proof.js';
export { buildConfigEpochWitness } from './witnesses/config_epoch_continuity.js';
export { buildCoverageCheckWitness } from './witnesses/coverage_check.js';
export { buildOrderingProofWitness } from './witnesses/ordering_proof.js';
export { ModalProverClient } from './modal-prover-client.js';
export type { ModalProverClientOptions } from './modal-prover-client.js';
export type { WitnessInput, ProofJobHandle, ProverClient, ProverConfig, ProverRouting, SkipConditionInputs, ConfigEpochInputs, CoverageCheckInputs, OrderingProofInputs, ThresholdApplicationInputs, PolicyConfigIntegrityInputs, ModelExecutionCoverageInputs, CircuitInputs, } from './types.js';
//# sourceMappingURL=index.d.ts.map