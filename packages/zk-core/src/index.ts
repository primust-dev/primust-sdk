// @primust/zk-core — Witness builders, prover routing, proof lifecycle

// Witness
export { buildWitness, MAX_RECORDS } from './witness.js';

// Proving
export {
  proveAsync,
  routeProver,
  StubProverClient,
  PROOF_TIMEOUT_MS,
  CIRCUIT_REGISTRY,
  STAGE_CIRCUIT_MAP,
  getCircuitRouting,
} from './prover.js';

// Proof lifecycle
export { ProofLifecycleManager } from './proof-lifecycle.js';
export type {
  ProofState,
  ProofLifecycleCallbacks,
  VPECProofStatus,
} from './proof-lifecycle.js';

// Circuit-specific witness builders
export { buildSkipConditionWitness } from './witnesses/skip_condition_proof.js';
export { buildConfigEpochWitness } from './witnesses/config_epoch_continuity.js';
export { buildCoverageCheckWitness } from './witnesses/coverage_check.js';
export { buildOrderingProofWitness } from './witnesses/ordering_proof.js';

// Modal prover client
export { ModalProverClient } from './modal-prover-client.js';
export type { ModalProverClientOptions } from './modal-prover-client.js';

// Types
export type {
  WitnessInput,
  ProofJobHandle,
  ProverClient,
  ProverConfig,
  ProverRouting,
  SkipConditionInputs,
  ConfigEpochInputs,
  CoverageCheckInputs,
  OrderingProofInputs,
  ThresholdApplicationInputs,
  PolicyConfigIntegrityInputs,
  ModelExecutionCoverageInputs,
  CircuitInputs,
} from './types.js';
