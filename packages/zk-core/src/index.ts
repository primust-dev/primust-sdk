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

// Types
export type {
  WitnessInput,
  ProofJobHandle,
  ProverClient,
  ProverConfig,
  ProverRouting,
  SkipConditionInputs,
  ConfigEpochInputs,
  CircuitInputs,
} from './types.js';
