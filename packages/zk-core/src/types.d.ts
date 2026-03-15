/**
 * Primust ZK Core — Types for witness, prover, and proof lifecycle.
 */
import type { Prover, ProverSystem, ZkProof } from '@primust/artifact-core';
export interface WitnessInput {
    commitment_root: string;
    policy_snapshot_hash: string;
    commitment_hashes: string[];
    check_results: number[];
    manifest_hash_values: string[];
    record_count: number;
}
export interface ProofJobHandle {
    job_id: string;
    submitted_at: string;
    status: 'pending' | 'running' | 'complete' | 'failed' | 'timed_out';
}
export interface ProverConfig {
    prover: Prover;
    prover_system: ProverSystem;
    circuit: string;
    timeout_ms: number;
}
export interface ProverRouting {
    prover: Prover;
    prover_system: ProverSystem;
}
export interface ProverClient {
    submitProof(witness: WitnessInput, config: ProverConfig): Promise<ProofJobHandle>;
    getStatus(jobId: string): Promise<ProofJobHandle>;
    getProof(jobId: string): Promise<ZkProof | null>;
}
export interface SkipConditionInputs {
    skip_condition_hash: string;
    commitment_root: string;
    condition_values: bigint[];
    blinding_factor: bigint;
    merkle_path: bigint[];
    merkle_index: number;
    run_id: string;
    manifest_id: string;
    policy_snapshot_hash: string;
}
export interface ConfigEpochInputs {
    current_config_hash: string;
    prior_config_hash: string;
    epoch_transition_exists: boolean;
    transition_commitment_hash: string;
    config_params: bigint[];
    blinding_factor: bigint;
    transition_gap_commitment: bigint;
}
export interface CoverageCheckInputs {
    commitment_root: string;
    total_actions: number;
    covered_count: number;
    threshold_pct: number;
    action_hashes: string[];
    has_record: number[];
    record_count: number;
}
export interface OrderingProofInputs {
    chain_root: string;
    sequence_length: number;
    sequence_values: string[];
    sequence_count: number;
}
export interface ThresholdApplicationInputs {
    decision_hash: string;
    pass_count: number;
    scores: string[];
    thresholds: string[];
    decisions: number[];
    blinding: bigint;
    record_count: number;
}
export interface PolicyConfigIntegrityInputs {
    policy_hash: string;
    trace_count: number;
    trace_policy_hashes: string[];
    actual_count: number;
}
export interface ModelExecutionCoverageInputs {
    model_hash: string;
    coverage_pct: number;
    trace_count: number;
    trace_model_hashes: string[];
    actual_count: number;
}
export type CircuitInputs = WitnessInput | SkipConditionInputs | ConfigEpochInputs | CoverageCheckInputs | OrderingProofInputs | ThresholdApplicationInputs | PolicyConfigIntegrityInputs | ModelExecutionCoverageInputs;
//# sourceMappingURL=types.d.ts.map