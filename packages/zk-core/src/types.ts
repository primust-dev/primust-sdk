/**
 * Primust ZK Core — Types for witness, prover, and proof lifecycle.
 */

import type { ProofLevel, Prover, ProverSystem, ZkProof } from '@primust/artifact-core';

// ── Witness ──

export interface WitnessInput {
  commitment_root: string;
  policy_snapshot_hash: string;
  commitment_hashes: string[];
  check_results: number[];
  manifest_hash_values: string[];
  record_count: number;
}

// ── Prover ──

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

// ── Circuit-Specific Witness Types ──

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
  config_params: bigint[];
  blinding_factor: bigint;
  transition_gap_commitment: bigint;
}

export type CircuitInputs = WitnessInput | SkipConditionInputs | ConfigEpochInputs;
