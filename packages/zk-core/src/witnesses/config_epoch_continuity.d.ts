/**
 * Witness builder for config_epoch_continuity circuit.
 *
 * Proves that the process_context_hash in this VPEC matches the
 * prior VPEC, OR that a recorded epoch transition gap exists
 * committing to both the old and new hash.
 */
import type { VPECArtifact } from '@primust/artifact-core';
import type { ProcessRun } from '@primust/runtime-core';
import type { ConfigEpochInputs } from '../types.js';
/**
 * Build witness inputs for the config_epoch_continuity circuit.
 *
 * @param currentRun - The current ProcessRun
 * @param priorVpec - The prior VPECArtifact, or null if first run
 * @param configParams - The actual config parameter values (max 32)
 * @param blindingFactor - Blinding factor for hash preimage hiding
 * @param transitionGapCommitment - Poseidon2(gap_record) if epoch transition, 0n otherwise
 * @returns ConfigEpochInputs ready for circuit proving
 * @throws If hashes differ and transitionGapCommitment is zero
 */
export declare function buildConfigEpochWitness(currentRun: ProcessRun, priorVpec: VPECArtifact | null, configParams: bigint[], blindingFactor: bigint, transitionGapCommitment?: bigint): ConfigEpochInputs;
//# sourceMappingURL=config_epoch_continuity.d.ts.map