/**
 * Witness builder for config_epoch_continuity circuit.
 *
 * Proves that the process_context_hash in this VPEC matches the
 * prior VPEC, OR that a recorded epoch transition gap exists
 * committing to both the old and new hash.
 */
import { commit } from '@primust/artifact-core';
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
export function buildConfigEpochWitness(currentRun, priorVpec, configParams, blindingFactor, transitionGapCommitment = 0n) {
    // Pad config_params to 32 elements
    const paddedParams = Array(32).fill(0n);
    for (let i = 0; i < Math.min(configParams.length, 32); i++) {
        paddedParams[i] = configParams[i];
    }
    // Compute current_config_hash from config_params + blinding_factor
    const hashInput = new Uint8Array(33 * 32);
    for (let i = 0; i < 32; i++) {
        hashInput.set(bigintToBytes32(paddedParams[i]), i * 32);
    }
    hashInput.set(bigintToBytes32(blindingFactor), 32 * 32);
    const { hash: currentConfigHash } = commit(hashInput, 'poseidon2');
    // Determine prior config hash and epoch transition state
    let priorConfigHash;
    let epochTransitionExists;
    if (priorVpec === null) {
        // First run in sequence: continuity trivially holds
        priorConfigHash = currentConfigHash;
        epochTransitionExists = false;
    }
    else {
        // Derive prior hash from prior VPEC's process_context_hash
        priorConfigHash =
            priorVpec.process_context_hash ??
                'poseidon2:' + '0'.repeat(64);
        // Prefix with poseidon2: if it doesn't already have an algorithm prefix
        if (!priorConfigHash.includes(':')) {
            priorConfigHash = 'poseidon2:' + priorConfigHash;
        }
        if (currentConfigHash === priorConfigHash) {
            // Hashes match: no transition needed
            epochTransitionExists = false;
        }
        else {
            // Hashes differ: must have a transition gap commitment
            epochTransitionExists = true;
            if (transitionGapCommitment === 0n) {
                throw new Error('config_epoch_continuity: hashes differ but no transition_gap_commitment provided');
            }
        }
    }
    // Compute transition_commitment_hash for the public input
    let transitionCommitmentHash;
    if (epochTransitionExists) {
        const tcInput = new Uint8Array(2 * 32);
        tcInput.set(bigintToBytes32(transitionGapCommitment), 0);
        tcInput.set(bigintToBytes32(blindingFactor), 32);
        const { hash } = commit(tcInput, 'poseidon2');
        transitionCommitmentHash = hash;
    }
    else {
        transitionCommitmentHash = '0';
    }
    return {
        current_config_hash: currentConfigHash,
        prior_config_hash: priorConfigHash,
        epoch_transition_exists: epochTransitionExists,
        transition_commitment_hash: transitionCommitmentHash,
        config_params: paddedParams,
        blinding_factor: blindingFactor,
        transition_gap_commitment: transitionGapCommitment,
    };
}
/** Convert a bigint to 32-byte big-endian Uint8Array. */
function bigintToBytes32(value) {
    const bytes = new Uint8Array(32);
    let v = value;
    for (let i = 31; i >= 0; i--) {
        bytes[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    return bytes;
}
//# sourceMappingURL=config_epoch_continuity.js.map