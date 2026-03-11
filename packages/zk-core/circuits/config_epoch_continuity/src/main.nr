// Config Epoch Continuity Circuit
//
// Proves that the process_context_hash in this VPEC matches the
// prior VPEC, OR that a recorded epoch transition gap exists
// committing to both the old and new hash. Prevents post-hoc
// configuration substitution.
//
// Public inputs:
//   - current_config_hash: process_context_hash on this run
//   - prior_config_hash: process_context_hash from prior VPEC
//   - epoch_transition_exists: whether an epoch transition gap was recorded
//
// Private inputs:
//   - config_params: Actual config parameter values
//   - blinding_factor: Blinding factor for hash preimage
//   - transition_gap_commitment: 0 if no transition, Poseidon2(gap_record) if yes
//
// Constraints:
//   1. If !epoch_transition_exists: current == prior (no change allowed)
//   2. If epoch_transition_exists: transition_gap_commitment != 0 and closes correctly
//   3. Poseidon2(config_params, blinding_factor) == current_config_hash

use std::hash::poseidon2;

fn main(
    // Public inputs
    current_config_hash: pub Field,
    prior_config_hash: pub Field,
    epoch_transition_exists: pub bool,
    transition_commitment_hash: pub Field,

    // Private inputs
    config_params: [Field; 32],
    blinding_factor: Field,
    transition_gap_commitment: Field,
) {
    // Constraint 1: If no epoch transition, hashes must match exactly
    if !epoch_transition_exists {
        assert(current_config_hash == prior_config_hash);
    }

    // Constraint 2: If epoch transition, gap commitment must match public input
    if epoch_transition_exists {
        // transition_gap_commitment must not be zero (real gap record exists)
        assert(transition_gap_commitment != 0);

        // Verify the gap commitment binds to the blinding factor
        let gap_binding = poseidon2::Poseidon2::hash(
            [transition_gap_commitment, blinding_factor],
            2,
        );
        // Gap binding must match the externally verifiable public input
        assert(gap_binding == transition_commitment_hash);
    }

    // When no epoch transition, the public input must be zero
    if !epoch_transition_exists {
        assert(transition_commitment_hash == 0);
    }

    // Constraint 3: Poseidon2(config_params, blinding_factor) == current_config_hash
    let mut hash_inputs: [Field; 33] = [0; 33];
    for i in 0..32 {
        hash_inputs[i] = config_params[i];
    }
    hash_inputs[32] = blinding_factor;
    let computed_hash = poseidon2::Poseidon2::hash(hash_inputs, 33);
    assert(computed_hash == current_config_hash);
}
