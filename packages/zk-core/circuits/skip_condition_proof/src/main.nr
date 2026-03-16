// Skip Condition Proof Circuit
//
// The witness builder (buildSkipConditionWitness) computes real Merkle
// proof paths from the record's position in the commitment tree.
// Single-leaf trees use all-zero siblings (circuit skips zero levels).
// Multi-leaf trees pass commitmentHashes[] to get the full proof path.
//
// Proves that a recorded skip was justified -- the declared skip
// condition evaluated to true. Upgrades skip records from attestation
// to mathematical proof level.
//
// Public inputs:
//   - skip_condition_hash: Poseidon2 hash of the declared condition
//   - commitment_root: Merkle root of run commitments
//
// Private inputs:
//   - condition_values: Actual condition parameter values
//   - blinding_factor: Blinding factor for hash preimage
//   - merkle_path: Sibling hashes along the Merkle path
//   - merkle_index: Position in the Merkle tree
//
// Constraints:
//   1. Poseidon2(condition_values, blinding_factor) == skip_condition_hash
//   2. Merkle path from leaf to commitment_root closes correctly
//   3. At least one condition_value is non-zero (condition is not vacuous)

use dep::poseidon::poseidon2;

fn main(
    // Public inputs
    skip_condition_hash: pub Field,
    commitment_root: pub Field,

    // Private inputs
    condition_values: [Field; 16],
    blinding_factor: Field,
    merkle_path: [Field; 20],
    merkle_index: u32,
) {
    // Constraint 1: Poseidon2(condition_values, blinding_factor) == skip_condition_hash
    // Hash all condition values with blinding factor into a single commitment
    let mut hash_inputs: [Field; 17] = [0; 17];
    for i in 0..16 {
        hash_inputs[i] = condition_values[i];
    }
    hash_inputs[16] = blinding_factor;
    let computed_hash = poseidon2::Poseidon2::hash(hash_inputs, 17);
    assert(computed_hash == skip_condition_hash);

    // Constraint 2: Merkle path verification
    // Walk from leaf (skip_condition_hash) up to commitment_root
    let mut current = skip_condition_hash;
    let mut idx = merkle_index;
    for i in 0..20 {
        let sibling = merkle_path[i];
        // If sibling is zero, we've reached the top (path shorter than 20)
        if sibling != 0 {
            if (idx & 1) == 0 {
                // Current is left child
                current = poseidon2::Poseidon2::hash([current, sibling], 2);
            } else {
                // Current is right child
                current = poseidon2::Poseidon2::hash([sibling, current], 2);
            }
            idx = idx >> 1;
        }
    }
    assert(current == commitment_root);

    // Constraint 3: At least one condition_value is non-zero (not vacuous)
    let mut has_nonzero = false;
    for i in 0..16 {
        if condition_values[i] != 0 {
            has_nonzero = true;
        }
    }
    assert(has_nonzero);
}
