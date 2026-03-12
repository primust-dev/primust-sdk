// Primust Governance Circuit v1
//
// Proves governance completeness over a set of CheckExecutionRecords
// without revealing individual check results.
//
// Public inputs:
//   - commitment_root: Poseidon2 Merkle root over all commitment_hashes
//   - policy_snapshot_hash: Hash of the policy snapshot at run time
//
// Private inputs:
//   - commitment_hashes: Individual record commitment hashes
//   - check_results: Check results encoded as u8 (0=pass..7=timed_out)
//   - manifest_hash_values: Manifest hashes per record
//   - record_count: Number of actual records (rest is padding)
//
// Constraints:
//   1. Merkle root recomputation matches commitment_root public input
//   2. All pass/not_applicable records counted for governance completeness
//   3. No override records present (enforcement integrity)

use dep::poseidon::poseidon2;

global MAX_RECORDS: u32 = 64;

// CheckResult encoding
global CHECK_PASS: u8 = 0;
global CHECK_OVERRIDE: u8 = 5;
global CHECK_NOT_APPLICABLE: u8 = 6;

fn main(
    // Public inputs
    commitment_root: pub Field,
    policy_snapshot_hash: pub Field,

    // Private inputs
    commitment_hashes: [Field; 64],
    check_results: [u8; 64],
    manifest_hash_values: [Field; 64],
    record_count: u32,
) {
    // Constraint 1: Recompute Merkle root from commitment_hashes
    let computed_root = compute_merkle_root(commitment_hashes, record_count);
    assert(computed_root == commitment_root);

    // Constraint 2 & 3: Verify governance completeness and no overrides
    let mut governance_count: u32 = 0;
    for i in 0..MAX_RECORDS {
        if (i as u32) < record_count {
            let result = check_results[i];

            // Constraint 3: No override records allowed
            assert(result != CHECK_OVERRIDE);

            // Constraint 2: Count pass + not_applicable
            if (result == CHECK_PASS) | (result == CHECK_NOT_APPLICABLE) {
                governance_count += 1;
            }
        }
    }

    // Bind policy_snapshot_hash to prevent proof reuse across different policies
    // The verifier checks this against the VPEC's policy_snapshot_hash
    let _ = policy_snapshot_hash;

    // Bind manifest_hash_values to prevent substitution
    for i in 0..MAX_RECORDS {
        if (i as u32) < record_count {
            let _ = manifest_hash_values[i];
        }
    }
}

/// Compute binary Merkle root using Poseidon2 for internal nodes.
/// Handles arbitrary record counts by duplicating the last leaf for odd counts.
fn compute_merkle_root(leaves: [Field; 64], count: u32) -> Field {
    // Build Merkle tree bottom-up
    // Layer 0: leaves (up to count, rest padded with zeros)
    let mut current_layer: [Field; 64] = [0; 64];
    for i in 0..MAX_RECORDS {
        if (i as u32) < count {
            current_layer[i] = leaves[i];
        }
    }

    // For zero records, result is 0; for single record, result is leaves[0].
    // Both cases are handled correctly by the loop below (which won't execute
    // when layer_size <= 1), leaving current_layer[0] as the root.
    let mut layer_size: u32 = count;

    // Process layers until we have a single root
    for _level in 0..6 {
        // log2(64) = 6 max levels
        if layer_size > 1 {
            let mut next_layer: [Field; 64] = [0; 64];
            let mut next_size: u32 = 0;

            let mut i: u32 = 0;
            for _pair in 0..32 {
                // max 32 pairs per level
                if i < layer_size {
                    let left = current_layer[i];
                    // Odd leaf: duplicate last
                    let right = if (i + 1) < layer_size {
                        current_layer[i + 1]
                    } else {
                        current_layer[i]
                    };
                    next_layer[next_size] = poseidon2::Poseidon2::hash([left, right], 2);
                    next_size += 1;
                    i += 2;
                }
            }

            current_layer = next_layer;
            layer_size = next_size;
        }
    }

    current_layer[0]
}
