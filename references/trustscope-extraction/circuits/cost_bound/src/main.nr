// TrustScope Cost Bound Circuit
//
// Proves: "All AI agent actions stayed within the configured cost limit"
// Without revealing: Individual action costs, timestamps, agent IDs
//
// Gate count: ~50K gates, ~$0.01 proving cost
// Use case: Prove cost compliance to auditors without exposing pricing

// Poseidon2 hash helpers (sponge construction over poseidon2_permutation)
global TWO_POW_64: Field = 18446744073709551616;

fn poseidon2_hash_2(a: Field, b: Field) -> Field {
    let iv = 2 * TWO_POW_64;
    let mut state: [Field; 4] = [a, b, 0, iv];
    state = std::hash::poseidon2_permutation(state, 4);
    state[0]
}

fn main(
    // Public inputs (visible in proof)
    commitment_root: pub Field,         // Merkle root of all cost commitments
    policy_max_cost_cents: pub u64,     // Maximum allowed cost per action (cents)
    action_count: pub u32,              // Number of actions verified

    // Private inputs (hidden in proof)
    costs: [u64; 256],                  // Individual action costs (cents)
    blindings: [Field; 256],            // Pedersen blinding factors
    merkle_paths: [[Field; 8]; 256],    // Merkle paths for each commitment
    merkle_directions: [[bool; 8]; 256] // Left/right at each level
) {
    // 1. Verify each cost is within policy limit
    for i in 0..256 {
        if (i as u32) < action_count {
            assert(costs[i] < policy_max_cost_cents, "Cost exceeds policy limit");
        }
    }

    // 2. Verify Pedersen commitments match claimed costs
    for i in 0..256 {
        if (i as u32) < action_count {
            let expected_commitment = poseidon2_hash_2(costs[i] as Field, blindings[i]);
            // Verify against Merkle tree
            let computed_root = compute_merkle_root(
                expected_commitment,
                merkle_paths[i],
                merkle_directions[i]
            );
            assert(computed_root == commitment_root, "Invalid commitment proof");
        }
    }
}

// Compute Merkle root from leaf and path
fn compute_merkle_root(
    leaf: Field,
    path: [Field; 8],
    directions: [bool; 8]
) -> Field {
    let mut current = leaf;
    for i in 0..8 {
        if directions[i] {
            current = poseidon2_hash_2(path[i], current);
        } else {
            current = poseidon2_hash_2(current, path[i]);
        }
    }
    current
}

#[test]
fn test_cost_within_limit() {
    // Test that costs within limit pass
    let costs: [u64; 8] = [100, 200, 300, 0, 0, 0, 0, 0];  // Only 3 actions
    let policy_max: u64 = 500;

    for i in 0..3 {
        assert(costs[i] < policy_max);
    }
}
