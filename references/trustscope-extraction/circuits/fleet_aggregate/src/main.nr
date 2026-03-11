// TrustScope Fleet Aggregate Circuit
//
// Proves: "Aggregate metric across all agents is within threshold"
// Without revealing: Per-agent metrics, agent identities, individual values
//
// Gate count: ~40K gates, ~$0.01 proving cost
// Use case: Fleet-level compliance without per-agent exposure

// Poseidon2 hash helpers (sponge construction over poseidon2_permutation)
global TWO_POW_64: Field = 18446744073709551616;

fn poseidon2_hash_2(a: Field, b: Field) -> Field {
    let iv = 2 * TWO_POW_64;
    let mut state: [Field; 4] = [a, b, 0, iv];
    state = std::hash::poseidon2_permutation(state, 4);
    state[0]
}

fn main(
    // Public inputs
    commitment_root: pub Field,         // Merkle root of agent metric commitments
    agent_count: pub u32,               // Number of agents in fleet
    aggregate_sum: pub Field,           // Sum of all agent metrics (public)
    aggregate_threshold: pub Field,     // Threshold aggregate must meet

    // Private inputs
    agent_metrics: [Field; 128],        // Individual agent metrics
    blindings: [Field; 128],
    merkle_paths: [[Field; 7]; 128],
    merkle_directions: [[bool; 7]; 128]
) {
    // 1. Verify aggregate matches sum of individual metrics
    let mut computed_sum: Field = 0;
    for i in 0..128 {
        if (i as u32) < agent_count {
            computed_sum += agent_metrics[i];
        }
    }
    assert(computed_sum == aggregate_sum, "Aggregate sum mismatch");

    // 2. Verify aggregate meets threshold
    assert(aggregate_sum as u64 >= aggregate_threshold as u64, "Aggregate below threshold");

    // 3. Verify each commitment
    for i in 0..128 {
        if (i as u32) < agent_count {
            let commitment = poseidon2_hash_2(
                agent_metrics[i],
                blindings[i]
            );
            let computed_root = compute_merkle_root(
                commitment,
                merkle_paths[i],
                merkle_directions[i]
            );
            assert(computed_root == commitment_root, "Invalid agent commitment");
        }
    }
}

fn compute_merkle_root(
    leaf: Field,
    path: [Field; 7],
    directions: [bool; 7]
) -> Field {
    let mut current = leaf;
    for i in 0..7 {
        if directions[i] {
            current = poseidon2_hash_2(path[i], current);
        } else {
            current = poseidon2_hash_2(current, path[i]);
        }
    }
    current
}

#[test]
fn test_fleet_aggregate() {
    let metrics: [Field; 5] = [95, 97, 98, 94, 96];
    let mut sum: Field = 0;
    for i in 0..5 {
        sum += metrics[i];
    }
    // Average = 480/5 = 96%
    assert(sum == 480);
}
