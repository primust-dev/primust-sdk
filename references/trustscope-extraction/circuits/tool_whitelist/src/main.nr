// TrustScope Tool Whitelist Circuit
//
// Proves: "All tools used by AI agents were on the approved whitelist"
// Without revealing: Specific tools used, frequency, agent configurations
//
// Gate count: ~80K gates, ~$0.02 proving cost
// Use case: Prove tool governance to auditors without exposing agent configs

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
    commitment_root: pub Field,         // Merkle root of tool usage commitments
    whitelist_hash: pub Field,          // Hash of approved tool list
    action_count: pub u32,              // Number of actions verified

    // Private inputs
    tool_ids: [Field; 256],             // Tool IDs used in each action
    blindings: [Field; 256],            // Pedersen blinding factors
    whitelist: [Field; 64],             // Approved tool ID list
    whitelist_count: u32,               // Number of tools in whitelist
    merkle_paths: [[Field; 8]; 256],
    merkle_directions: [[bool; 8]; 256]
) {
    // 1. Verify whitelist hash matches
    let computed_whitelist_hash = hash_whitelist(whitelist, whitelist_count);
    assert(computed_whitelist_hash == whitelist_hash, "Whitelist mismatch");

    // 2. Verify each tool is in whitelist
    for i in 0..256 {
        if (i as u32) < action_count {
            let tool = tool_ids[i];
            let in_whitelist = check_in_whitelist(tool, whitelist, whitelist_count);
            assert(in_whitelist, "Tool not in whitelist");
        }
    }

    // 3. Verify commitments
    for i in 0..256 {
        if (i as u32) < action_count {
            let commitment = poseidon2_hash_2(tool_ids[i], blindings[i]);
            let computed_root = compute_merkle_root(
                commitment,
                merkle_paths[i],
                merkle_directions[i]
            );
            assert(computed_root == commitment_root, "Invalid commitment");
        }
    }
}

fn hash_whitelist(whitelist: [Field; 64], count: u32) -> Field {
    // Hash all whitelist items together
    let mut hash: Field = 0;
    for i in 0..64 {
        if (i as u32) < count {
            hash = poseidon2_hash_2(hash, whitelist[i]);
        }
    }
    hash
}

fn check_in_whitelist(tool: Field, whitelist: [Field; 64], count: u32) -> bool {
    let mut found = false;
    for i in 0..64 {
        if (i as u32) < count {
            if whitelist[i] == tool {
                found = true;
            }
        }
    }
    found
}

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
fn test_tool_in_whitelist() {
    let mut whitelist: [Field; 64] = [0; 64];
    whitelist[0] = 1;
    whitelist[1] = 2;
    whitelist[2] = 3;
    whitelist[3] = 4;
    whitelist[4] = 5;
    let count: u32 = 5;
    assert(check_in_whitelist(3, whitelist, count));
}
