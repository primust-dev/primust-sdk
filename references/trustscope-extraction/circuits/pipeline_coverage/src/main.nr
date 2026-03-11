// TrustScope Pipeline Coverage Circuit
//
// Proves: "Every action in an agent pipeline run had at least one governance
//          check executed, with coverage meeting minimum threshold."
// Without revealing: Check details, action content, blinding factors.
//
// Use case: PEC pipeline credentials -- prove end-to-end governance coverage.

// Max actions/checks in a single pipeline run
global MAX_ACTIONS: u32 = 256;
// Merkle tree depth (2^8 = 256 leaves)
// Poseidon2 hash helpers (sponge construction over poseidon2_permutation)
global TWO_POW_64: Field = 18446744073709551616;

fn poseidon2_hash_2(a: Field, b: Field) -> Field {
    let iv = 2 * TWO_POW_64;
    let mut state: [Field; 4] = [a, b, 0, iv];
    state = std::hash::poseidon2_permutation(state, 4);
    state[0]
}

fn compute_merkle_root(
    leaf: Field,
    path: [Field; 8],
    index: u32
) -> Field {
    let mut current = leaf;
    for i in 0..8 {
        let bit = (index >> (i as u32)) & 1;
        if bit == 1 {
            current = poseidon2_hash_2(path[i], current);
        } else {
            current = poseidon2_hash_2(current, path[i]);
        }
    }
    current
}

fn main(
    // Public inputs
    commitment_root: pub Field,        // Poseidon2 Merkle root of all check commitments
    action_count: pub u32,             // Total actions in the run
    governed_count: pub u32,           // Actions with at least one check
    coverage_pct_x100: pub u32,        // (governed_count / action_count) * 10000
    coverage_threshold: pub u32,       // Minimum acceptable coverage_pct_x100

    // Private inputs
    check_commitments: [Field; 256],       // Poseidon2 commitment per check
    action_to_check_index: [u32; 256],     // For action i, which check governed it
    blindings: [Field; 256],               // Per-check random blinding factor
    merkle_paths: [[Field; 8]; 256],       // Depth-8 Merkle inclusion paths
    merkle_indices: [u32; 256],            // Leaf index in Merkle tree per check
) {
    // Validate counts
    assert(action_count <= MAX_ACTIONS, "Action count exceeds maximum");
    assert(action_count >= 1, "Must have at least one action");
    assert(governed_count <= action_count, "Governed count exceeds action count");

    // Verify coverage percentage calculation
    // coverage_pct_x100 == (governed_count * 10000) / action_count
    let computed_pct = (governed_count * 10000) / action_count;
    assert(computed_pct == coverage_pct_x100, "Coverage percentage mismatch");

    // Verify coverage meets threshold
    assert(coverage_pct_x100 >= coverage_threshold, "Coverage below threshold");

    // Verify each action has a valid governance check with Merkle inclusion
    let ac = action_count;
    for i in 0..MAX_ACTIONS {
        if (i as u32) < ac {
            let check_idx = action_to_check_index[i];

            // Check commitment must be non-zero (check was executed)
            assert(check_commitments[check_idx] != 0, "Check commitment is zero");

            // Compute leaf from check commitment and blinding
            let leaf = poseidon2_hash_2(
                check_commitments[check_idx],
                blindings[check_idx]
            );

            // Verify Merkle inclusion
            let computed_root = compute_merkle_root(
                leaf,
                merkle_paths[check_idx],
                merkle_indices[check_idx]
            );
            assert(computed_root == commitment_root, "Merkle inclusion failed");
        }
    }
}

// --- Helper to build a minimal valid Merkle tree for tests ---

// Build a depth-8 Merkle tree from a single leaf and return (root, path, index).
// For tests: place leaf at index 0, fill siblings with zeros.
// (helper removed -- tree building done inline in tests)

// --- Inline Tests ---

#[test]
fn test_4_actions_100pct_coverage() {
    // 4 actions, all governed, 100% coverage, threshold 9000
    let mut check_commitments: [Field; 256] = [0; 256];
    let mut blindings: [Field; 256] = [0; 256];
    let mut action_to_check_index: [u32; 256] = [0; 256];
    let mut merkle_paths: [[Field; 8]; 256] = [[0; 8]; 256];
    let mut merkle_indices: [u32; 256] = [0; 256];

    // Set up 4 checks with distinct commitments
    check_commitments[0] = 100;
    check_commitments[1] = 200;
    check_commitments[2] = 300;
    check_commitments[3] = 400;
    blindings[0] = 10;
    blindings[1] = 20;
    blindings[2] = 30;
    blindings[3] = 40;

    // Each action maps to its own check
    action_to_check_index[0] = 0;
    action_to_check_index[1] = 1;
    action_to_check_index[2] = 2;
    action_to_check_index[3] = 3;

    // Build leaves
    let leaf0 = poseidon2_hash_2(100, 10);
    let leaf1 = poseidon2_hash_2(200, 20);
    let leaf2 = poseidon2_hash_2(300, 30);
    let leaf3 = poseidon2_hash_2(400, 40);

    // Build Merkle tree bottom-up for 4 leaves (padded to 256 with 0s)
    // Level 0 pairs: (leaf0, leaf1), (leaf2, leaf3), (0,0), ...
    let n01 = poseidon2_hash_2(leaf0, leaf1);
    let n23 = poseidon2_hash_2(leaf2, leaf3);
    let z = poseidon2_hash_2(0, 0); // zero pair hash

    // Level 1: (n01, n23), (z, z), ...
    let n0123 = poseidon2_hash_2(n01, n23);
    let zz = poseidon2_hash_2(z, z);

    // Level 2: (n0123, zz), (zz, zz), ...
    let n_l2 = poseidon2_hash_2(n0123, zz);
    let zz2 = poseidon2_hash_2(zz, zz);

    // Level 3-7: chain up with zero pairs
    let n_l3 = poseidon2_hash_2(n_l2, zz2);
    let zz3 = poseidon2_hash_2(zz2, zz2);
    let n_l4 = poseidon2_hash_2(n_l3, zz3);
    let zz4 = poseidon2_hash_2(zz3, zz3);
    let n_l5 = poseidon2_hash_2(n_l4, zz4);
    let zz5 = poseidon2_hash_2(zz4, zz4);
    let n_l6 = poseidon2_hash_2(n_l5, zz5);
    let zz6 = poseidon2_hash_2(zz5, zz5);
    let root = poseidon2_hash_2(n_l6, zz6);

    // Merkle path for leaf0 (index 0): sibling=leaf1, then n23, then zz, then zz2...
    merkle_paths[0] = [leaf1, n23, zz, zz2, zz3, zz4, zz5, zz6];
    merkle_indices[0] = 0; // all bits 0 = leftmost

    // Merkle path for leaf1 (index 1): sibling=leaf0, then n23, then zz...
    merkle_paths[1] = [leaf0, n23, zz, zz2, zz3, zz4, zz5, zz6];
    merkle_indices[1] = 1; // bit 0 = 1

    // Merkle path for leaf2 (index 2): sibling=leaf3, then n01, then zz...
    merkle_paths[2] = [leaf3, n01, zz, zz2, zz3, zz4, zz5, zz6];
    merkle_indices[2] = 2; // bit 1 = 1

    // Merkle path for leaf3 (index 3): sibling=leaf2, then n01, then zz...
    merkle_paths[3] = [leaf2, n01, zz, zz2, zz3, zz4, zz5, zz6];
    merkle_indices[3] = 3; // bits 0,1 = 1

    main(
        root,
        4,    // action_count
        4,    // governed_count
        10000, // 100.00%
        9000,  // threshold 90%
        check_commitments,
        action_to_check_index,
        blindings,
        merkle_paths,
        merkle_indices,
    );
}

#[test(should_fail)]
fn test_4_actions_75pct_below_threshold() {
    // 4 actions, 3 governed, 75% coverage, threshold 9000 -- should FAIL
    // coverage_pct_x100 = 7500 < 9000
    let check_commitments: [Field; 256] = [1; 256]; // all non-zero
    let action_to_check_index: [u32; 256] = [0; 256];
    let blindings: [Field; 256] = [1; 256];
    let merkle_paths: [[Field; 8]; 256] = [[0; 8]; 256];
    let merkle_indices: [u32; 256] = [0; 256];

    main(
        0, // dummy root (will fail on coverage check first)
        4,
        3,
        7500,
        9000, // threshold > coverage -> fails
        check_commitments,
        action_to_check_index,
        blindings,
        merkle_paths,
        merkle_indices,
    );
}

#[test(should_fail)]
fn test_zero_commitment_fails() {
    // A check slot has zero commitment -> should FAIL constraint 1b
    let mut check_commitments: [Field; 256] = [0; 256];
    // Leave check_commitments[0] = 0 (zero!)
    let action_to_check_index: [u32; 256] = [0; 256]; // action 0 maps to check 0
    let blindings: [Field; 256] = [1; 256];
    let merkle_paths: [[Field; 8]; 256] = [[0; 8]; 256];
    let merkle_indices: [u32; 256] = [0; 256];

    main(
        0,
        1, // 1 action
        1,
        10000,
        10000,
        check_commitments,
        action_to_check_index,
        blindings,
        merkle_paths,
        merkle_indices,
    );
}
