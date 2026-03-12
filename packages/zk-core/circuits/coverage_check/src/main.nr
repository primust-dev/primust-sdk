// Coverage Check Circuit
//
// Proves every action had a corresponding check record and that
// coverage meets a minimum threshold. Prevents issuance of VPECs
// with incomplete governance coverage.
//
// Public inputs:
//   - commitment_root: Poseidon2 Merkle root over action hashes
//   - total_actions: number of actions in the run
//   - covered_count: number of actions with check records
//   - threshold_pct: minimum coverage percentage (0-100)
//
// Private inputs:
//   - action_hashes: per-action commitment hashes
//   - has_record: 1 if action has a check record, 0 if not
//   - record_count: actual number of actions (rest is padding)
//
// Constraints:
//   1. Merkle root recomputation matches commitment_root
//   2. Count of has_record == 1 matches covered_count
//   3. covered_count * 100 >= threshold_pct * total_actions

use dep::poseidon::poseidon2;

global MAX_ACTIONS: u32 = 256;

fn main(
    // Public inputs
    commitment_root: pub Field,
    total_actions: pub u32,
    covered_count: pub u32,
    threshold_pct: pub u32,

    // Private inputs
    action_hashes: [Field; 256],
    has_record: [u8; 256],
    record_count: u32,
) {
    // record_count must match total_actions
    assert(record_count == total_actions);

    // Constraint 1: Recompute Merkle root from action_hashes
    let computed_root = compute_merkle_root(action_hashes, record_count);
    assert(computed_root == commitment_root);

    // Constraint 2: Count covered actions and verify
    let mut count: u32 = 0;
    for i in 0..MAX_ACTIONS {
        if (i as u32) < record_count {
            // has_record must be 0 or 1
            assert((has_record[i] == 0) | (has_record[i] == 1));
            if has_record[i] == 1 {
                count += 1;
            }
        }
    }
    assert(count == covered_count);

    // Constraint 3: Coverage meets threshold
    // covered_count * 100 >= threshold_pct * total_actions
    assert(covered_count * 100 >= threshold_pct * total_actions);
}

/// Compute binary Merkle root using Poseidon2 for internal nodes.
/// Bottom-up construction, handles arbitrary counts by duplicating
/// the last leaf for odd counts.
fn compute_merkle_root(leaves: [Field; 256], count: u32) -> Field {
    let mut current_layer: [Field; 256] = [0; 256];
    for i in 0..MAX_ACTIONS {
        if (i as u32) < count {
            current_layer[i] = leaves[i];
        }
    }

    let mut layer_size: u32 = count;

    // log2(256) = 8, +1 for safety = 9 levels
    for _level in 0..9 {
        if layer_size > 1 {
            let mut next_layer: [Field; 256] = [0; 256];
            let mut next_size: u32 = 0;

            let mut i: u32 = 0;
            for _pair in 0..128 {
                if i < layer_size {
                    let left = current_layer[i];
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
