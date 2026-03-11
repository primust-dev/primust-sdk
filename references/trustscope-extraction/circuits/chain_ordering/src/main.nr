// TrustScope Chain Ordering Circuit
//
// Proves: "The sequence of governance checks in a pipeline run is monotonically
//          ordered (no gaps, no skips, no reordering) and the hash chain closes
//          correctly to a known chain_head."
// Without revealing: Step content, individual hashes, action data.
//
// Use case: PEC pipeline credentials -- prove no steps were removed or reordered.

// Maximum steps in a pipeline
global MAX_STEPS: u32 = 256;

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
    chain_head: pub Field,       // Final hash of the complete chain
    chain_length: pub u32,       // Number of steps in the chain

    // Private inputs
    step_hashes: [Field; 256],        // Hash of each step's action data
    sequence_numbers: [u32; 256],     // Sequence number for each step (0-indexed)
) {
    // Validate chain length
    assert(chain_length >= 1, "Chain must have at least one step");
    assert(chain_length <= MAX_STEPS, "Chain length exceeds maximum");

    // 1. First sequence number must be 0
    assert(sequence_numbers[0] == 0, "Chain must start at sequence 0");

    let cl = chain_length;

    // 2. Verify monotonically increasing sequence (no gaps)
    for i in 1..MAX_STEPS {
        if (i as u32) < cl {
            assert(
                sequence_numbers[i] == sequence_numbers[i - 1] + 1,
                "Sequence gap or reordering detected"
            );
        }
    }

    // 3. Compute running hash chain
    let mut running_hash: Field = step_hashes[0];
    for i in 1..MAX_STEPS {
        if (i as u32) < cl {
            running_hash = poseidon2_hash_2(running_hash, step_hashes[i]);
        }
    }

    // 4. Verify chain head matches
    assert(running_hash == chain_head, "Chain head mismatch");
}

// --- Inline Tests ---

#[test]
fn test_3_steps_correct_sequence() {
    // Chain of 3 steps, correct sequence 0,1,2, correct chain_head
    let mut step_hashes: [Field; 256] = [0; 256];
    let mut sequence_numbers: [u32; 256] = [0; 256];

    step_hashes[0] = 111;
    step_hashes[1] = 222;
    step_hashes[2] = 333;

    sequence_numbers[0] = 0;
    sequence_numbers[1] = 1;
    sequence_numbers[2] = 2;

    // Compute expected chain_head
    let h01 = poseidon2_hash_2(111, 222);
    let chain_head = poseidon2_hash_2(h01, 333);

    main(
        chain_head,
        3,
        step_hashes,
        sequence_numbers,
    );
}

#[test(should_fail)]
fn test_3_steps_gap_in_sequence() {
    // Sequence 0, 2, 3 -- gap at position 1 -- should FAIL
    let mut step_hashes: [Field; 256] = [0; 256];
    let mut sequence_numbers: [u32; 256] = [0; 256];

    step_hashes[0] = 111;
    step_hashes[1] = 222;
    step_hashes[2] = 333;

    sequence_numbers[0] = 0;
    sequence_numbers[1] = 2; // Gap! Should be 1
    sequence_numbers[2] = 3;

    let h01 = poseidon2_hash_2(111, 222);
    let chain_head = poseidon2_hash_2(h01, 333);

    main(
        chain_head,
        3,
        step_hashes,
        sequence_numbers,
    );
}

#[test(should_fail)]
fn test_3_steps_wrong_chain_head() {
    // Correct sequence but wrong chain_head -- should FAIL
    let mut step_hashes: [Field; 256] = [0; 256];
    let mut sequence_numbers: [u32; 256] = [0; 256];

    step_hashes[0] = 111;
    step_hashes[1] = 222;
    step_hashes[2] = 333;

    sequence_numbers[0] = 0;
    sequence_numbers[1] = 1;
    sequence_numbers[2] = 2;

    main(
        99999, // Wrong chain head
        3,
        step_hashes,
        sequence_numbers,
    );
}

#[test]
fn test_single_step_chain() {
    // Chain of 1 step -- chain_head is just the step hash
    let mut step_hashes: [Field; 256] = [0; 256];
    let mut sequence_numbers: [u32; 256] = [0; 256];

    step_hashes[0] = 42;
    sequence_numbers[0] = 0;

    main(
        42, // Single step: chain_head == step_hash[0]
        1,
        step_hashes,
        sequence_numbers,
    );
}
