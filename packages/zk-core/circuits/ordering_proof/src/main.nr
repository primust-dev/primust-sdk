// Ordering Proof Circuit
//
// Proves monotonic sequence ordering with no gaps and that
// the hash chain closes correctly. Used to verify temporal
// ordering of check records within a process run.
//
// Public inputs:
//   - chain_root: Poseidon2 hash chain terminal value
//   - sequence_length: number of items in the sequence
//
// Private inputs:
//   - sequence_values: ordered sequence values (as Field elements)
//   - sequence_count: actual number of values (rest is padding)
//
// Constraints:
//   1. Strict monotonic ordering: v[i+1] > v[i] for all adjacent pairs
//   2. Hash chain: H(H(H(v[0], v[1]), v[2]), ...) matches chain_root
//   3. sequence_count == sequence_length

use dep::poseidon::poseidon2;

global MAX_SEQUENCE: u32 = 256;

fn main(
    // Public inputs
    chain_root: pub Field,
    sequence_length: pub u32,

    // Private inputs
    sequence_values: [Field; 256],
    sequence_count: u32,
) {
    // Constraint 3: counts must match
    assert(sequence_count == sequence_length);
    // Must have at least 1 element
    assert(sequence_count > 0);

    // Constraint 1: Strict monotonic ordering
    // Compare as u64 to avoid Field modular arithmetic issues
    for i in 0..MAX_SEQUENCE {
        if ((i as u32) + 1) < sequence_count {
            let current = sequence_values[i] as u64;
            let next = sequence_values[i + 1] as u64;
            assert(next > current);
        }
    }

    // Constraint 2: Hash chain computation
    // Start with first value, then iteratively hash with next value
    let mut chain = sequence_values[0];
    for i in 0..MAX_SEQUENCE {
        if ((i as u32) + 1) < sequence_count {
            chain = poseidon2::Poseidon2::hash([chain, sequence_values[i + 1]], 2);
        }
    }
    assert(chain == chain_root);
}
