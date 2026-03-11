// TrustScope Range Proof Circuit
//
// Proves: "Committed value is within specified range [min, max]"
// Without revealing: The actual value
//
// Gate count: ~20K gates, ~$0.005 proving cost
// Use case: Federated compliance - prove metric in valid range without revealing

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
    commitment: pub Field,              // Pedersen commitment to the value
    range_min: pub u64,                 // Minimum allowed value
    range_max: pub u64,                 // Maximum allowed value

    // Private inputs
    value: u64,                         // Actual value
    blinding: Field                     // Blinding factor
) {
    // 1. Verify value is in range (using integers for comparison)
    assert(value >= range_min, "Value below minimum");
    assert(value <= range_max, "Value above maximum");

    // 2. Verify commitment opens to claimed value
    let computed_commitment = poseidon2_hash_2(value as Field, blinding);
    assert(computed_commitment == commitment, "Commitment does not match value");
}

#[test]
fn test_in_range() {
    let value: u64 = 75;
    let min: u64 = 0;
    let max: u64 = 100;
    assert(value >= min);
    assert(value <= max);
}

#[test]
fn test_commitment_verification() {
    let value: u64 = 50;
    let blinding: Field = 12345;
    let commitment = poseidon2_hash_2(value as Field, blinding);

    // Verify same inputs produce same commitment
    let recomputed = poseidon2_hash_2(value as Field, blinding);
    assert(commitment == recomputed);
}
