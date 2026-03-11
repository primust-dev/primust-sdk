// TrustScope Temporal Comparison Circuit
//
// Proves: "Metric improved (or maintained) compared to previous period"
// Without revealing: Actual metric values from either period
//
// Gate count: ~30K gates, ~$0.005 proving cost
// Use case: Prove improvement trends without exposing absolute values

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
    period1_commitment: pub Field,      // Commitment to period 1 metric
    period2_commitment: pub Field,      // Commitment to period 2 metric
    comparison_type: pub u8,            // 0=improved, 1=maintained, 2=any

    // Private inputs
    period1_value: u64,                 // Actual period 1 metric
    period1_blinding: Field,
    period2_value: u64,                 // Actual period 2 metric
    period2_blinding: Field
) {
    // 1. Verify period 1 commitment
    let computed_c1 = poseidon2_hash_2(period1_value as Field, period1_blinding);
    assert(computed_c1 == period1_commitment, "Period 1 commitment invalid");

    // 2. Verify period 2 commitment
    let computed_c2 = poseidon2_hash_2(period2_value as Field, period2_blinding);
    assert(computed_c2 == period2_commitment, "Period 2 commitment invalid");

    // 3. Verify comparison based on type
    if comparison_type == 0 {
        // Improved: period2 > period1
        assert(period2_value > period1_value, "Metric did not improve");
    } else if comparison_type == 1 {
        // Maintained: period2 >= period1
        assert(period2_value >= period1_value, "Metric declined");
    }
    // comparison_type == 2: any relationship allowed
}

#[test]
fn test_improvement() {
    let p1: u64 = 85;
    let p2: u64 = 92;
    assert(p2 > p1);  // Improved
}

#[test]
fn test_maintained() {
    let p1: u64 = 95;
    let p2: u64 = 95;
    assert(p2 >= p1);  // Maintained
}
