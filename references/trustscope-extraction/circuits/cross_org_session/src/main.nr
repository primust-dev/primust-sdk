// Cross-Organization Session Proof Circuit
//
// Proves compliance for A2A (Agent-to-Agent) sessions spanning
// two different TrustScope customer organizations.
//
// When two AI agents from different organizations interact,
// this circuit proves that BOTH organizations maintained
// compliance on their respective sides of the conversation.
//
// Public Inputs:
// - session_id_hash: Hash of the A2A session identifier
// - org_a_commitment: Pedersen commitment to Org A's compliance
// - org_b_commitment: Pedersen commitment to Org B's compliance
// - min_compliance_score: Minimum required score for each org
//
// Private Witnesses (per org):
// - compliance_score: Each org's actual compliance score
// - trace_count: Number of traces in the session
// - policy_enforcement_rate: Rate of policy enforcement
// - detection_event_count: Number of detection events
// - blindings: Blinding factors for commitments
//
// Proves:
// 1. Both orgs had compliance score >= minimum
// 2. Both orgs' commitments are properly formed
// 3. Session ID hash matches the committed session

// Maximum traces per org side in a session
global MAX_TRACES_PER_ORG: u32 = 128;

// Poseidon2 hash helpers (sponge construction over poseidon2_permutation)
global TWO_POW_64: Field = 18446744073709551616;

fn poseidon2_hash_2(a: Field, b: Field) -> Field {
    let iv = 2 * TWO_POW_64;
    let mut state: [Field; 4] = [a, b, 0, iv];
    state = std::hash::poseidon2_permutation(state, 4);
    state[0]
}

fn poseidon2_hash_4(a: Field, b: Field, c: Field, d: Field) -> Field {
    let iv = 4 * TWO_POW_64;
    let mut state: [Field; 4] = [a, b, c, iv];
    state = std::hash::poseidon2_permutation(state, 4);
    state[0] += d;
    state = std::hash::poseidon2_permutation(state, 4);
    state[0]
}

fn main(
    // Public inputs
    session_id_hash: pub Field,
    org_a_commitment: pub Field,
    org_b_commitment: pub Field,
    min_compliance_score: pub u64,    // in basis points (e.g., 7500 = 75%)

    // Org A private witnesses
    org_a_score: u64,                 // Actual compliance score [0-10000 bps]
    org_a_trace_count: u32,
    org_a_enforcement_rate: u64,      // [0-10000 bps]
    org_a_detection_events: u32,
    org_a_blinding: Field,

    // Org B private witnesses
    org_b_score: u64,
    org_b_trace_count: u32,
    org_b_enforcement_rate: u64,
    org_b_detection_events: u32,
    org_b_blinding: Field,

    // Session data
    session_trace_hashes: [Field; 256], // Interleaved A/B traces
    session_trace_count: u32,
) {
    // 1. Verify Org A compliance
    assert(org_a_score >= min_compliance_score);

    // 2. Verify Org B compliance
    assert(org_b_score >= min_compliance_score);

    // 3. Verify Org A commitment
    // Commitment = H(score || trace_count || enforcement_rate || blinding)
    let org_a_computed = poseidon2_hash_4(
        org_a_score as Field,
        org_a_trace_count as Field,
        org_a_enforcement_rate as Field,
        org_a_blinding
    );
    assert(org_a_computed == org_a_commitment);

    // 4. Verify Org B commitment
    let org_b_computed = poseidon2_hash_4(
        org_b_score as Field,
        org_b_trace_count as Field,
        org_b_enforcement_rate as Field,
        org_b_blinding
    );
    assert(org_b_computed == org_b_commitment);

    // 5. Verify session trace count is reasonable
    let tc = session_trace_count;
    assert(tc <= 256);
    assert(tc >= 2);  // At least one trace from each org

    // 6. Verify session ID hash matches trace chain
    let mut session_hash: Field = 0;
    for i in 0..256 {
        if (i as u32) < tc {
            session_hash = poseidon2_hash_2(session_hash, session_trace_hashes[i]);
        }
    }
    assert(session_hash == session_id_hash);

    // 7. Verify trace counts are consistent
    // Total traces should equal org_a_trace_count + org_b_trace_count
    let expected_total = org_a_trace_count + org_b_trace_count;
    assert(expected_total == tc);

    // 8. Enforce minimum enforcement rate (optional check)
    // Both orgs should have at least some policy enforcement
    assert(org_a_enforcement_rate >= 5000);  // At least 50%
    assert(org_b_enforcement_rate >= 5000);
}

// Test function
#[test]
fn test_cross_org_basic() {
    // Set up test data
    let org_a_score: u64 = 8000;  // 80%
    let org_a_trace_count: u32 = 5;
    let org_a_enforcement_rate: u64 = 9000;  // 90%
    let org_a_detection_events: u32 = 0;
    let org_a_blinding: Field = 12345;

    let org_b_score: u64 = 8500;  // 85%
    let org_b_trace_count: u32 = 5;
    let org_b_enforcement_rate: u64 = 9500;  // 95%
    let org_b_detection_events: u32 = 1;
    let org_b_blinding: Field = 67890;

    // Compute commitments
    let org_a_commitment = poseidon2_hash_4(
        org_a_score as Field,
        org_a_trace_count as Field,
        org_a_enforcement_rate as Field,
        org_a_blinding
    );

    let org_b_commitment = poseidon2_hash_4(
        org_b_score as Field,
        org_b_trace_count as Field,
        org_b_enforcement_rate as Field,
        org_b_blinding
    );

    // Set up session traces
    let mut session_trace_hashes: [Field; 256] = [0; 256];
    for i in 0..10 {
        session_trace_hashes[i] = i as Field + 1;
    }

    // Compute session ID hash
    let mut session_id_hash: Field = 0;
    for i in 0..10 {
        session_id_hash = poseidon2_hash_2(session_id_hash, session_trace_hashes[i]);
    }

    // Run the proof
    main(
        session_id_hash,
        org_a_commitment,
        org_b_commitment,
        7500,  // 75% minimum

        org_a_score,
        org_a_trace_count,
        org_a_enforcement_rate,
        org_a_detection_events,
        org_a_blinding,

        org_b_score,
        org_b_trace_count,
        org_b_enforcement_rate,
        org_b_detection_events,
        org_b_blinding,

        session_trace_hashes,
        10,  // session_trace_count
    );
}
