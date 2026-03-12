// Threshold Application Circuit
//
// Proves score >= threshold IFF decision == pass for every record.
// Prevents score/decision inconsistency -- a record cannot claim
// "pass" if its score is below threshold, and cannot claim "fail"
// if its score meets threshold.
//
// Public inputs:
//   - decision_hash: Poseidon2 commitment binding all inputs
//   - pass_count: number of passing decisions
//
// Private inputs:
//   - scores: raw score per record (as Field, compared as u64)
//   - thresholds: threshold per record (as Field, compared as u64)
//   - decisions: 1=pass, 0=fail per record
//   - blinding: blinding factor for commitment
//   - record_count: actual number of records
//
// Constraints:
//   1. For each record: decision==1 iff score >= threshold
//   2. Count of decisions==1 matches pass_count
//   3. decision_hash binds all inputs via Poseidon2

use dep::poseidon::poseidon2;

global MAX_RECORDS: u32 = 256;

fn main(
    // Public inputs
    decision_hash: pub Field,
    pass_count: pub u32,

    // Private inputs
    scores: [Field; 256],
    thresholds: [Field; 256],
    decisions: [u8; 256],
    blinding: Field,
    record_count: u32,
) {
    assert(record_count > 0);

    // Constraint 1 + 2: Verify each decision and count passes
    let mut counted_passes: u32 = 0;
    for i in 0..MAX_RECORDS {
        if (i as u32) < record_count {
            let score = scores[i] as u64;
            let threshold = thresholds[i] as u64;
            let decision = decisions[i];

            // Decision must be 0 or 1
            assert((decision == 0) | (decision == 1));

            if decision == 1 {
                // Pass: score must be >= threshold
                assert(score >= threshold);
                counted_passes += 1;
            }
            if decision == 0 {
                // Fail: score must be < threshold
                assert(score < threshold);
            }
        }
    }
    assert(counted_passes == pass_count);

    // Constraint 3: Compute decision_hash commitment
    // Hash structure: H(scores[0..N] || thresholds[0..N] || decisions[0..N] || blinding)
    // We chain hash in groups to avoid exceeding Poseidon2 input limits.
    // Chain: start with blinding, then fold in each record's (score, threshold, decision).
    let mut commitment = blinding;
    for i in 0..MAX_RECORDS {
        if (i as u32) < record_count {
            commitment = poseidon2::Poseidon2::hash(
                [commitment, scores[i], thresholds[i], decisions[i] as Field],
                4,
            );
        }
    }
    assert(commitment == decision_hash);
}
