// Policy Config Integrity Circuit
//
// Proves the same policy snapshot hash was used across all traces
// in a process run. Prevents mid-run policy substitution where
// different traces could be evaluated against different policies.
//
// Public inputs:
//   - policy_hash: expected policy snapshot hash
//   - trace_count: number of traces in the run
//
// Private inputs:
//   - trace_policy_hashes: policy hash recorded per trace
//   - actual_count: actual number of traces
//
// Constraints:
//   1. All trace_policy_hashes[i] == policy_hash for i < actual_count
//   2. actual_count == trace_count
//   3. actual_count > 0 (non-vacuous proof)

fn main(
    // Public inputs
    policy_hash: pub Field,
    trace_count: pub u32,

    // Private inputs
    trace_policy_hashes: [Field; 256],
    actual_count: u32,
) {
    // Constraint 2: counts must match
    assert(actual_count == trace_count);

    // Constraint 3: non-vacuous -- at least one trace
    assert(actual_count > 0);

    // Constraint 1: every trace used the same policy
    for i in 0..256 {
        if (i as u32) < actual_count {
            assert(trace_policy_hashes[i] == policy_hash);
        }
    }
}
