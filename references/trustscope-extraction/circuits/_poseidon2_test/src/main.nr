global TWO_POW_64: Field = 18446744073709551616;

fn poseidon2_hash_2(a: Field, b: Field) -> Field {
    let iv = 2 * TWO_POW_64;
    let mut state: [Field; 4] = [a, b, 0, iv];
    state = std::hash::poseidon2_permutation(state, 4);
    state[0]
}

fn main() -> pub Field {
    poseidon2_hash_2(12345, 67890)
}
