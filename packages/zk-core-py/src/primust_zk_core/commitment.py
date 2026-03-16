"""
Primust ZK Core — Poseidon2 Commitment (Python)

Provides ``poseidon2_commit(data)`` which hashes arbitrary bytes using the
Poseidon2 sponge over BN254 field elements.  The result is returned in
the canonical ``"poseidon2:{064x}"`` format used throughout Primust.

The hashing strategy matches the TypeScript ``@primust/artifact-core``
commitment layer:

1. Split bytes into 31-byte big-endian chunks -> field elements.
2. Fold pairs through Poseidon2:
      state = hash([(state + left) % p, right])
   where *left* and *right* are successive field elements (right defaults
   to 0 when the element count is odd).
3. Format as ``poseidon2:<64-hex-chars>``.
"""

from .poseidon2 import BN254_P, bytes_to_field_elements, poseidon2_hash


def poseidon2_commit(data: bytes) -> str:
    """
    Compute a Poseidon2 commitment over arbitrary bytes.

    Args:
        data: Raw content bytes.

    Returns:
        Commitment string in ``"poseidon2:{hex}"`` format (64 hex chars).
    """
    elements = bytes_to_field_elements(data)

    state = 0
    for i in range(0, len(elements), 2):
        left = elements[i]
        right = elements[i + 1] if i + 1 < len(elements) else 0
        state = poseidon2_hash([(state + left) % BN254_P, right])

    return "poseidon2:" + format(state, "064x")
