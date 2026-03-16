"""
primust-zk-core — Poseidon2 hashing and commitments over BN254 (Python)

Public API
----------
- ``poseidon2_hash(inputs)``  — hash a list of field elements via Poseidon2 sponge
- ``bytes_to_field_elements(data)`` — split bytes into 31-byte big-endian BN254 field elements
- ``poseidon2_commit(data)`` — hash arbitrary bytes, returning ``"poseidon2:<hex>"``
- ``BN254_P`` — the BN254 scalar field prime
"""

from .poseidon2 import BN254_P, bytes_to_field_elements, poseidon2_hash
from .commitment import poseidon2_commit

__all__ = [
    "BN254_P",
    "bytes_to_field_elements",
    "poseidon2_hash",
    "poseidon2_commit",
]
