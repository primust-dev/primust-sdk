"""Tests for primust_zk_core Poseidon2 implementation."""

from primust_zk_core import (
    BN254_P,
    bytes_to_field_elements,
    poseidon2_commit,
    poseidon2_hash,
)


class TestBytesToFieldElements:
    def test_empty_returns_zero(self):
        assert bytes_to_field_elements(b"") == [0]

    def test_single_byte(self):
        elems = bytes_to_field_elements(b"\x42")
        assert elems == [0x42]

    def test_31_bytes_single_element(self):
        data = bytes(range(31))
        elems = bytes_to_field_elements(data)
        assert len(elems) == 1
        assert elems[0] == int.from_bytes(data, "big")

    def test_32_bytes_two_elements(self):
        data = bytes(range(32))
        elems = bytes_to_field_elements(data)
        assert len(elems) == 2
        assert elems[0] == int.from_bytes(data[:31], "big")
        assert elems[1] == int.from_bytes(data[31:], "big")

    def test_all_elements_less_than_prime(self):
        data = b"\xff" * 62  # 2 chunks of 31 0xff bytes
        elems = bytes_to_field_elements(data)
        for e in elems:
            assert 0 <= e < BN254_P


class TestPoseidon2Hash:
    def test_single_zero(self):
        result = poseidon2_hash([0])
        assert 0 <= result < BN254_P

    def test_deterministic(self):
        a = poseidon2_hash([1, 2, 3])
        b = poseidon2_hash([1, 2, 3])
        assert a == b

    def test_different_inputs_different_outputs(self):
        a = poseidon2_hash([1, 2])
        b = poseidon2_hash([3, 4])
        assert a != b

    def test_result_in_field(self):
        result = poseidon2_hash([BN254_P - 1, 1])
        assert 0 <= result < BN254_P


class TestPoseidon2Commit:
    def test_format(self):
        result = poseidon2_commit(b"hello")
        assert result.startswith("poseidon2:")
        hex_part = result.split(":")[1]
        assert len(hex_part) == 64
        # Should be valid hex
        int(hex_part, 16)

    def test_deterministic(self):
        a = poseidon2_commit(b"test data")
        b = poseidon2_commit(b"test data")
        assert a == b

    def test_different_inputs(self):
        a = poseidon2_commit(b"alpha")
        b = poseidon2_commit(b"beta")
        assert a != b

    def test_empty_input(self):
        result = poseidon2_commit(b"")
        assert result.startswith("poseidon2:")
        assert len(result.split(":")[1]) == 64


class TestCrossPackageConsistency:
    """Verify zk-core matches artifact-core-py Poseidon2 output."""

    def test_matches_artifact_core(self):
        """If artifact-core-py is importable, verify identical results."""
        try:
            from primust_artifact_core.commitment import (
                _bytes_to_field_elements as ac_b2fe,
                _poseidon2_bytes as ac_poseidon2_bytes,
                poseidon2_hash as ac_poseidon2_hash,
            )
        except ImportError:
            # artifact-core-py not installed; skip
            return

        # Field element conversion
        data = b"cross-package consistency check"
        zk_elems = bytes_to_field_elements(data)
        ac_elems = ac_b2fe(data)
        assert zk_elems == ac_elems

        # Raw hash
        inputs = [1, 2, 3]
        assert poseidon2_hash(inputs) == ac_poseidon2_hash(inputs)

        # Full commitment
        assert poseidon2_commit(data) == ac_poseidon2_bytes(data)
