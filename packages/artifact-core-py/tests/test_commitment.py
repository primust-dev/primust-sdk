"""
Tests for Primust commitment layer — P6-A Python mirror.
SHA-256 default, Poseidon2 opt-in via PRIMUST_COMMITMENT_ALGORITHM=poseidon2.
"""

import json
import os
from pathlib import Path

import pytest

from primust_artifact_core.commitment import (
    ZK_IS_BLOCKING,
    build_commitment_root,
    commit,
    commit_output,
    select_proof_level,
)

VECTORS_PATH = Path(__file__).resolve().parents[3] / "schemas" / "golden" / "commitment_vectors.json"


def load_vectors():
    with open(VECTORS_PATH) as f:
        return json.load(f)


# ── Tests ──


class TestCommitment:
    def test_poseidon2_deterministic(self):
        """poseidon2 is deterministic — same input → same hash."""
        data = b"hello primust"
        h1, _ = commit(data, "poseidon2")
        h2, _ = commit(data, "poseidon2")
        assert h1 == h2
        assert h1.startswith("poseidon2:")

    def test_sha256_deterministic(self):
        """sha256 is deterministic — same input → same hash."""
        data = b"hello primust"
        h1, _ = commit(data, "sha256")
        h2, _ = commit(data, "sha256")
        assert h1 == h2
        assert h1.startswith("sha256:")

    def test_default_algorithm_is_poseidon2(self):
        """Default algorithm is Poseidon2 (no env var set)."""
        # Ensure env var is not set
        old = os.environ.pop("PRIMUST_COMMITMENT_ALGORITHM", None)
        try:
            h, alg = commit(b"test data")
            assert alg == "poseidon2"
            assert h.startswith("poseidon2:")
        finally:
            if old is not None:
                os.environ["PRIMUST_COMMITMENT_ALGORITHM"] = old

    def test_sha256_golden_vectors(self):
        """All SHA-256 golden vectors pass."""
        data = load_vectors()
        for v in data["sha256_vectors"]:
            if "input_hex" in v:
                inp = bytes.fromhex(v["input_hex"])
            else:
                inp = v["input_utf8"].encode("utf-8")
            h, _ = commit(inp, v["algorithm"])
            assert h == v["expected_hash"], f"Vector {v['id']} failed: got {h}"

    def test_poseidon2_golden_vectors(self):
        """All Poseidon2 golden vectors pass (opt-in path)."""
        data = load_vectors()
        for v in data["poseidon2_vectors"]:
            if "input_hex" in v:
                inp = bytes.fromhex(v["input_hex"])
            else:
                inp = v["input_utf8"].encode("utf-8")
            h, _ = commit(inp, v["algorithm"])
            assert h == v["expected_hash"], f"Vector {v['id']} failed: got {h}"

    def test_merkle_sha256_golden_vectors(self):
        """SHA-256 Merkle root golden vectors pass (default path)."""
        data = load_vectors()
        for v in data["merkle_sha256_vectors"]:
            result = build_commitment_root(v["input_hashes"], algorithm="sha256")
            assert result == v["expected_root"], f"Vector {v['id']} failed: got {result}"

    def test_merkle_poseidon2_golden_vectors(self):
        """Poseidon2 Merkle root golden vectors pass (opt-in path)."""
        data = load_vectors()
        for v in data["merkle_poseidon2_vectors"]:
            result = build_commitment_root(v["input_hashes"], algorithm="poseidon2")
            assert result == v["expected_root"], f"Vector {v['id']} failed: got {result}"

    def test_commit_output_default_poseidon2(self):
        """commit_output defaults to Poseidon2."""
        old = os.environ.pop("PRIMUST_COMMITMENT_ALGORITHM", None)
        try:
            h, alg = commit_output(b"any output data")
            assert alg == "poseidon2"
            assert h.startswith("poseidon2:")
        finally:
            if old is not None:
                os.environ["PRIMUST_COMMITMENT_ALGORITHM"] = old

    def test_build_commitment_root_empty_is_none(self):
        """buildCommitmentRoot([]) → None."""
        assert build_commitment_root([]) is None

    def test_zk_is_blocking_false(self):
        """ZK_IS_BLOCKING === False."""
        assert ZK_IS_BLOCKING is False

    def test_raw_content_never_transmitted(self):
        """Raw content not in commitment hash (structural check)."""
        raw = b"sensitive-data-that-must-not-leak"
        h, _ = commit(raw, "poseidon2")
        assert raw.decode() not in h
        h2, _ = commit(raw, "sha256")
        assert raw.decode() not in h2

    def test_proof_levels_reachable(self):
        """Proof levels reachable (mathematical excluded until ZK proofs wired)."""
        levels = set()
        for st in ["deterministic_rule", "ml_model", "zkml_model", "statistical_test", "custom_code", "witnessed"]:
            levels.add(select_proof_level(st))
        # TODO(zk-integration): Restore mathematical assertion when ZK proofs are wired
        assert "verifiable_inference" in levels
        assert "execution" in levels
        assert "witnessed" in levels

    def test_verifiable_inference_only_for_zkml_model(self):
        """verifiable_inference only for zkml_model."""
        assert select_proof_level("zkml_model") == "verifiable_inference"
        for st in ["deterministic_rule", "ml_model", "statistical_test", "custom_code", "witnessed"]:
            assert select_proof_level(st) != "verifiable_inference"
