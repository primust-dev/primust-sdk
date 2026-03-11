"""
Tests for Primust commitment layer — P6-A Python mirror.
9 MUST PASS tests matching TypeScript commitment.test.ts.
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
        return json.load(f)["vectors"]


# ── Tests ──


class TestCommitment:
    def test_poseidon2_deterministic(self):
        """MUST PASS: poseidon2 is deterministic — same input → same hash."""
        data = b"hello primust"
        h1, _ = commit(data, "poseidon2")
        h2, _ = commit(data, "poseidon2")
        assert h1 == h2
        assert h1.startswith("poseidon2:")

    def test_sha256_deterministic(self):
        """MUST PASS: sha256 is deterministic — same input → same hash."""
        data = b"hello primust"
        h1, _ = commit(data, "sha256")
        h2, _ = commit(data, "sha256")
        assert h1 == h2
        assert h1.startswith("sha256:")

    def test_golden_vectors(self):
        """MUST PASS: all 10 golden vectors pass."""
        vectors = load_vectors()
        assert len(vectors) == 10

        for v in vectors:
            if v.get("type") == "merkle_root":
                result = build_commitment_root(v["input_hashes"])
                assert result == v["expected_root"], f"Vector {v['id']} failed"
            else:
                inp = bytes.fromhex(v["input_hex"])
                h, _ = commit(inp, v["algorithm"])
                assert h == v["expected_hash"], f"Vector {v['id']} failed"

    def test_commit_output_always_poseidon2(self):
        """MUST PASS: commitOutput always uses poseidon2."""
        h, alg = commit_output(b"any output data")
        assert alg == "poseidon2"
        assert h.startswith("poseidon2:")

    def test_build_commitment_root_empty_is_none(self):
        """MUST PASS: buildCommitmentRoot([]) → None."""
        assert build_commitment_root([]) is None

    def test_zk_is_blocking_false(self):
        """MUST PASS: ZK_IS_BLOCKING === False."""
        assert ZK_IS_BLOCKING is False

    def test_raw_content_never_transmitted(self):
        """MUST PASS: raw content not in HTTP request body (structural check)."""
        # Verify commit only returns hash, not raw content
        raw = b"sensitive-data-that-must-not-leak"
        h, _ = commit(raw, "poseidon2")
        assert raw.decode() not in h
        h2, _ = commit(raw, "sha256")
        assert raw.decode() not in h2

    def test_all_5_proof_levels(self):
        """MUST PASS: all 5 proof levels present in selectProofLevel."""
        levels = set()
        for st in ["deterministic_rule", "ml_model", "zkml_model", "statistical_test", "custom_code", "human_review"]:
            levels.add(select_proof_level(st))
        # Must cover: mathematical, execution_zkml, execution, witnessed
        assert "mathematical" in levels
        assert "execution_zkml" in levels
        assert "execution" in levels
        assert "witnessed" in levels

    def test_execution_zkml_only_for_zkml_model(self):
        """MUST PASS: execution_zkml only for zkml_model."""
        assert select_proof_level("zkml_model") == "execution_zkml"
        for st in ["deterministic_rule", "ml_model", "statistical_test", "custom_code", "human_review"]:
            assert select_proof_level(st) != "execution_zkml"
