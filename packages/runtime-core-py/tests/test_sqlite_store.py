"""Tests for primust-runtime-core SQLite store — mirrors TypeScript tests."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[3] / "artifact-core-py" / "src"),
)

import logging
from typing import Any

import pytest

from primust_runtime_core.store.sqlite_store import (
    CHAIN_GENESIS_PREFIX,
    SqliteStore,
)

BANNED_COLUMNS = ["agent_id", "pipeline_id", "tool_name", "session_id", "trace_id"]


def _make_record(
    index: int, run_id: str = "run_001", **overrides: Any
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "record_id": f"rec_{index:03d}",
        "run_id": run_id,
        "action_unit_id": f"au_{index}",
        "manifest_id": "manifest_001",
        "manifest_hash": "sha256:" + "a" * 64,
        "surface_id": "surf_001",
        "commitment_hash": "poseidon2:" + "b" * 64,
        "output_commitment": None,
        "commitment_algorithm": "poseidon2",
        "commitment_type": "input_commitment",
        "check_result": "pass",
        "proof_level_achieved": "execution",
        "proof_pending": False,
        "zkml_proof_pending": False,
        "check_open_tst": None,
        "check_close_tst": None,
        "skip_rationale_hash": None,
        "reviewer_credential": None,
        "unverified_provenance": False,
        "freshness_warning": False,
        "idempotency_key": f"idem_{index}",
        "recorded_at": f"2026-03-10T00:00:{index:02d}Z",
    }
    base.update(overrides)
    return base


def _open_default_run(store: SqliteStore, run_id: str = "run_001", **kw: Any):
    defaults = dict(
        run_id=run_id,
        workflow_id="wf_001",
        org_id="org_test",
        surface_id="surf_001",
        policy_snapshot_hash="sha256:" + "x" * 64,
        process_context_hash=None,
        action_unit_count=10,
        ttl_seconds=3600,
    )
    defaults.update(kw)
    return store.open_run(**defaults)


class TestSqliteStore:
    # ── MUST PASS: CHAIN_GENESIS_PREFIX ──

    def test_chain_genesis_prefix(self):
        assert CHAIN_GENESIS_PREFIX == "PRIMUST_CHAIN_GENESIS"

    # ── MUST PASS: chain verifies on 10 sequential records ──

    def test_chain_verifies_10_records(self):
        store = SqliteStore()
        _open_default_run(store)

        for i in range(10):
            result = store.append_check_record(_make_record(i))
            assert result is not None
            assert result["chain_hash"].startswith("sha256:")

        verification = store.verify_chain("run_001")
        assert verification["valid"] is True
        assert verification["broken_at"] == -1

        store.close()

    # ── MUST PASS: modify record 5 → chain breaks at 5 ──

    def test_tamper_record_5_breaks_chain(self):
        store = SqliteStore()
        _open_default_run(store)

        for i in range(10):
            store.append_check_record(_make_record(i))

        # Tamper record 5
        store._conn.execute(
            "UPDATE check_execution_records SET check_result = 'tampered' "
            "WHERE record_id = 'rec_005'"
        )
        store._conn.commit()

        verification = store.verify_chain("run_001")
        assert verification["valid"] is False
        assert verification["broken_at"] == 5

        store.close()

    # ── MUST PASS: failed write does not throw ──

    def test_failed_write_no_throw(self, caplog):
        store = SqliteStore()
        _open_default_run(store)

        store.append_check_record(_make_record(0))

        # Duplicate insert → UNIQUE constraint
        with caplog.at_level(logging.ERROR):
            result = store.append_check_record(_make_record(0))

        assert result is None  # fail-open returns None

        store.close()

    # ── MUST PASS: policy_config_drift ──

    def test_drift_gap_emitted(self):
        store = SqliteStore()
        _open_default_run(store)

        store.append_check_record(
            _make_record(0, manifest_hash="sha256:" + "a" * 64)
        )
        store.close_run("run_001")

        # Second run with changed hash
        drift_gaps = store.open_run(
            run_id="run_002",
            workflow_id="wf_001",
            org_id="org_test",
            surface_id="surf_001",
            policy_snapshot_hash="sha256:" + "x" * 64,
            process_context_hash=None,
            action_unit_count=1,
            ttl_seconds=3600,
            manifest_hashes={"manifest_001": "sha256:" + "b" * 64},
        )

        assert len(drift_gaps) == 1
        assert drift_gaps[0]["gap_type"] == "policy_config_drift"
        assert drift_gaps[0]["severity"] == "Medium"
        assert drift_gaps[0]["details"]["manifest_id"] == "manifest_001"
        assert drift_gaps[0]["details"]["prior_hash"] == "sha256:" + "a" * 64
        assert drift_gaps[0]["details"]["current_hash"] == "sha256:" + "b" * 64

        gaps = store.get_gaps("run_002")
        assert len(gaps) == 1

        store.close()

    # ── MUST PASS: no banned columns ──

    def test_no_banned_columns(self):
        store = SqliteStore()
        tables = store.get_all_table_names()
        for table in tables:
            columns = store.get_table_columns(table)
            for banned in BANNED_COLUMNS:
                assert banned not in columns, (
                    f"Banned column '{banned}' found in table '{table}'"
                )
        store.close()

    # ── MUST PASS: reliance_mode not in any table ──

    def test_no_reliance_mode(self):
        store = SqliteStore()
        tables = store.get_all_table_names()
        for table in tables:
            columns = store.get_table_columns(table)
            assert "reliance_mode" not in columns, (
                f"reliance_mode found in table '{table}'"
            )
        store.close()

    # ── MUST PASS: process_context_hash ──

    def test_process_context_hash_stored(self):
        store = SqliteStore()
        context_hash = "sha256:" + "c" * 64

        _open_default_run(store, process_context_hash=context_hash)

        run = store.get_process_run("run_001")
        assert run is not None
        assert run["process_context_hash"] == context_hash

        store.close()

    def test_process_context_hash_null(self):
        store = SqliteStore()

        _open_default_run(store, process_context_hash=None)

        run = store.get_process_run("run_001")
        assert run is not None
        assert run["process_context_hash"] is None

        store.close()

    # ── MUST PASS: nullable columns ──

    def test_nullable_columns_present(self):
        store = SqliteStore()
        columns = store.get_table_columns("check_execution_records")

        for col in [
            "check_open_tst",
            "check_close_tst",
            "output_commitment",
            "skip_rationale_hash",
        ]:
            assert col in columns, f"Column '{col}' missing"

        # Verify they hold values
        _open_default_run(store)
        store.append_check_record(
            _make_record(
                0,
                check_open_tst="base64:open_token",
                check_close_tst="base64:close_token",
                output_commitment="poseidon2:" + "f" * 64,
                skip_rationale_hash="poseidon2:" + "e" * 64,
            )
        )

        records = store.get_check_records("run_001")
        assert len(records) == 1
        assert records[0]["check_open_tst"] == "base64:open_token"
        assert records[0]["check_close_tst"] == "base64:close_token"
        assert records[0]["output_commitment"] == "poseidon2:" + "f" * 64
        assert records[0]["skip_rationale_hash"] == "poseidon2:" + "e" * 64

        store.close()

    # ── MUST PASS: reviewer_credential as JSON blob ──

    def test_reviewer_credential_json_roundtrip(self):
        store = SqliteStore()
        _open_default_run(store)

        credential = {
            "reviewer_key_id": "key_1",
            "key_binding": "software",
            "role": "reviewer",
            "org_credential_ref": None,
            "reviewer_signature": "ed25519:sig_data",
            "display_hash": "poseidon2:" + "f" * 64,
            "rationale_hash": "poseidon2:" + "f" * 64,
            "signed_content_hash": "poseidon2:" + "f" * 64,
            "open_tst": "base64:open_token",
            "close_tst": "base64:close_token",
        }

        store.append_check_record(
            _make_record(
                0,
                proof_level_achieved="witnessed",
                reviewer_credential=credential,
            )
        )

        records = store.get_check_records("run_001")
        assert len(records) == 1

        retrieved = records[0]["reviewer_credential"]
        assert retrieved is not None
        assert retrieved["reviewer_key_id"] == "key_1"
        assert retrieved["key_binding"] == "software"
        assert retrieved["role"] == "reviewer"
        assert retrieved["reviewer_signature"] == "ed25519:sig_data"

        store.close()

    # ── No drift when hash unchanged ──

    def test_no_drift_when_hash_unchanged(self):
        store = SqliteStore()
        _open_default_run(store)

        store.append_check_record(
            _make_record(0, manifest_hash="sha256:" + "a" * 64)
        )
        store.close_run("run_001")

        drift_gaps = store.open_run(
            run_id="run_002",
            workflow_id="wf_001",
            org_id="org_test",
            surface_id="surf_001",
            policy_snapshot_hash="sha256:" + "x" * 64,
            process_context_hash=None,
            action_unit_count=1,
            ttl_seconds=3600,
            manifest_hashes={"manifest_001": "sha256:" + "a" * 64},
        )

        assert len(drift_gaps) == 0
        store.close()

    # ── MUST PASS: corrupted DB → fail-open (no crash) ──

    def test_corrupted_db_fails_open(self, tmp_path):
        """Write to a store, corrupt the file, write operations fail-open (no throw)."""
        db_file = str(tmp_path / "test.db")
        store = SqliteStore(db_file)
        _open_default_run(store)
        store.append_check_record(_make_record(0))
        store.close()

        # Corrupt the file
        with open(db_file, "wb") as f:
            f.write(b"CORRUPTED DATA " * 100)

        # Re-open with corrupted file — write operations should not throw
        store2 = SqliteStore.__new__(SqliteStore)
        import sqlite3
        store2._conn = sqlite3.connect(db_file, check_same_thread=False)
        store2._conn.row_factory = sqlite3.Row

        # append_check_record: fail-open → returns None
        result = store2.append_check_record(_make_record(1, run_id="run_002"))
        assert result is None

        # open_run: fail-open → returns empty list (no crash)
        drift = store2.open_run(
            run_id="run_003", workflow_id="wf_001", org_id="org_test",
            surface_id="surf_001", policy_snapshot_hash="sha256:" + "x" * 64,
            process_context_hash=None, action_unit_count=1, ttl_seconds=3600,
        )
        assert drift == []

        # insert_gap: fail-open → no throw
        store2.insert_gap({
            "gap_id": "gap_corrupt", "run_id": "run_003",
            "gap_type": "test", "severity": "Low", "state": "open",
            "details": {}, "detected_at": "2026-03-10T00:00:00Z",
        })
        # If we reach here, fail-open worked (no exception propagated)

        store2.close()

    # ── Chain hashes are unique ──

    def test_chain_hashes_unique(self):
        store = SqliteStore()
        _open_default_run(store)

        hashes = []
        for i in range(5):
            result = store.append_check_record(_make_record(i))
            hashes.append(result["chain_hash"])

        assert len(set(hashes)) == 5
        store.close()
