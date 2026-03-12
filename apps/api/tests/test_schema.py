"""
P9-A schema validation tests — 9 MUST PASS.

Validates the Postgres migration SQL structurally without requiring
a live database connection.
"""

from __future__ import annotations

import os
import re

import pytest

MIGRATION_PATH = os.path.join(
    os.path.dirname(__file__),
    "..", "..", "..", "packages", "db", "migrations", "001_initial.sql",
)


@pytest.fixture
def migration_sql() -> str:
    with open(MIGRATION_PATH) as f:
        return f.read()


# ── P9-A Tests ──


class TestSchema:
    """P9-A: Postgres Schema and Migrations."""

    def test_migrations_parseable(self, migration_sql: str) -> None:
        """MUST PASS: migration SQL is valid and non-empty."""
        assert len(migration_sql) > 100
        # Must contain CREATE TABLE statements
        tables = re.findall(r"CREATE TABLE (\w+)", migration_sql)
        assert len(tables) >= 11, f"Expected 11+ tables, got {len(tables)}: {tables}"

    def test_all_10_objects_have_tables(self, migration_sql: str) -> None:
        """MUST PASS: all 10 P4-A objects round-trip through their tables."""
        required_tables = [
            "observation_surfaces",
            "check_manifests",
            "policy_packs",
            "policy_snapshots",
            "process_runs",
            "action_units",
            "check_execution_records",
            "gaps",
            "waivers",
            "vpecs",
            "evidence_packs",
        ]
        tables = re.findall(r"CREATE TABLE (\w+)", migration_sql)
        for table in required_tables:
            assert table in tables, f"Missing table: {table}"

    def test_no_banned_column_names(self, migration_sql: str) -> None:
        """MUST PASS: no column named agent_id, pipeline_id, tool_name, session_id, trace_id."""
        banned = ["agent_id", "pipeline_id", "tool_name", "session_id", "trace_id"]
        for col in banned:
            # Match as a column definition (word boundary)
            pattern = rf"\b{col}\b\s+(TEXT|INTEGER|BOOLEAN|JSONB|TIMESTAMPTZ|NUMERIC)"
            assert not re.search(pattern, migration_sql, re.IGNORECASE), (
                f"Banned column '{col}' found in migration"
            )

    def test_reliance_mode_absent(self, migration_sql: str) -> None:
        """MUST PASS: reliance_mode column absent in all tables."""
        assert "reliance_mode" not in migration_sql.lower()

    def test_process_context_hash_nullable(self, migration_sql: str) -> None:
        """MUST PASS: process_context_hash nullable column on process_runs."""
        # Find the process_runs CREATE TABLE block
        match = re.search(
            r"CREATE TABLE process_runs\s*\((.*?)\);",
            migration_sql,
            re.DOTALL,
        )
        assert match, "process_runs table not found"
        block = match.group(1)

        # process_context_hash should NOT have NOT NULL
        pch_line = [
            line
            for line in block.split("\n")
            if "process_context_hash" in line
        ]
        assert len(pch_line) == 1, "process_context_hash column not found in process_runs"
        assert "NOT NULL" not in pch_line[0].upper(), (
            "process_context_hash must be nullable"
        )

    def test_dual_database_urls(self) -> None:
        """MUST PASS: DATABASE_URL_US and DATABASE_URL_EU both configured."""
        # The migration SQL header comments reference dual-region
        # The actual env vars are validated at runtime in db.py
        from primust_api.db import RegionConfig

        # Test US config
        us = RegionConfig("us")
        assert us.database_url  # env var set in conftest

        # Test EU config
        os.environ["DATABASE_URL_EU"] = "postgresql://test:test@localhost:5432/primust_eu"
        eu = RegionConfig("eu")
        assert eu.database_url

        # Invalid region should raise
        with pytest.raises(ValueError, match="Invalid region"):
            RegionConfig("ap")

    def test_check_execution_records_append_only(self, migration_sql: str) -> None:
        """MUST PASS: check_execution_records append-only (no UPDATE trigger)."""
        assert "prevent_cer_update" in migration_sql
        assert "trg_cer_no_update" in migration_sql
        assert "BEFORE UPDATE ON check_execution_records" in migration_sql

    def test_all_5_proof_level_enum_values(self, migration_sql: str) -> None:
        """MUST PASS: all 5 proof level enum values present."""
        proof_levels = [
            "mathematical",
            "verifiable_inference",
            "execution",
            "witnessed",
            "attestation",
        ]
        for level in proof_levels:
            assert f"'{level}'" in migration_sql, (
                f"Proof level '{level}' not in enum"
            )

    def test_waivers_expires_at_not_null(self, migration_sql: str) -> None:
        """MUST PASS: waivers.expires_at NOT NULL (no permanent waivers)."""
        match = re.search(
            r"CREATE TABLE waivers\s*\((.*?)\);",
            migration_sql,
            re.DOTALL,
        )
        assert match, "waivers table not found"
        block = match.group(1)

        expires_line = [
            line for line in block.split("\n") if "expires_at" in line
        ]
        assert len(expires_line) == 1, "expires_at column not found in waivers"
        assert "NOT NULL" in expires_line[0].upper(), (
            "waivers.expires_at must be NOT NULL"
        )
