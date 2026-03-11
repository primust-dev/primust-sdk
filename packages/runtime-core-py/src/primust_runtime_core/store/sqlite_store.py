"""Primust Runtime Core — SQLite Store + Integrity Chain (Python).

Tables match P4-A schemas exactly. All column names use P4-A field names verbatim.

INTEGRITY CHAIN:
  First record:   chain_hash = SHA256(CHAIN_GENESIS_PREFIX || run_id || canonical(record))
  Subsequent:     chain_hash = SHA256(CHAIN_GENESIS_PREFIX || prev_chain_hash || canonical(record))

FAIL-OPEN: store write failure → log error, do NOT throw.
APPEND-ONLY: no UPDATE on check_execution_records after insert.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from dataclasses import asdict
from typing import Any

from primust_artifact_core.canonical import canonical

logger = logging.getLogger(__name__)

CHAIN_GENESIS_PREFIX = "PRIMUST_CHAIN_GENESIS"

_CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS observation_surfaces (
    surface_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    surface_type TEXT NOT NULL,
    surface_name TEXT NOT NULL,
    surface_version TEXT NOT NULL,
    observation_mode TEXT NOT NULL,
    scope_type TEXT NOT NULL,
    scope_description TEXT NOT NULL,
    surface_coverage_statement TEXT NOT NULL,
    proof_ceiling TEXT NOT NULL,
    gaps_detectable TEXT NOT NULL,
    gaps_not_detectable TEXT NOT NULL,
    registered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS check_manifests (
    manifest_id TEXT PRIMARY KEY,
    manifest_hash TEXT NOT NULL,
    domain TEXT NOT NULL,
    name TEXT NOT NULL,
    semantic_version TEXT NOT NULL,
    check_type TEXT NOT NULL,
    implementation_type TEXT NOT NULL,
    supported_proof_level TEXT NOT NULL,
    evaluation_scope TEXT NOT NULL,
    evaluation_window_seconds INTEGER,
    stages TEXT NOT NULL,
    aggregation_config TEXT NOT NULL,
    freshness_threshold_hours REAL,
    benchmark TEXT,
    model_or_tool_hash TEXT,
    publisher TEXT NOT NULL,
    signer_id TEXT NOT NULL,
    kid TEXT NOT NULL,
    signed_at TEXT NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_packs (
    policy_pack_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    checks TEXT NOT NULL,
    created_at TEXT NOT NULL,
    signer_id TEXT NOT NULL,
    kid TEXT NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    policy_pack_id TEXT NOT NULL,
    policy_pack_version TEXT NOT NULL,
    effective_checks TEXT NOT NULL,
    snapshotted_at TEXT NOT NULL,
    policy_basis TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS process_runs (
    run_id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    surface_id TEXT NOT NULL,
    policy_snapshot_hash TEXT NOT NULL,
    process_context_hash TEXT,
    state TEXT NOT NULL,
    action_unit_count INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    closed_at TEXT,
    ttl_seconds INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS action_units (
    action_unit_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    surface_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS check_execution_records (
    record_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    action_unit_id TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    surface_id TEXT NOT NULL,
    commitment_hash TEXT NOT NULL,
    output_commitment TEXT,
    commitment_algorithm TEXT NOT NULL,
    commitment_type TEXT NOT NULL,
    check_result TEXT NOT NULL,
    proof_level_achieved TEXT NOT NULL,
    proof_pending INTEGER NOT NULL DEFAULT 0,
    zkml_proof_pending INTEGER NOT NULL DEFAULT 0,
    check_open_tst TEXT,
    check_close_tst TEXT,
    skip_rationale_hash TEXT,
    reviewer_credential TEXT,
    unverified_provenance INTEGER NOT NULL DEFAULT 0,
    freshness_warning INTEGER NOT NULL DEFAULT 0,
    chain_hash TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gaps (
    gap_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    gap_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    state TEXT NOT NULL,
    details TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE TABLE IF NOT EXISTS waivers (
    waiver_id TEXT PRIMARY KEY,
    gap_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    requestor_user_id TEXT NOT NULL,
    approver_user_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    compensating_control TEXT,
    expires_at TEXT NOT NULL,
    signature TEXT NOT NULL,
    approved_at TEXT NOT NULL
);
"""


def _compute_chain_hash(prefix: str, content: str) -> str:
    data = (prefix + content).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _build_record_content(record: dict[str, Any]) -> dict[str, Any]:
    """Build the content dict for chain hashing (excludes chain_hash)."""
    return {
        "record_id": record["record_id"],
        "run_id": record["run_id"],
        "action_unit_id": record["action_unit_id"],
        "manifest_id": record["manifest_id"],
        "manifest_hash": record["manifest_hash"],
        "surface_id": record["surface_id"],
        "commitment_hash": record["commitment_hash"],
        "output_commitment": record["output_commitment"],
        "commitment_algorithm": record["commitment_algorithm"],
        "commitment_type": record["commitment_type"],
        "check_result": record["check_result"],
        "proof_level_achieved": record["proof_level_achieved"],
        "proof_pending": record["proof_pending"],
        "zkml_proof_pending": record["zkml_proof_pending"],
        "check_open_tst": record["check_open_tst"],
        "check_close_tst": record["check_close_tst"],
        "skip_rationale_hash": record["skip_rationale_hash"],
        "reviewer_credential": record["reviewer_credential"],
        "unverified_provenance": record["unverified_provenance"],
        "freshness_warning": record["freshness_warning"],
        "idempotency_key": record["idempotency_key"],
        "recorded_at": record["recorded_at"],
    }


class SqliteStore:
    def __init__(self, db_path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_CREATE_TABLES)
        self._conn.commit()

    # ── Process Runs ──

    def open_run(
        self,
        *,
        run_id: str,
        workflow_id: str,
        org_id: str,
        surface_id: str,
        policy_snapshot_hash: str,
        process_context_hash: str | None,
        action_unit_count: int,
        ttl_seconds: int,
        manifest_hashes: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Open a new process run. Returns drift gaps if any."""
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        drift_gaps: list[dict[str, Any]] = []

        try:
            self._conn.execute(
                """
                INSERT INTO process_runs (
                    run_id, workflow_id, org_id, surface_id, policy_snapshot_hash,
                    process_context_hash, state, action_unit_count, started_at,
                    closed_at, ttl_seconds
                ) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, NULL, ?)
                """,
                (
                    run_id, workflow_id, org_id, surface_id,
                    policy_snapshot_hash, process_context_hash,
                    action_unit_count, now, ttl_seconds,
                ),
            )
            self._conn.commit()

            # Policy config drift detection
            if manifest_hashes:
                row = self._conn.execute(
                    """
                    SELECT run_id FROM process_runs
                    WHERE workflow_id = ? AND state = 'closed' AND run_id != ?
                    ORDER BY started_at DESC LIMIT 1
                    """,
                    (workflow_id, run_id),
                ).fetchone()

                if row:
                    last_run_id = row["run_id"]
                    for manifest_id, current_hash in manifest_hashes.items():
                        prior = self._conn.execute(
                            """
                            SELECT manifest_hash FROM check_execution_records
                            WHERE run_id = ? AND manifest_id = ? LIMIT 1
                            """,
                            (last_run_id, manifest_id),
                        ).fetchone()

                        if prior and prior["manifest_hash"] != current_hash:
                            gap = {
                                "gap_id": f"gap_drift_{manifest_id}_{run_id}",
                                "run_id": run_id,
                                "gap_type": "policy_config_drift",
                                "severity": "Medium",
                                "state": "open",
                                "details": {
                                    "manifest_id": manifest_id,
                                    "prior_hash": prior["manifest_hash"],
                                    "current_hash": current_hash,
                                    "detected_at": now,
                                },
                                "detected_at": now,
                                "resolved_at": None,
                            }
                            drift_gaps.append(gap)
                            self.insert_gap(gap)

        except Exception as exc:
            logger.error("SqliteStore.open_run failed: %s", exc)

        return drift_gaps

    def close_run(
        self, run_id: str, state: str = "closed"
    ) -> None:
        from datetime import datetime, timezone

        try:
            now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            self._conn.execute(
                "UPDATE process_runs SET state = ?, closed_at = ? WHERE run_id = ?",
                (state, now, run_id),
            )
            self._conn.commit()
        except Exception as exc:
            logger.error("SqliteStore.close_run failed: %s", exc)

    def get_process_run(self, run_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM process_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        return dict(row) if row else None

    # ── Policy Snapshots ──

    def write_policy_snapshot(
        self,
        *,
        snapshot_id: str,
        policy_pack_id: str,
        policy_pack_version: str,
        effective_checks: list[dict[str, Any]],
        snapshotted_at: str,
        policy_basis: str,
    ) -> None:
        """Write a policy snapshot. INSERT OR IGNORE (content-addressed, immutable).
        FAIL-OPEN: logs error, does NOT raise."""
        try:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO policy_snapshots (
                    snapshot_id, policy_pack_id, policy_pack_version,
                    effective_checks, snapshotted_at, policy_basis
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id, policy_pack_id, policy_pack_version,
                    json.dumps(effective_checks), snapshotted_at, policy_basis,
                ),
            )
            self._conn.commit()
        except Exception as exc:
            logger.error("SqliteStore.write_policy_snapshot failed: %s", exc)

    def get_policy_snapshot(self, snapshot_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM policy_snapshots WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["effective_checks"] = json.loads(d["effective_checks"])
        return d

    # ── Check Execution Records (append-only) ──

    def append_check_record(
        self, record: dict[str, Any]
    ) -> dict[str, str] | None:
        """Append a check execution record. Computes chain_hash.
        FAIL-OPEN: logs error, returns None on failure.
        """
        try:
            record_content = _build_record_content(record)
            canonical_content = canonical(record_content)

            # Get previous chain_hash for this run
            prev = self._conn.execute(
                """
                SELECT chain_hash FROM check_execution_records
                WHERE run_id = ? ORDER BY recorded_at DESC, rowid DESC LIMIT 1
                """,
                (record["run_id"],),
            ).fetchone()

            if prev:
                chain_hash = _compute_chain_hash(
                    CHAIN_GENESIS_PREFIX,
                    prev["chain_hash"] + canonical_content,
                )
            else:
                chain_hash = _compute_chain_hash(
                    CHAIN_GENESIS_PREFIX,
                    record["run_id"] + canonical_content,
                )

            reviewer_cred = record.get("reviewer_credential")
            reviewer_json = json.dumps(reviewer_cred) if reviewer_cred else None

            self._conn.execute(
                """
                INSERT INTO check_execution_records (
                    record_id, run_id, action_unit_id, manifest_id, manifest_hash,
                    surface_id, commitment_hash, output_commitment, commitment_algorithm,
                    commitment_type, check_result, proof_level_achieved, proof_pending,
                    zkml_proof_pending, check_open_tst, check_close_tst, skip_rationale_hash,
                    reviewer_credential, unverified_provenance, freshness_warning,
                    chain_hash, idempotency_key, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["record_id"], record["run_id"], record["action_unit_id"],
                    record["manifest_id"], record["manifest_hash"], record["surface_id"],
                    record["commitment_hash"], record.get("output_commitment"),
                    record["commitment_algorithm"], record["commitment_type"],
                    record["check_result"], record["proof_level_achieved"],
                    1 if record.get("proof_pending") else 0,
                    1 if record.get("zkml_proof_pending") else 0,
                    record.get("check_open_tst"), record.get("check_close_tst"),
                    record.get("skip_rationale_hash"), reviewer_json,
                    1 if record.get("unverified_provenance") else 0,
                    1 if record.get("freshness_warning") else 0,
                    chain_hash, record["idempotency_key"], record["recorded_at"],
                ),
            )
            self._conn.commit()
            return {"chain_hash": chain_hash}

        except Exception as exc:
            logger.error("SqliteStore.append_check_record failed: %s", exc)
            return None

    def get_check_records(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM check_execution_records WHERE run_id = ? ORDER BY recorded_at, rowid",
            (run_id,),
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["proof_pending"] = d["proof_pending"] == 1
            d["zkml_proof_pending"] = d["zkml_proof_pending"] == 1
            d["unverified_provenance"] = d["unverified_provenance"] == 1
            d["freshness_warning"] = d["freshness_warning"] == 1
            d["reviewer_credential"] = (
                json.loads(d["reviewer_credential"])
                if d["reviewer_credential"]
                else None
            )
            result.append(d)
        return result

    # ── Chain Verification ──

    def verify_chain(self, run_id: str) -> dict[str, Any]:
        """Verify the integrity chain. Returns {valid, broken_at}."""
        rows = self._conn.execute(
            "SELECT * FROM check_execution_records WHERE run_id = ? ORDER BY recorded_at, rowid",
            (run_id,),
        ).fetchall()

        records = [dict(r) for r in rows]

        for i, record in enumerate(records):
            rc = _build_record_content_from_row(record)
            canonical_content = canonical(rc)

            if i == 0:
                expected = _compute_chain_hash(
                    CHAIN_GENESIS_PREFIX,
                    run_id + canonical_content,
                )
            else:
                prev_hash = records[i - 1]["chain_hash"]
                expected = _compute_chain_hash(
                    CHAIN_GENESIS_PREFIX,
                    prev_hash + canonical_content,
                )

            if record["chain_hash"] != expected:
                return {"valid": False, "broken_at": i}

        return {"valid": True, "broken_at": -1}

    # ── Gaps ──

    def insert_gap(self, gap: dict[str, Any]) -> None:
        try:
            self._conn.execute(
                """
                INSERT INTO gaps (
                    gap_id, run_id, gap_type, severity, state,
                    details, detected_at, resolved_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    gap["gap_id"], gap["run_id"], gap["gap_type"],
                    gap["severity"], gap["state"],
                    json.dumps(gap["details"]), gap["detected_at"],
                    gap.get("resolved_at"),
                ),
            )
            self._conn.commit()
        except Exception as exc:
            logger.error("SqliteStore.insert_gap failed: %s", exc)

    def get_gaps(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM gaps WHERE run_id = ? ORDER BY detected_at",
            (run_id,),
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["details"] = json.loads(d["details"])
            result.append(d)
        return result

    # ── Schema inspection ──

    def get_table_columns(self, table_name: str) -> list[str]:
        rows = self._conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return [r["name"] for r in rows]

    def get_all_table_names(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        return [r["name"] for r in rows]

    def close(self) -> None:
        self._conn.close()


def _build_record_content_from_row(row: dict[str, Any]) -> dict[str, Any]:
    """Build content for chain verification from a DB row."""
    reviewer = row.get("reviewer_credential")
    if isinstance(reviewer, str):
        reviewer = json.loads(reviewer)
    return {
        "record_id": row["record_id"],
        "run_id": row["run_id"],
        "action_unit_id": row["action_unit_id"],
        "manifest_id": row["manifest_id"],
        "manifest_hash": row["manifest_hash"],
        "surface_id": row["surface_id"],
        "commitment_hash": row["commitment_hash"],
        "output_commitment": row["output_commitment"],
        "commitment_algorithm": row["commitment_algorithm"],
        "commitment_type": row["commitment_type"],
        "check_result": row["check_result"],
        "proof_level_achieved": row["proof_level_achieved"],
        "proof_pending": row["proof_pending"] == 1,
        "zkml_proof_pending": row["zkml_proof_pending"] == 1,
        "check_open_tst": row["check_open_tst"],
        "check_close_tst": row["check_close_tst"],
        "skip_rationale_hash": row["skip_rationale_hash"],
        "reviewer_credential": reviewer,
        "unverified_provenance": row["unverified_provenance"] == 1,
        "freshness_warning": row["freshness_warning"] == 1,
        "idempotency_key": row["idempotency_key"],
        "recorded_at": row["recorded_at"],
    }
