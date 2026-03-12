"""
Primust SDK — Local durability queue.

If api.primust.com is unreachable, records are queued locally in SQLite.
The SDK never throws to the caller due to API unavailability.
When connectivity recovers, the queue flushes automatically.
If the queue is permanently lost, a system_unavailable gap is recorded
in the VPEC — SDK never silently drops governance evidence.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("primust.queue")

_DEFAULT_DB_PATH = Path(
    os.environ.get("PRIMUST_QUEUE_PATH", Path.home() / ".primust" / "queue.db")
)


class LocalQueue:
    """
    Thread-safe SQLite-backed queue for offline durability.
    One queue per SDK process, shared across Pipeline instances.
    """

    def __init__(self, db_path: Path = _DEFAULT_DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS queued_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    queued_at REAL NOT NULL,
                    attempts INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS queued_closes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    queued_at REAL NOT NULL,
                    attempts INTEGER DEFAULT 0
                )
            """)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.db_path), timeout=10)

    def enqueue_record(self, run_id: str, endpoint: str, payload: dict) -> int:
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    "INSERT INTO queued_records (run_id, payload, endpoint, queued_at) VALUES (?,?,?,?)",
                    (run_id, json.dumps(payload), endpoint, time.time())
                )
                return cur.lastrowid  # type: ignore[return-value]

    def enqueue_close(self, run_id: str, payload: dict) -> int:
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    "INSERT INTO queued_closes (run_id, payload, queued_at) VALUES (?,?,?)",
                    (run_id, json.dumps(payload), time.time())
                )
                return cur.lastrowid  # type: ignore[return-value]

    def pending_records(self) -> list[dict]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT id, run_id, endpoint, payload, attempts FROM queued_records ORDER BY id"
                ).fetchall()
            return [
                {"id": r[0], "run_id": r[1], "endpoint": r[2],
                 "payload": json.loads(r[3]), "attempts": r[4]}
                for r in rows
            ]

    def pending_closes(self) -> list[dict]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT id, run_id, payload, attempts FROM queued_closes ORDER BY id"
                ).fetchall()
            return [
                {"id": r[0], "run_id": r[1],
                 "payload": json.loads(r[2]), "attempts": r[3]}
                for r in rows
            ]

    def delete_record(self, row_id: int) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM queued_records WHERE id=?", (row_id,))

    def delete_close(self, row_id: int) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM queued_closes WHERE id=?", (row_id,))

    def increment_attempts(self, table: str, row_id: int) -> None:
        if table not in ("queued_records", "queued_closes"):
            raise ValueError(f"Invalid table: {table}")
        with self._lock:
            with self._connect() as conn:
                conn.execute(f"UPDATE {table} SET attempts=attempts+1 WHERE id=?", (row_id,))

    def count(self) -> int:
        with self._lock:
            with self._connect() as conn:
                r = conn.execute(
                    "SELECT COUNT(*) FROM queued_records"
                ).fetchone()
                c = conn.execute(
                    "SELECT COUNT(*) FROM queued_closes"
                ).fetchone()
                return (r[0] if r else 0) + (c[0] if c else 0)
