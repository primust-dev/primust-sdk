"""Primust Runtime Core — Sync Queue + Degraded Operating Modes (Python).

In-memory queue (500 records max, 10-min TTL) between local SQLite store
and remote Primust API. Handles API unavailability (Mode 1) and Pipeline
TTL (Mode 5) directly. Modes 2-4 are signaled via DegradedStatus flags
for the caller pipeline to read.

FAIL-OPEN: push() and close() never raise to the caller.
ZK_IS_BLOCKING = False: ZK proof failures NEVER block VPEC issuance.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Literal, Protocol, TypedDict

from primust_runtime_core.store.sqlite_store import SqliteStore

logger = logging.getLogger(__name__)

# ── Constants ──

ZK_IS_BLOCKING: bool = False
"""ZK proof failures NEVER block VPEC issuance. Non-negotiable."""

QUEUE_MAX_RECORDS: int = 500
"""Maximum in-memory queue depth."""

QUEUE_RECORD_TTL_MS: int = 10 * 60 * 1000
"""Per-record TTL in milliseconds (10 minutes)."""

CLOSE_MAX_RETRIES: int = 5
"""Maximum close() retries."""

CLOSE_BACKOFF_CAP_MS: int = 30_000
"""Maximum backoff cap in milliseconds."""

PIPELINE_TTL_SECONDS: int = 3600
"""Default pipeline TTL in seconds (1 hour)."""


# ── Types ──


class SyncResultOk(TypedDict):
    ok: Literal[True]


class SyncResultError(TypedDict):
    ok: Literal[False]
    error: str
    retryable: bool


SyncResult = SyncResultOk | SyncResultError


class SyncTarget(Protocol):
    async def send(self, records: list[dict[str, Any]]) -> SyncResult: ...


class DegradedStatus(TypedDict):
    api_available: bool
    signer_available: bool
    zk_prover_available: bool
    zkml_prover_available: bool


SleepFn = Callable[[float], Any]
"""Callable that sleeps for the given number of milliseconds. Can be async."""


@dataclass
class QueuedRecord:
    record: dict[str, Any]
    enqueued_at: float  # time.monotonic() * 1000


OnRecordDroppedFn = Callable[[dict[str, Any], Literal["ttl_expired", "capacity_overflow"]], None]
OnGapDetectedFn = Callable[[dict[str, Any]], None]


@dataclass
class SyncQueueCallbacks:
    on_record_dropped: OnRecordDroppedFn | None = None
    on_gap_detected: OnGapDetectedFn | None = None


# ── Default sleep ──

async def _default_sleep(ms: float) -> None:
    await asyncio.sleep(ms / 1000.0)


# ── SyncQueue ──


class SyncQueue:
    def __init__(
        self,
        *,
        store: SqliteStore,
        target: SyncTarget | None = None,
        callbacks: SyncQueueCallbacks | None = None,
        sleep_fn: SleepFn | None = None,
    ) -> None:
        self._store = store
        self._target = target
        self._buffer: list[QueuedRecord] = []
        self._status: DegradedStatus = {
            "api_available": target is not None,
            "signer_available": True,
            "zk_prover_available": True,
            "zkml_prover_available": True,
        }
        self._callbacks = callbacks or SyncQueueCallbacks()
        self._sleep_fn = sleep_fn or _default_sleep
        self._pipeline_timers: dict[str, asyncio.TimerHandle | None] = {}
        self._ttl_tasks: dict[str, Any] = {}  # for non-asyncio timer fallback

    def push(self, record: dict[str, Any]) -> None:
        """Push a record into the queue. Writes to SQLite first, then buffers.
        Never raises."""
        try:
            self._sweep_expired()

            if len(self._buffer) >= QUEUE_MAX_RECORDS:
                dropped = self._buffer.pop(0)
                if self._callbacks.on_record_dropped:
                    self._callbacks.on_record_dropped(dropped.record, "capacity_overflow")
                logger.error("SyncQueue: record dropped due to capacity overflow")

            result = self._store.append_check_record(record)

            full_record = {**record, "chain_hash": result["chain_hash"] if result else ""}

            self._buffer.append(QueuedRecord(
                record=full_record,
                enqueued_at=time.monotonic() * 1000,
            ))

            # Fire-and-forget flush if API available
            if self._status["api_available"] and self._target:
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(self.flush())
                except RuntimeError:
                    pass  # No event loop — skip async flush
        except Exception as exc:
            logger.error("SyncQueue.push failed: %s", exc)

    async def flush(self) -> int:
        """Attempt to send buffered records upstream. Returns count sent."""
        try:
            self._sweep_expired()

            if not self._buffer or not self._target:
                return 0

            batch = [qr.record for qr in self._buffer]
            result = await self._target.send(batch)

            if result["ok"]:
                count = len(self._buffer)
                self._buffer.clear()
                self._status["api_available"] = True
                return count

            self._status["api_available"] = False
            if not result.get("retryable", False):
                dropped = list(self._buffer)
                self._buffer.clear()
                if self._callbacks.on_record_dropped:
                    for qr in dropped:
                        self._callbacks.on_record_dropped(qr.record, "capacity_overflow")
            return 0
        except Exception as exc:
            self._status["api_available"] = False
            logger.error("SyncQueue.flush failed: %s", exc)
            return 0

    async def close(self, run_id: str) -> None:
        """Close a pipeline run with retry. On all retries failing,
        auto-closes the run and emits an api_unavailable gap."""
        try:
            flushed = False

            for attempt in range(CLOSE_MAX_RETRIES):
                count = await self.flush()
                if count > 0 or len(self._buffer) == 0:
                    flushed = True
                    break

                if not self._target:
                    break

                delay = min(1000 * (2 ** attempt), CLOSE_BACKOFF_CAP_MS)
                await self._sleep_fn(delay)

            if flushed or len(self._buffer) == 0:
                self._store.close_run(run_id, "closed")
            else:
                self._store.close_run(run_id, "auto_closed")

                now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                gap = {
                    "gap_id": f"gap_api_unavailable_{run_id}",
                    "run_id": run_id,
                    "gap_type": "api_unavailable",
                    "severity": "High",
                    "state": "open",
                    "details": {
                        "reason": f"API unreachable after {CLOSE_MAX_RETRIES} retries",
                    },
                    "detected_at": now,
                    "resolved_at": None,
                }
                self._store.insert_gap(gap)
                if self._callbacks.on_gap_detected:
                    self._callbacks.on_gap_detected(gap)

            self.cancel_pipeline_ttl(run_id)
        except Exception as exc:
            logger.error("SyncQueue.close failed: %s", exc)
            try:
                self._store.close_run(run_id, "auto_closed")
            except Exception:
                pass  # truly fail-open

    def start_pipeline_ttl(self, run_id: str, ttl_seconds: int = PIPELINE_TTL_SECONDS) -> None:
        """Start a pipeline TTL timer. Auto-closes the run after ttl_seconds."""
        try:
            loop = asyncio.get_running_loop()
            handle = loop.call_later(ttl_seconds, self._auto_close, run_id)
            self._pipeline_timers[run_id] = handle
        except RuntimeError:
            # No event loop — use threading.Timer fallback
            import threading
            timer = threading.Timer(ttl_seconds, self._auto_close, args=[run_id])
            timer.daemon = True
            timer.start()
            self._ttl_tasks[run_id] = timer

    def cancel_pipeline_ttl(self, run_id: str) -> None:
        """Cancel a pipeline TTL timer."""
        handle = self._pipeline_timers.pop(run_id, None)
        if handle is not None:
            handle.cancel()

        timer = self._ttl_tasks.pop(run_id, None)
        if timer is not None:
            timer.cancel()

    def _auto_close(self, run_id: str) -> None:
        """Auto-close a run (called by TTL timer)."""
        try:
            self._store.close_run(run_id, "auto_closed")
            self._pipeline_timers.pop(run_id, None)
            self._ttl_tasks.pop(run_id, None)
        except Exception as exc:
            logger.error("SyncQueue._auto_close failed: %s", exc)

    # ── Degraded status ──

    def get_degraded_status(self) -> DegradedStatus:
        return {**self._status}

    def mark_subsystem_down(self, subsystem: str) -> None:
        self._status[subsystem] = False  # type: ignore[literal-required]

    def mark_subsystem_up(self, subsystem: str) -> None:
        self._status[subsystem] = True  # type: ignore[literal-required]

    def is_fully_operational(self) -> bool:
        return all(self._status.values())

    def get_buffer_size(self) -> int:
        return len(self._buffer)

    # ── Internal ──

    def _sweep_expired(self) -> int:
        now = time.monotonic() * 1000
        before = len(self._buffer)
        expired: list[QueuedRecord] = []

        kept: list[QueuedRecord] = []
        for qr in self._buffer:
            if now - qr.enqueued_at > QUEUE_RECORD_TTL_MS:
                expired.append(qr)
            else:
                kept.append(qr)
        self._buffer = kept

        if self._callbacks.on_record_dropped:
            for qr in expired:
                self._callbacks.on_record_dropped(qr.record, "ttl_expired")

        return before - len(self._buffer)
