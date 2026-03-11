"""Tests for SyncQueue — Python mirror of sync_queue.test.ts."""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import patch

import pytest

from primust_runtime_core.queue.sync_queue import (
    CLOSE_MAX_RETRIES,
    PIPELINE_TTL_SECONDS,
    QUEUE_MAX_RECORDS,
    QUEUE_RECORD_TTL_MS,
    ZK_IS_BLOCKING,
    SyncQueue,
    SyncQueueCallbacks,
)
from primust_runtime_core.store.sqlite_store import SqliteStore


# ── Helpers ──


def make_record(
    index: int,
    run_id: str = "run_001",
    **overrides: Any,
) -> dict[str, Any]:
    return {
        "record_id": f"rec_{str(index).zfill(3)}",
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
        "recorded_at": f"2026-03-10T00:00:{str(index).zfill(2)}Z",
        **overrides,
    }


class MockSyncTarget:
    def __init__(self, behavior: str = "succeed") -> None:
        self.behavior = behavior
        self.sent: list[list[dict[str, Any]]] = []

    async def send(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        if self.behavior == "succeed":
            self.sent.append(list(records))
            return {"ok": True}
        if self.behavior == "fail_retryable":
            return {"ok": False, "error": "timeout", "retryable": True}
        return {"ok": False, "error": "auth_failed", "retryable": False}


async def instant_sleep(ms: float) -> None:
    """Instant sleep for fast tests."""
    pass


def open_default_run(store: SqliteStore, run_id: str = "run_001") -> None:
    store.open_run(
        run_id=run_id,
        workflow_id="wf_001",
        org_id="org_test",
        surface_id="surf_001",
        policy_snapshot_hash="sha256:" + "x" * 64,
        process_context_hash=None,
        action_unit_count=10,
        ttl_seconds=3600,
    )


# ── Tests ──


class TestSyncQueue:
    def setup_method(self) -> None:
        self.store = SqliteStore(":memory:")

    def teardown_method(self) -> None:
        self.store.close()

    # ── MUST PASS: ZK_IS_BLOCKING constant ──

    def test_zk_is_blocking_false(self) -> None:
        assert ZK_IS_BLOCKING is False

    # ── MUST PASS: Mode 1 — API unavailable does not throw ──

    def test_mode1_push_succeeds_when_api_unavailable(self) -> None:
        open_default_run(self.store)
        queue = SyncQueue(store=self.store, target=None)

        # Must not raise
        queue.push(make_record(0))
        assert queue.get_buffer_size() == 1

        records = self.store.get_check_records("run_001")
        assert len(records) == 1

    def test_mode1_close_retries_with_backoff_and_emits_gap(self) -> None:
        open_default_run(self.store)
        target = MockSyncTarget("fail_retryable")
        sleep_calls: list[float] = []

        async def tracking_sleep(ms: float) -> None:
            sleep_calls.append(ms)

        queue = SyncQueue(
            store=self.store, target=target, sleep_fn=tracking_sleep
        )
        queue.push(make_record(0))

        asyncio.get_event_loop().run_until_complete(queue.close("run_001"))

        # Should have retried CLOSE_MAX_RETRIES times with backoff
        assert len(sleep_calls) == CLOSE_MAX_RETRIES
        assert sleep_calls[0] == 1000
        assert sleep_calls[1] == 2000
        assert sleep_calls[2] == 4000
        assert sleep_calls[3] == 8000
        assert sleep_calls[4] == 16000

        # Run should be auto_closed
        run = self.store.get_process_run("run_001")
        assert run is not None
        assert run["state"] == "auto_closed"

        # api_unavailable gap should exist
        gaps = self.store.get_gaps("run_001")
        api_gap = next((g for g in gaps if g["gap_type"] == "api_unavailable"), None)
        assert api_gap is not None
        assert api_gap["severity"] == "High"

    def test_mode1_close_succeeds_when_api_available(self) -> None:
        open_default_run(self.store)
        target = MockSyncTarget("succeed")
        queue = SyncQueue(store=self.store, target=target, sleep_fn=instant_sleep)
        queue.push(make_record(0))

        asyncio.get_event_loop().run_until_complete(queue.close("run_001"))

        run = self.store.get_process_run("run_001")
        assert run is not None
        assert run["state"] == "closed"
        assert len(target.sent) >= 1

    # ── MUST PASS: Mode 2 — Signer unavailable does not throw ──

    def test_mode2_push_succeeds_with_signer_unavailable(self) -> None:
        open_default_run(self.store)
        queue = SyncQueue(store=self.store, target=None)
        queue.mark_subsystem_down("signer_available")

        queue.push(make_record(0))

        assert queue.get_buffer_size() == 1
        assert queue.get_degraded_status()["signer_available"] is False

        records = self.store.get_check_records("run_001")
        assert len(records) == 1

    # ── MUST PASS: Mode 3 — Prover failure does not block VPEC issuance ──

    def test_mode3_prover_failure_does_not_block(self) -> None:
        open_default_run(self.store)
        queue = SyncQueue(store=self.store, target=None)
        queue.mark_subsystem_down("zk_prover_available")

        record = make_record(0, "run_001", proof_pending=True)
        queue.push(record)

        assert queue.get_buffer_size() == 1
        stored = self.store.get_check_records("run_001")
        assert len(stored) == 1
        assert stored[0]["proof_pending"] is True

    def test_mode3_zkml_proof_pending_when_ezkl_unavailable(self) -> None:
        open_default_run(self.store)
        queue = SyncQueue(store=self.store, target=None)
        queue.mark_subsystem_down("zkml_prover_available")

        record = make_record(0, "run_001", zkml_proof_pending=True)
        queue.push(record)

        stored = self.store.get_check_records("run_001")
        assert len(stored) == 1
        assert stored[0]["zkml_proof_pending"] is True

    # ── MUST PASS: Mode 4 — Adapter failure does not throw ──

    def test_mode4_adapter_failure_inserts_gap_no_throw(self) -> None:
        open_default_run(self.store)

        gap = {
            "gap_id": "gap_adapter_001",
            "run_id": "run_001",
            "gap_type": "check_not_executed",
            "severity": "High",
            "state": "open",
            "details": {"check_id": "check_001", "reason": "adapter_timeout"},
            "detected_at": "2026-03-10T00:00:00Z",
            "resolved_at": None,
        }

        # Must not raise
        self.store.insert_gap(gap)

        gaps = self.store.get_gaps("run_001")
        assert len(gaps) == 1
        assert gaps[0]["gap_type"] == "check_not_executed"

    # ── MUST PASS: Mode 5 — Pipeline TTL ──

    def test_mode5_auto_closes_run_after_ttl(self) -> None:
        open_default_run(self.store)
        queue = SyncQueue(store=self.store, target=None)

        # Use threading.Timer path (no running event loop)
        queue.start_pipeline_ttl("run_001", 1)

        # Wait for timer to fire
        time.sleep(1.5)

        run = self.store.get_process_run("run_001")
        assert run is not None
        assert run["state"] == "auto_closed"

    # ── Queue mechanics ──

    def test_drops_oldest_when_exceeding_capacity(self) -> None:
        open_default_run(self.store)
        dropped: list[str] = []

        def on_dropped(record: dict[str, Any], reason: str) -> None:
            dropped.append(f"{record['record_id']}:{reason}")

        queue = SyncQueue(
            store=self.store,
            target=None,
            callbacks=SyncQueueCallbacks(on_record_dropped=on_dropped),
        )

        for i in range(QUEUE_MAX_RECORDS):
            queue.push(make_record(i))
        assert queue.get_buffer_size() == QUEUE_MAX_RECORDS

        queue.push(make_record(QUEUE_MAX_RECORDS))
        assert queue.get_buffer_size() == QUEUE_MAX_RECORDS
        assert len(dropped) == 1
        assert "capacity_overflow" in dropped[0]

    def test_drops_records_exceeding_ttl(self) -> None:
        open_default_run(self.store)
        dropped: list[str] = []

        def on_dropped(record: dict[str, Any], reason: str) -> None:
            dropped.append(f"{record['record_id']}:{reason}")

        queue = SyncQueue(
            store=self.store,
            target=None,
            callbacks=SyncQueueCallbacks(on_record_dropped=on_dropped),
        )

        queue.push(make_record(0))
        assert queue.get_buffer_size() == 1

        # Simulate time passing beyond TTL by patching time.monotonic
        original = time.monotonic()
        with patch("time.monotonic", return_value=original + QUEUE_RECORD_TTL_MS / 1000 + 1):
            queue.push(make_record(1))

        assert len(dropped) == 1
        assert "ttl_expired" in dropped[0]

    def test_flush_sends_and_clears_buffer(self) -> None:
        open_default_run(self.store)
        target = MockSyncTarget("succeed")
        queue = SyncQueue(store=self.store, target=target, sleep_fn=instant_sleep)

        queue.mark_subsystem_down("api_available")
        queue.push(make_record(0))
        queue.push(make_record(1))
        queue.mark_subsystem_up("api_available")

        assert queue.get_buffer_size() == 2

        count = asyncio.get_event_loop().run_until_complete(queue.flush())
        assert count == 2
        assert queue.get_buffer_size() == 0
        assert len(target.sent) == 1
        assert len(target.sent[0]) == 2

    def test_flush_retains_buffer_on_retryable_failure(self) -> None:
        open_default_run(self.store)
        target = MockSyncTarget("fail_retryable")
        queue = SyncQueue(store=self.store, target=target, sleep_fn=instant_sleep)

        queue.mark_subsystem_down("api_available")
        queue.push(make_record(0))
        queue.mark_subsystem_up("api_available")

        count = asyncio.get_event_loop().run_until_complete(queue.flush())
        assert count == 0
        assert queue.get_buffer_size() == 1  # retained

    # ── Degraded status ──

    def test_is_fully_operational_true_when_all_up(self) -> None:
        target = MockSyncTarget("succeed")
        queue = SyncQueue(store=self.store, target=target)
        assert queue.is_fully_operational() is True

    def test_is_fully_operational_false_when_any_down(self) -> None:
        target = MockSyncTarget("succeed")
        queue = SyncQueue(store=self.store, target=target)

        queue.mark_subsystem_down("zk_prover_available")
        assert queue.is_fully_operational() is False

        queue.mark_subsystem_up("zk_prover_available")
        assert queue.is_fully_operational() is True

    def test_mark_subsystem_toggle(self) -> None:
        queue = SyncQueue(store=self.store, target=None)

        queue.mark_subsystem_down("signer_available")
        assert queue.get_degraded_status()["signer_available"] is False

        queue.mark_subsystem_up("signer_available")
        assert queue.get_degraded_status()["signer_available"] is True

    # ── Close with no target ──

    def test_close_succeeds_with_no_target(self) -> None:
        open_default_run(self.store)
        queue = SyncQueue(store=self.store, target=None)

        asyncio.get_event_loop().run_until_complete(queue.close("run_001"))

        run = self.store.get_process_run("run_001")
        assert run is not None
        assert run["state"] == "closed"

    # ── Pipeline TTL cancellation ──

    def test_close_cancels_pipeline_ttl(self) -> None:
        open_default_run(self.store)
        queue = SyncQueue(store=self.store, target=None)

        queue.start_pipeline_ttl("run_001", 10)
        asyncio.get_event_loop().run_until_complete(queue.close("run_001"))

        # Wait a bit — should NOT auto-close again
        time.sleep(0.5)

        run = self.store.get_process_run("run_001")
        assert run is not None
        assert run["state"] == "closed"  # not auto_closed
