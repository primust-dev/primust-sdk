"""
Primust SDK — HTTP transport layer.

Wraps api.primust.com. Handles:
  - Auth (X-API-Key header)
  - Retries with exponential backoff (3 attempts)
  - Queue flush on successful reconnect

CRITICAL: The transport layer never receives raw input values.
Commitment hashes only. Enforced by the Run/Pipeline layer above this.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Optional

import httpx

from .queue import LocalQueue

log = logging.getLogger("primust.transport")

_BASE_URL = "https://api.primust.com/api/v1"
_TIMEOUT = 10.0
_MAX_RETRIES = 3
_RETRY_BACKOFF = [0.5, 1.0, 2.0]


class PrimustTransport:

    def __init__(self, api_key: str, queue: LocalQueue, base_url: str = _BASE_URL):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.queue = queue
        self.test_mode = api_key.startswith("pk_test_") or api_key.startswith("pk_sb_")
        self._headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json",
            "X-Primust-SDK": "python/0.1.0",
        }

    # ------------------------------------------------------------------
    # Public API (called by Run / Pipeline)
    # ------------------------------------------------------------------

    def post_record(self, run_id: str, payload: dict) -> Optional[dict]:
        """
        POST a check execution record envelope to the API.
        INVARIANT: payload must not contain raw input — only commitment hashes.
        Returns API response dict, or None if queued for later.
        """
        endpoint = f"/runs/{run_id}/records"
        return self._post_with_fallback(endpoint, payload, queue_table="record", run_id=run_id)

    def post_open_run(self, payload: dict) -> dict:
        """Open a process run. Required before any records can be posted."""
        return self._post_required("/runs", payload)

    def post_close_run(self, run_id: str, payload: dict) -> Optional[dict]:
        """Close a run and request VPEC issuance."""
        endpoint = f"/runs/{run_id}/close"
        return self._post_with_fallback(endpoint, payload, queue_table="close", run_id=run_id)

    def post_manifest(self, payload: dict) -> dict:
        """Register a check manifest. Required once per manifest version."""
        return self._post_required("/manifests", payload)

    def get_vpec(self, run_id: str) -> Optional[dict]:
        """Poll for a completed VPEC. Returns None if still pending."""
        try:
            with httpx.Client(timeout=_TIMEOUT) as client:
                resp = client.get(
                    f"{self.base_url}/runs/{run_id}/vpec",
                    headers=self._headers,
                )
                if resp.status_code == 202:
                    return None  # still pending
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as e:
            log.warning("get_vpec failed: %s", e)
            return None

    def flush_queue(self) -> int:
        """
        Attempt to flush all queued records and closes.
        Returns number of items successfully flushed.
        """
        flushed = 0
        for item in self.queue.pending_records():
            try:
                with httpx.Client(timeout=_TIMEOUT) as client:
                    resp = client.post(
                        f"{self.base_url}{item['endpoint']}",
                        json=item["payload"],
                        headers=self._headers,
                    )
                    resp.raise_for_status()
                self.queue.delete_record(item["id"])
                flushed += 1
            except httpx.HTTPError:
                self.queue.increment_attempts("queued_records", item["id"])

        for item in self.queue.pending_closes():
            try:
                run_id = item["run_id"]
                with httpx.Client(timeout=_TIMEOUT) as client:
                    resp = client.post(
                        f"{self.base_url}/runs/{run_id}/close",
                        json=item["payload"],
                        headers=self._headers,
                    )
                    resp.raise_for_status()
                self.queue.delete_close(item["id"])
                flushed += 1
            except httpx.HTTPError:
                self.queue.increment_attempts("queued_closes", item["id"])

        return flushed

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _post_required(self, endpoint: str, payload: dict) -> dict:
        """POST that must succeed — no queue fallback. Used for run open and manifests."""
        last_exc = None
        for attempt, backoff in enumerate(_RETRY_BACKOFF):
            try:
                with httpx.Client(timeout=_TIMEOUT) as client:
                    resp = client.post(
                        f"{self.base_url}{endpoint}",
                        json=payload,
                        headers=self._headers,
                    )
                    resp.raise_for_status()
                    return resp.json()
            except httpx.HTTPError as e:
                last_exc = e
                if attempt < len(_RETRY_BACKOFF) - 1:
                    time.sleep(backoff)
        raise ConnectionError(
            f"Primust API unreachable at {self.base_url}{endpoint} "
            f"after {_MAX_RETRIES} attempts: {last_exc}"
        )

    def _post_with_fallback(
        self, endpoint: str, payload: dict, queue_table: str, run_id: str
    ) -> Optional[dict]:
        """POST that falls back to local queue if API is unreachable."""
        for attempt, backoff in enumerate(_RETRY_BACKOFF):
            try:
                with httpx.Client(timeout=_TIMEOUT) as client:
                    resp = client.post(
                        f"{self.base_url}{endpoint}",
                        json=payload,
                        headers=self._headers,
                    )
                    resp.raise_for_status()
                    # Successful — attempt queue flush in case items built up
                    if self.queue.count() > 0:
                        self.flush_queue()
                    return resp.json()
            except httpx.HTTPError as e:
                log.warning("API unavailable (attempt %d): %s", attempt + 1, e)
                if attempt < len(_RETRY_BACKOFF) - 1:
                    time.sleep(backoff)

        # All retries exhausted — queue locally
        log.warning("Queuing record locally. Will flush when API recovers.")
        if queue_table == "record":
            self.queue.enqueue_record(run_id, endpoint, payload)
        else:
            self.queue.enqueue_close(run_id, payload)
        return None
