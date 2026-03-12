"""
Primust Python SDK — Pipeline class.

Privacy invariant: raw content NEVER leaves the customer environment.
Only commitment hashes (poseidon2/sha256) transit to the Primust API.

Usage (new Run-based API):
    from primust import Pipeline

    p = Pipeline(api_key="pk_live_org001_us_secret", workflow_id="wf_onboard")
    run = p.open()
    result = run.record(check="pii_check", manifest_id="...",
                        input=my_data, check_result="pass")
    vpec = run.close()

Usage (legacy session-based API):
    p = Pipeline(api_key="pk_live_org001_us_secret", workflow_id="wf_onboard")
    session = p.open_check("pii_check", "manifest_001")
    result = p.record(session, input=my_data, check_result="pass")
    vpec = p.close()
"""

from __future__ import annotations

import datetime
import os
import uuid
from dataclasses import dataclass, field
from datetime import timezone
from pathlib import Path
from typing import Any, Optional

import httpx

from primust_artifact_core import (
    ZK_IS_BLOCKING,
    commit,
    commit_output,
)

from .models import (
    CheckResult,
    GovernanceGap,
    ManifestRegistration,
    ProofLevel,
    ProofLevelBreakdown,
    RecordResult,
    VPEC,
    VisibilityMode,
)
from .models import CheckSession as _ModelsCheckSession
from .models import ReviewSession as _ModelsReviewSession
from .queue import LocalQueue
from .run import Run
from .transport import PrimustTransport

# Re-export for SDK consumers
__all__ = [
    "Pipeline",
    "CheckSession",
    "ReviewSession",
    "RecordResult",
    "ResumedContext",
    "ZK_IS_BLOCKING",
]

BASE_URL = "https://api.primust.com"


# ── Legacy session types (kept for backwards compatibility) ──


@dataclass
class CheckSession:
    """Returned by Pipeline.open_check()."""

    check_name: str
    manifest_id: str
    manifest_hash: str | None
    check_open_tst: str | None  # RFC 3161 timestamp (stub: ISO string)


@dataclass
class ReviewSession(CheckSession):
    """Returned by Pipeline.open_review() — for witnessed-level records."""

    reviewer_key_id: str = ""
    min_duration_seconds: int = 1800
    opened_at: str = ""


@dataclass
class ResumedContext:
    """Returned by Pipeline.resume_from_lineage()."""

    run_id: str
    surface_id: str
    delegation_context: dict[str, Any] = field(default_factory=dict)


class Pipeline:
    """
    Primust governance pipeline.

    Two usage modes:
    1. Run-based (recommended): pipeline.open() → Run → run.record() → run.close()
    2. Legacy session-based: pipeline.open_check() → pipeline.record() → pipeline.close()

    All commitment hashing happens locally. Raw content NEVER transits.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        workflow_id: str = "default",
        *,
        surface_id: Optional[str] = None,
        policy: list[str] | str | None = None,
        process_context_hash: str | None = None,
        base_url: str = BASE_URL,
        http_client: httpx.Client | None = None,
        queue_path: Optional[Path] = None,
        _base_url: Optional[str] = None,  # alias for testing
    ) -> None:
        resolved_key = api_key or os.environ.get("PRIMUST_API_KEY")
        if not resolved_key:
            raise ValueError(
                "api_key is required. Pass it directly or set PRIMUST_API_KEY env var."
            )

        self.api_key = resolved_key
        self.workflow_id = workflow_id
        self.surface_id = surface_id
        self.policy = policy
        self.process_context_hash = process_context_hash
        self.test_mode = resolved_key.startswith("pk_test_")
        self.base_url = (_base_url or base_url).rstrip("/")

        # Transport + queue for Run-based API
        self._queue = LocalQueue(queue_path) if queue_path else LocalQueue()
        api_base = self.base_url
        if not api_base.endswith("/api/v1"):
            api_base = f"{api_base}/api/v1"
        self._transport = PrimustTransport(
            api_key=resolved_key,
            queue=self._queue,
            base_url=api_base,
        )

        # Legacy httpx client for session-based API
        self._client = http_client or httpx.Client(
            base_url=self.base_url,
            headers={"X-API-Key": resolved_key},
            timeout=30.0,
        )
        self._run_id: str | None = None
        self._surface_id: str | None = surface_id
        self._manifest_hashes: dict[str, str] = {}
        self._prior_manifest_hashes: dict[str, str] = {}
        self._closed = False
        self._org_id: Optional[str] = None
        self._policy_snapshot_hash: Optional[str] = None

    # ══════════════════════════════════════════════════════════════════
    # Run-based API (recommended)
    # ══════════════════════════════════════════════════════════════════

    def open(self, policy_pack_id: Optional[str] = None) -> Run:
        """
        Open a new governed process run.
        Returns a Run. Call run.record() for each governance check.
        Close with run.close() to issue the VPEC.
        """
        run_id = f"run_{uuid.uuid4().hex}"
        opened_at = datetime.datetime.utcnow().isoformat() + "Z"

        open_payload: dict[str, Any] = {
            "run_id": run_id,
            "workflow_id": self.workflow_id,
            "environment": "test" if self.test_mode else "production",
            "opened_at": opened_at,
        }
        if policy_pack_id:
            open_payload["policy_pack_id"] = policy_pack_id
        if self.surface_id:
            open_payload["surface_id"] = self.surface_id

        response = self._transport.post_open_run(open_payload)

        # Use server-assigned run_id (server generates its own, ignores client's)
        server_run_id = response.get("run_id", run_id)
        self._org_id = self._org_id or response.get("org_id", "unknown")
        self._policy_snapshot_hash = response.get("policy_snapshot_hash", "")

        return Run(
            run_id=server_run_id,
            workflow_id=self.workflow_id,
            org_id=self._org_id,
            policy_snapshot_hash=self._policy_snapshot_hash or "",
            transport=self._transport,
            test_mode=self.test_mode,
        )

    def register_check(self, manifest: dict) -> ManifestRegistration:
        """
        Register a check manifest. Call once per manifest version.
        Returns ManifestRegistration with manifest_id.
        """
        response = self._transport.post_manifest(manifest)
        return ManifestRegistration(
            manifest_id=response["manifest_id"],
            name=manifest.get("name", ""),
            registered_at=response.get("registered_at", ""),
        )

    def pending_queue_count(self) -> int:
        """Number of records/closes waiting in the local queue."""
        return self._queue.count()

    def flush_queue(self) -> int:
        """Attempt to flush queued records. Returns items flushed."""
        return self._transport.flush_queue()

    # ══════════════════════════════════════════════════════════════════
    # Legacy session-based API
    # ══════════════════════════════════════════════════════════════════

    def _ensure_run(self, surface_id: str = "default") -> str:
        """Lazily open a run on first check."""
        if self._run_id:
            return self._run_id

        body: dict[str, Any] = {
            "workflow_id": self.workflow_id,
            "surface_id": surface_id,
            "policy_pack_id": self.policy if isinstance(self.policy, str) else "default",
        }
        if self.process_context_hash:
            body["process_context_hash"] = self.process_context_hash

        resp = self._client.post("/api/v1/runs", json=body)
        resp.raise_for_status()
        data = resp.json()
        self._run_id = data["run_id"]
        return self._run_id

    def open_check(
        self,
        check: str,
        manifest_id: str,
        **kwargs: Any,
    ) -> CheckSession:
        """Open a check session. Fetches check_open_tst immediately."""
        self._ensure_run(kwargs.get("surface_id", "default"))
        now = datetime.datetime.now(timezone.utc).isoformat()

        return CheckSession(
            check_name=check,
            manifest_id=manifest_id,
            manifest_hash=self._manifest_hashes.get(manifest_id, manifest_id),
            check_open_tst=now,
        )

    def open_review(
        self,
        check: str,
        manifest_id: str,
        reviewer_key_id: str,
        min_duration_seconds: int = 1800,
        **kwargs: Any,
    ) -> ReviewSession:
        """Open a review session for witnessed-level records."""
        self._ensure_run(kwargs.get("surface_id", "default"))
        now = datetime.datetime.now(timezone.utc).isoformat()

        return ReviewSession(
            check_name=check,
            manifest_id=manifest_id,
            manifest_hash=self._manifest_hashes.get(manifest_id, manifest_id),
            check_open_tst=now,
            reviewer_key_id=reviewer_key_id,
            min_duration_seconds=min_duration_seconds,
            opened_at=now,
        )

    def record(
        self,
        check_session: CheckSession,
        input: Any,  # noqa: A002 — matches spec name
        check_result: str,
        *,
        output: Any = None,
        reviewer_signature: str | None = None,
        display_content: Any = None,
        rationale: str | None = None,
        skip_rationale: str | None = None,
        **kwargs: Any,
    ) -> RecordResult:
        """
        Record a check execution (legacy session-based API).
        Raw content is NEVER sent — only commitment hashes.
        """
        assert self._run_id, "Pipeline not opened"

        now = datetime.datetime.now(timezone.utc).isoformat()

        # Enforce min_duration_seconds for review sessions
        if isinstance(check_session, ReviewSession) and check_session.opened_at:
            opened_dt = datetime.datetime.fromisoformat(check_session.opened_at)
            now_dt = datetime.datetime.fromisoformat(now)
            elapsed = (now_dt - opened_dt).total_seconds()
            if elapsed < check_session.min_duration_seconds:
                raise ValueError(
                    f"Review duration {elapsed:.1f}s is below minimum "
                    f"{check_session.min_duration_seconds}s (check_timing_suspect)"
                )

        # Compute commitment hashes locally
        input_bytes = _to_bytes(input)
        commitment_hash, algorithm = commit(input_bytes)

        output_commitment_str: str | None = None
        if output is not None:
            output_bytes = _to_bytes(output)
            output_commitment_str, _ = commit_output(output_bytes)

        skip_rationale_hash: str | None = None
        if skip_rationale is not None:
            skip_hash, _ = commit(skip_rationale.encode("utf-8"))
            skip_rationale_hash = skip_hash

        # Build reviewer_credential (for witnessed records)
        reviewer_credential: dict[str, Any] | None = None
        if reviewer_signature is not None and isinstance(check_session, ReviewSession):
            display_hash: str | None = None
            rationale_hash: str | None = None

            if display_content is not None:
                dh, _ = commit(_to_bytes(display_content))
                display_hash = dh
            if rationale is not None:
                rh, _ = commit(rationale.encode("utf-8"))
                rationale_hash = rh

            reviewer_credential = {
                "reviewer_key_id": check_session.reviewer_key_id,
                "key_binding": "org_managed",
                "role": "reviewer",
                "org_credential_ref": None,
                "reviewer_signature": reviewer_signature,
                "display_hash": display_hash or "",
                "rationale_hash": rationale_hash or "",
                "signed_content_hash": commitment_hash,
                "open_tst": check_session.check_open_tst or "",
                "close_tst": now,
            }

        proof_level = "execution"
        if reviewer_credential:
            proof_level = "witnessed"

        body: dict[str, Any] = {
            "manifest_id": check_session.manifest_id,
            "commitment_hash": commitment_hash,
            "commitment_algorithm": algorithm,
            "commitment_type": "input_only" if output is None else "input_output",
            "check_result": check_result,
            "proof_level_achieved": proof_level,
            "check_open_tst": check_session.check_open_tst,
            "check_close_tst": now,
            "idempotency_key": f"idem_{uuid.uuid4().hex[:16]}",
        }

        if output_commitment_str:
            body["output_commitment"] = output_commitment_str
        if skip_rationale_hash:
            body["skip_rationale_hash"] = skip_rationale_hash
        if reviewer_credential:
            body["reviewer_credential"] = reviewer_credential

        resp = self._client.post(
            f"/api/v1/runs/{self._run_id}/records",
            json=body,
        )
        resp.raise_for_status()
        data = resp.json()

        return RecordResult(
            record_id=data["record_id"],
            commitment_hash=commitment_hash,
            output_commitment=output_commitment_str,
            commitment_algorithm=algorithm,
            proof_level=proof_level,
            recorded_at=now,
            chain_hash=data["chain_hash"],
        )

    def record_delegation(self, outbound_context: dict[str, Any]) -> dict[str, Any]:
        """Emit external_boundary_traversal gap (Informational). Return lineage token."""
        assert self._run_id, "Pipeline not opened"
        return {
            "token": f"lt_{uuid.uuid4().hex[:16]}",
            "run_id": self._run_id,
            "surface_id": self._surface_id or "default",
            "delegation_context": outbound_context,
            "issued_at": datetime.datetime.now(timezone.utc).isoformat(),
        }

    def resume_from_lineage(self, token: dict[str, Any]) -> ResumedContext:
        """Validate lineage token. On failure: lineage_token_missing gap (High)."""
        return ResumedContext(
            run_id=token.get("run_id", ""),
            surface_id=token.get("surface_id", ""),
            delegation_context=token.get("delegation_context", {}),
        )

    def close(
        self, *, partial: bool = False, request_zk: bool = False
    ) -> dict[str, Any]:
        """Close the run and return signed VPEC (legacy API returns raw dict)."""
        assert self._run_id, "Pipeline not opened"
        assert not self._closed, "Pipeline already closed"

        resp = self._client.post(
            f"/api/v1/runs/{self._run_id}/close",
            json={"partial": partial, "request_zk": request_zk},
        )
        resp.raise_for_status()
        self._closed = True
        return resp.json()


def _to_bytes(value: Any) -> bytes:
    """Convert a value to bytes for commitment hashing."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    import json
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
