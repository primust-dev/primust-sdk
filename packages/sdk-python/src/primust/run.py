"""
Primust SDK — Run context.

A Run is opened by Pipeline.open() and closed by run.close() → VPEC.
All record() calls happen on a Run.

INVARIANT: Raw input is committed locally via primust_artifact_core.commit()
before any data is handed to the transport layer. The transport layer
receives only commitment hashes, never raw values.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import threading
import time
import uuid
from typing import Any, Optional, Union

from primust_artifact_core import commit

from .models import (
    CheckResult,
    CheckSession,
    GovernanceGap,
    LoggerOptions,
    PrimustLogEvent,
    ProofLevel,
    ProofLevelBreakdown,
    RecordResult,
    ReviewSession,
    VPEC,
    VisibilityMode,
)
from .transport import PrimustTransport

log = logging.getLogger("primust.run")

_VPEC_POLL_INTERVAL = 1.5   # seconds between polls
_VPEC_POLL_TIMEOUT = 30.0   # give up after this many seconds


def _to_bytes(value: Any) -> bytes:
    """Convert a value to bytes for commitment hashing."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class Run:
    """
    A governed process run. Opened by Pipeline.open().

    Usage:
        run = pipeline.open()
        result = run.record(check="pii_scan", manifest_id="...",
                            input=content, check_result="pass")
        vpec = run.close()
    """

    def __init__(
        self,
        run_id: str,
        workflow_id: str,
        org_id: str,
        policy_snapshot_hash: str,
        transport: PrimustTransport,
        test_mode: bool,
        logger_callback: Optional[Any] = None,
        logger_options: Optional[LoggerOptions] = None,
    ):
        self.run_id = run_id
        self.workflow_id = workflow_id
        self.org_id = org_id
        self.policy_snapshot_hash = policy_snapshot_hash
        self._transport = transport
        self._test_mode = test_mode
        self._closed = False
        self._lock = threading.Lock()
        self._record_ids: list[str] = []
        self._chain_hash = ""
        self._sequence = 0
        self._proof_levels: list[str] = []
        self._logger_callback = logger_callback
        self._logger_options = logger_options or LoggerOptions()

    # ------------------------------------------------------------------
    # run.record()
    # ------------------------------------------------------------------

    def record(
        self,
        check: str,
        manifest_id: str,
        check_result: Union[str, CheckResult],
        input: Any,
        details: Optional[dict] = None,
        output: Optional[Any] = None,
        visibility: str = "opaque",
        check_session: Optional[Union[CheckSession, ReviewSession]] = None,
        reviewer_signature: Optional[str] = None,
        display_content: Optional[Any] = None,
        rationale: Optional[str] = None,
    ) -> RecordResult:
        """
        Record a governance check execution.

        INVARIANT: `input` and `output` are committed locally before
        anything leaves this process. Neither value is transmitted to
        api.primust.com — only the commitment hashes are.
        """
        with self._lock:
            if self._closed:
                raise RuntimeError("Cannot record on a closed Run.")

            record_id = f"rec_{uuid.uuid4().hex}"
            sequence = self._sequence
            self._sequence += 1
            recorded_at = datetime.datetime.utcnow().isoformat() + "Z"

            # ── LOCAL COMMITMENT — raw input never leaves ──
            # Explicit SHA-256 default: not contingent on artifact-core package default.
            # Poseidon2 opt-in via PRIMUST_COMMITMENT_ALGORITHM=poseidon2 env var.
            # TODO: Wire Poseidon2 commitment to Noir circuit output. Currently falls back to
            # SHA256. See poseidon2 test failures in sdk-python, langgraph, openai-agents, google-adk.
            _alg = os.environ.get("PRIMUST_COMMITMENT_ALGORITHM", "sha256")
            input_bytes = _to_bytes(input)
            input_commitment, algorithm = commit(input_bytes, _alg)

            output_commitment = None
            if output is not None:
                output_bytes = _to_bytes(output)
                output_commitment, _ = commit(output_bytes, _alg)

            display_hash = None
            if display_content is not None:
                dh, _ = commit(_to_bytes(display_content), _alg)
                display_hash = dh

            rationale_hash = None
            if rationale is not None:
                rh, _ = commit(rationale.encode("utf-8"), _alg)
                rationale_hash = rh
            # ──────────────────────────────────────────────

            # Rolling chain hash for chain integrity
            chain_input = f"{self._chain_hash}|{record_id}|{input_commitment}|{sequence}"
            self._chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()

            proof_level = self._estimate_proof_level(check_session, reviewer_signature)

            # Build envelope — ONLY hashes and metadata, never raw values
            envelope: dict[str, Any] = {
                "record_id": record_id,
                "run_id": self.run_id,
                "manifest_id": manifest_id,
                "check": check,
                "sequence": sequence,
                "check_result": check_result if isinstance(check_result, str) else check_result.value,
                "commitment_hash": input_commitment,
                "commitment_algorithm": algorithm,
                "commitment_type": "input_commitment",
                "proof_level_achieved": proof_level,
                "idempotency_key": f"idem_{uuid.uuid4().hex[:16]}",
                "visibility": visibility,
                "chain_hash": self._chain_hash,
                "recorded_at": recorded_at,
            }

            if output_commitment:
                envelope["output_commitment"] = output_commitment
            if details:
                envelope["details"] = details
            if display_hash:
                envelope["display_hash"] = display_hash
            if rationale_hash:
                envelope["rationale_hash"] = rationale_hash
            if check_session is not None:
                envelope["check_open_tst"] = check_session.open_tst
                # session_id is a banned field in the API — do not send it
                if isinstance(check_session, ReviewSession):
                    envelope["reviewer_credential"] = {
                        "reviewer_key_id": check_session.reviewer_key_id,
                        "key_binding": "software",
                        "role": "reviewer",
                        "org_credential_ref": None,
                        "reviewer_signature": reviewer_signature or "",
                        "display_hash": display_hash or "",
                        "rationale_hash": rationale_hash or "",
                        "signed_content_hash": input_commitment,
                        "open_tst": check_session.open_tst or "",
                        "close_tst": recorded_at,
                    }

            self._proof_levels.append(proof_level)

            # Logger callback — called synchronously after commitment_hash
            # computed, before ObservationEnvelope sent to API.
            if self._logger_callback is not None:
                event = PrimustLogEvent(
                    primust_record_id=record_id,
                    primust_commitment_hash=input_commitment,
                    primust_check_result=check_result if isinstance(check_result, str) else check_result.value,
                    primust_proof_level=proof_level,
                    primust_workflow_id=self.workflow_id,
                    primust_run_id=self.run_id,
                    primust_recorded_at=recorded_at,
                )
                try:
                    self._logger_callback(event)
                except Exception:
                    log.warning("Logger callback raised an exception — suppressed", exc_info=True)

            # ── TRANSMIT — only the envelope (no raw data) ──
            response = self._transport.post_record(self.run_id, envelope)
            queued = response is None
            # ──────────────────────────────────────────────

            server_proof_level = proof_level
            if response and "proof_level" in response:
                server_proof_level = response["proof_level"]

            result = RecordResult(
                record_id=record_id,
                commitment_hash=input_commitment,
                output_commitment=output_commitment,
                commitment_algorithm=algorithm,
                proof_level=server_proof_level,
                recorded_at=recorded_at,
                chain_hash=self._chain_hash,
                queued=queued,
            )

            self._record_ids.append(record_id)
            return result

    # ------------------------------------------------------------------
    # run.open_check() — timed check sessions
    # ------------------------------------------------------------------

    def open_check(self, check: str, manifest_id: str) -> CheckSession:
        """Open a timed check session."""
        session_id = f"cs_{uuid.uuid4().hex}"
        opened_at = datetime.datetime.utcnow().isoformat() + "Z"
        import base64
        stub = json.dumps({"session_id": session_id, "ts": opened_at, "source": "local_stub"})
        open_tst = base64.b64encode(stub.encode()).decode()
        return CheckSession(
            session_id=session_id,
            check=check,
            manifest_id=manifest_id,
            open_tst=open_tst,
            opened_at=opened_at,
        )

    # ------------------------------------------------------------------
    # run.open_review() — Witnessed level human review
    # ------------------------------------------------------------------

    def open_review(
        self,
        check: str,
        manifest_id: str,
        reviewer_key_id: str,
        min_duration_seconds: int = 0,
    ) -> ReviewSession:
        """Open a Witnessed level review session."""
        session_id = f"rv_{uuid.uuid4().hex}"
        opened_at = datetime.datetime.utcnow().isoformat() + "Z"
        import base64
        stub = json.dumps({"session_id": session_id, "ts": opened_at, "source": "local_stub"})
        open_tst = base64.b64encode(stub.encode()).decode()
        return ReviewSession(
            session_id=session_id,
            check=check,
            manifest_id=manifest_id,
            reviewer_key_id=reviewer_key_id,
            min_duration_seconds=min_duration_seconds,
            open_tst=open_tst,
            opened_at=opened_at,
        )

    # ------------------------------------------------------------------
    # run.close() → VPEC
    # ------------------------------------------------------------------

    def close(self) -> VPEC:
        """
        Close the run and request VPEC issuance.
        After close(), no further records can be added.
        """
        with self._lock:
            if self._closed:
                raise RuntimeError("Run already closed.")
            self._closed = True

        closed_at = datetime.datetime.utcnow().isoformat() + "Z"
        overall_proof_level = self._weakest_link_proof_level()

        close_payload = {
            "run_id": self.run_id,
            "record_ids": self._record_ids,
            "final_chain_hash": self._chain_hash,
            "closed_at": closed_at,
            "record_count": len(self._record_ids),
        }

        response = self._transport.post_close_run(self.run_id, close_payload)

        if response is None:
            log.warning("VPEC issuance queued — API was unreachable.")
            return self._pending_vpec(closed_at, overall_proof_level)

        vpec_data = self._poll_for_vpec(response)
        return self._parse_vpec(vpec_data, overall_proof_level)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _weakest_link_proof_level(self) -> str:
        """Weakest-link rule: overall level is the lowest proof level seen."""
        order = [
            ProofLevel.ATTESTATION.value,
            ProofLevel.WITNESSED.value,
            ProofLevel.EXECUTION.value,
            ProofLevel.VERIFIABLE_INFERENCE.value,
            ProofLevel.MATHEMATICAL.value,
        ]
        if not self._proof_levels:
            return ProofLevel.ATTESTATION.value
        for level in order:
            if level in self._proof_levels:
                return level
        return ProofLevel.ATTESTATION.value

    def _estimate_proof_level(
        self,
        check_session: Optional[Union[CheckSession, ReviewSession]],
        reviewer_signature: Optional[str],
    ) -> str:
        """Local estimate pending server authoritative response."""
        if isinstance(check_session, ReviewSession) or reviewer_signature:
            return ProofLevel.WITNESSED.value
        return ProofLevel.ATTESTATION.value

    def _poll_for_vpec(self, initial_response: dict) -> dict:
        """Extract VPEC from close response."""
        # API returns VPEC at top level (vpec_id is the marker)
        if "vpec_id" in initial_response:
            return initial_response
        # Legacy wrapper format
        if "vpec" in initial_response:
            return initial_response["vpec"]

        deadline = time.monotonic() + _VPEC_POLL_TIMEOUT
        while time.monotonic() < deadline:
            time.sleep(_VPEC_POLL_INTERVAL)
            result = self._transport.get_vpec(self.run_id)
            if result:
                return result

        log.warning("VPEC poll timed out — returning close response as stub")
        return initial_response

    def _pending_vpec(self, closed_at: str, proof_level: str) -> VPEC:
        return VPEC(
            vpec_id=f"vpec_pending_{self.run_id}",
            run_id=self.run_id,
            workflow_id=self.workflow_id,
            org_id=self.org_id,
            issued_at=closed_at,
            proof_level_floor=proof_level,
            provable_surface=0.0,
            provable_surface_breakdown=ProofLevelBreakdown(),
            total_checks_run=len(self._record_ids),
            checks_passed=0,
            checks_failed=0,
            gaps=[GovernanceGap(
                gap_id=f"gap_{uuid.uuid4().hex}",
                gap_type="system_unavailable",
                severity="high",
                timestamp=closed_at,
            )],
            chain_intact=True,
            merkle_root="",
            signature="",
            timestamp_rfc3161="",
            environment="sandbox" if self._test_mode else "production",
            raw={"status": "pending", "run_id": self.run_id},
        )

    def _parse_vpec(self, data: dict, local_proof_level: str) -> VPEC:
        breakdown_raw = data.get("provable_surface_breakdown", {})
        breakdown = ProofLevelBreakdown(
            mathematical=breakdown_raw.get("mathematical", 0.0),
            verifiable_inference=breakdown_raw.get("verifiable_inference", 0.0),
            execution=breakdown_raw.get("execution", 0.0),
            witnessed=breakdown_raw.get("witnessed", 0.0),
            attestation=breakdown_raw.get("attestation", 0.0),
        )

        gaps_raw = data.get("gaps", [])
        gaps = [
            GovernanceGap(
                gap_id=g.get("gap_id", ""),
                gap_type=g.get("gap_type", ""),
                severity=g.get("severity", ""),
                check=g.get("check"),
                sequence=g.get("sequence"),
                timestamp=g.get("timestamp", ""),
            )
            for g in gaps_raw
        ]

        coverage = data.get("coverage", {})
        total_checks = coverage.get("records_total", data.get("total_checks_run", len(self._record_ids)))
        checks_passed = coverage.get("records_pass", data.get("checks_passed", 0))
        checks_failed = coverage.get("records_fail", data.get("checks_failed", 0))
        provable_surface = coverage.get("provable_surface", data.get("provable_surface", 0.0))

        return VPEC(
            vpec_id=data.get("vpec_id", f"vpec_{self.run_id}"),
            run_id=self.run_id,
            workflow_id=self.workflow_id,
            org_id=data.get("org_id", self.org_id),
            issued_at=data.get("issued_at", ""),
            proof_level_floor=data.get("proof_level_floor", local_proof_level),
            provable_surface=provable_surface,
            provable_surface_breakdown=breakdown,
            total_checks_run=total_checks,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
            gaps=gaps,
            chain_intact=data.get("chain_intact", True),
            merkle_root=data.get("merkle_root", ""),
            signature=data.get("signature", ""),
            timestamp_rfc3161=data.get("timestamp_rfc3161", ""),
            environment="sandbox" if self._test_mode else "production",
            provable_surface_pending=data.get("provable_surface_pending", 0.0),
            provable_surface_ungoverned=data.get("provable_surface_ungoverned", 0.0),
            provable_surface_basis=data.get("provable_surface_basis", "executed_records"),
            provable_surface_suppressed=data.get("provable_surface_suppressed", False),
            raw=data,
        )
