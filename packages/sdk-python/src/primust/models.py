"""
Primust SDK — Data models.

All types returned by the public API surface.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class CheckResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    SKIPPED = "skipped"
    DEGRADED = "degraded"
    OVERRIDE = "override"
    NOT_APPLICABLE = "not_applicable"


class ProofLevel(str, Enum):
    MATHEMATICAL = "mathematical"
    VERIFIABLE_INFERENCE = "verifiable_inference"
    EXECUTION = "execution"
    WITNESSED = "witnessed"
    ATTESTATION = "attestation"


class VisibilityMode(str, Enum):
    TRANSPARENT = "transparent"
    SELECTIVE = "selective"
    OPAQUE = "opaque"


@dataclass
class RecordResult:
    """Returned by run.record(). Write commitment_hash to your own logs."""
    record_id: str
    commitment_hash: str          # log linkage anchor — write to operational logs
    output_commitment: Optional[str]
    commitment_algorithm: str     # "sha256" | "poseidon2"
    proof_level: str
    recorded_at: str
    chain_hash: str = ""
    queued: bool = False          # True if API was unreachable — will flush


@dataclass
class CheckSession:
    """Returned by run.open_check(). Provides RFC 3161 timestamp at check open."""
    session_id: str
    check: str
    manifest_id: str
    open_tst: str                 # RFC 3161 timestamp token (base64)
    opened_at: str


@dataclass
class ReviewSession:
    """Returned by run.open_review(). Witnessed level — human review."""
    session_id: str
    check: str
    manifest_id: str
    reviewer_key_id: str
    min_duration_seconds: int
    open_tst: str                 # RFC 3161 timestamp — review start
    opened_at: str


@dataclass
class ManifestRegistration:
    """Returned by pipeline.register_check()."""
    manifest_id: str              # sha256 content-addressed
    name: str
    registered_at: str


@dataclass
class PrimustLogEvent:
    """
    Passed to the logger callback on every record() call.
    All fields namespaced primust_* to avoid collision in customer logs.
    No content fields. Only governance metadata.
    """
    primust_record_id: str
    primust_commitment_hash: str       # poseidon2:hex — linkage anchor
    primust_check_result: str          # pass|fail|error|etc.
    primust_proof_level: str           # mathematical|execution|etc.
    primust_workflow_id: str
    primust_run_id: str
    primust_recorded_at: str           # ISO 8601
    gap_types_emitted: Optional[list[str]] = None  # only if include_gap_types


@dataclass
class LoggerOptions:
    """Options for Pipeline.set_logger()."""
    include_gap_types: bool = False


@dataclass
class ProofLevelBreakdown:
    mathematical: int = 0
    verifiable_inference: int = 0
    execution: int = 0
    witnessed: int = 0
    attestation: int = 0


@dataclass
class GovernanceGap:
    gap_id: str
    gap_type: str
    severity: str
    check: Optional[str] = None
    sequence: Optional[int] = None
    timestamp: str = ""


@dataclass
class VPEC:
    """
    Verifiable Process Execution Credential.

    The artifact produced by run.close(). Portable, offline-verifiable.
    Verify with: primust-verify vpec.json
    """
    vpec_id: str
    run_id: str
    workflow_id: str
    org_id: str
    issued_at: str
    proof_level: str              # weakest-link across all checks
    proof_level_breakdown: ProofLevelBreakdown
    coverage_verified_pct: float
    total_checks_run: int
    checks_passed: int
    checks_failed: int
    governance_gaps: list[GovernanceGap]
    chain_intact: bool
    merkle_root: str
    signature: str                # Ed25519 over credential body
    timestamp_rfc3161: str        # RFC 3161 anchor
    test_mode: bool = False       # True when api_key starts with pk_test_
    raw: dict = field(default_factory=dict)  # full JSON for offline verification

    def to_dict(self) -> dict:
        return self.raw

    def gaps_count(self) -> int:
        return len(self.governance_gaps)

    def is_clean(self) -> bool:
        return self.chain_intact and self.gaps_count() == 0
