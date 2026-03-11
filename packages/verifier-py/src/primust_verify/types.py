"""primust-verify — Types for offline verifier."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional


RekorStatus = Literal["clean", "revoked", "unavailable", "skipped"]


@dataclass
class VerifyOptions:
    """Options for verify()."""

    production: bool = False
    skip_network: bool = False
    trust_root: Optional[str] = None


@dataclass
class VerificationResult:
    """Result of verifying a VPEC artifact."""

    vpec_id: str = ""
    valid: bool = False
    schema_version: str = ""
    proof_level: str = ""
    proof_distribution: dict[str, Any] = field(default_factory=dict)
    org_id: str = ""
    workflow_id: str = ""
    process_context_hash: Optional[str] = None
    partial: bool = False
    test_mode: bool = False
    signer_id: str = ""
    kid: str = ""
    signed_at: str = ""
    timestamp_anchor_valid: Optional[bool] = None
    rekor_status: RekorStatus = "skipped"
    zk_proof_valid: Optional[bool] = None
    manifest_hashes: dict[str, str] = field(default_factory=dict)
    gaps: list[dict[str, str]] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict."""
        return {
            "vpec_id": self.vpec_id,
            "valid": self.valid,
            "schema_version": self.schema_version,
            "proof_level": self.proof_level,
            "proof_distribution": self.proof_distribution,
            "org_id": self.org_id,
            "workflow_id": self.workflow_id,
            "process_context_hash": self.process_context_hash,
            "partial": self.partial,
            "test_mode": self.test_mode,
            "signer_id": self.signer_id,
            "kid": self.kid,
            "signed_at": self.signed_at,
            "timestamp_anchor_valid": self.timestamp_anchor_valid,
            "rekor_status": self.rekor_status,
            "zk_proof_valid": self.zk_proof_valid,
            "manifest_hashes": self.manifest_hashes,
            "gaps": self.gaps,
            "coverage": self.coverage,
            "errors": self.errors,
            "warnings": self.warnings,
        }
