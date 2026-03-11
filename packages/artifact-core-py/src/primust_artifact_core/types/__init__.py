"""Primust artifact type definitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

# ── Signer / signature types (originally in types.py, now merged here) ──

KeyStatus = Literal["active", "rotated", "revoked"]
RevocationReason = Literal["key_compromise", "decommissioned"]
SignerType = Literal["artifact_signer", "manifest_signer", "policy_pack_signer"]


@dataclass(frozen=True)
class SignerRecord:
    """One record per kid. A signer_id may have multiple SignerRecords."""

    signer_id: str
    kid: str
    public_key_b64url: str
    algorithm: Literal["Ed25519"] = "Ed25519"
    status: KeyStatus = "active"
    revocation_reason: Optional[RevocationReason] = None
    revoked_at: Optional[str] = None
    superseded_by_kid: Optional[str] = None
    activated_at: str = ""
    deactivated_at: Optional[str] = None
    org_id: str = ""
    signer_type: SignerType = "artifact_signer"


@dataclass(frozen=True)
class SignatureEnvelope:
    """Attached to every signed Primust artifact. Both signer_id and kid required."""

    signer_id: str
    kid: str
    algorithm: Literal["Ed25519"]
    signature: str  # base64url-encoded Ed25519 signature
    signed_at: str  # ISO 8601


# ── Artifact types ──

from primust_artifact_core.types.artifact import (
    VPECArtifact,
    SurfaceEntry,
    ProofDistribution,
    Coverage,
    GapEntry,
    ZkProof,
    ArtifactIssuer,
    ArtifactSignature,
    TimestampAnchor,
    TransparencyLog,
    PendingFlags,
)

__all__ = [
    "KeyStatus",
    "RevocationReason",
    "SignerType",
    "SignerRecord",
    "SignatureEnvelope",
    "VPECArtifact",
    "SurfaceEntry",
    "ProofDistribution",
    "Coverage",
    "GapEntry",
    "ZkProof",
    "ArtifactIssuer",
    "ArtifactSignature",
    "TimestampAnchor",
    "TransparencyLog",
    "PendingFlags",
]
