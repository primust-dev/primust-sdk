"""Primust Signing — Ed25519 key generation, signing, verification, rotation.

Signing process (spec):
  1. canonical(document) → string
  2. SHA-256(canonical_string) → bytes
  3. Ed25519.sign(hash_bytes, private_key) → signature_bytes
  4. base64url(signature_bytes) → signature field

Key identity invariants (SIGNER_TRUST_POLICY.md):
  - signer_id: stable logical identifier, survives rotation
  - kid: specific key version, unique per generation
  - Both required in every SignatureEnvelope
  - Rotation creates new kid, same signer_id
  - Rotation does NOT invalidate prior signatures (Q2 quarantine)

Library: PyNaCl (libsodium bindings)
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import replace
from datetime import datetime, timezone

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

from primust_artifact_core.canonical import canonical
from primust_artifact_core.types import SignerRecord, SignatureEnvelope, SignerType


def _random_hex(n_bytes: int) -> str:
    return os.urandom(n_bytes).hex()


def _to_b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _from_b64url(s: str) -> bytes:
    padded = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(padded)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def generate_key_pair(
    signer_id: str,
    org_id: str,
    signer_type: SignerType,
) -> tuple[SignerRecord, bytes]:
    """Generate a new Ed25519 key pair and produce a SignerRecord.

    Each call produces a distinct kid. No silent auto-generation (Q4 quarantine).

    Returns:
        Tuple of (SignerRecord, private_key_bytes).
        The private_key_bytes are the 32-byte Ed25519 seed.
    """
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    kid = f"kid_{_random_hex(8)}"
    now = _now_iso()

    record = SignerRecord(
        signer_id=signer_id,
        kid=kid,
        public_key_b64url=_to_b64url(bytes(verify_key)),
        algorithm="Ed25519",
        status="active",
        revocation_reason=None,
        revoked_at=None,
        superseded_by_kid=None,
        activated_at=now,
        deactivated_at=None,
        org_id=org_id,
        signer_type=signer_type,
    )

    return record, bytes(signing_key)


def sign(
    document: dict,
    private_key: bytes,
    signer_record: SignerRecord,
) -> tuple[dict, SignatureEnvelope]:
    """Sign a document.

    Process:
      1. canonical(document) → deterministic JSON string
      2. SHA-256(canonical_string) → 32-byte hash
      3. Ed25519.sign(hash, privateKey) → 64-byte signature
      4. base64url(signature) → string

    Args:
        document: The document to sign (must contain only JSON-native types).
        private_key: 32-byte Ed25519 seed.
        signer_record: The signer's active record (must have status 'active').

    Returns:
        Tuple of (original document, SignatureEnvelope).

    Raises:
        ValueError: If the signer record is not active.
    """
    if signer_record.status != "active":
        raise ValueError(
            f"Cannot sign with {signer_record.status} key (kid: {signer_record.kid})"
        )

    canonical_str = canonical(document)
    hash_bytes = hashlib.sha256(canonical_str.encode("utf-8")).digest()

    signing_key = SigningKey(private_key)
    signed = signing_key.sign(hash_bytes)
    signature_bytes = signed.signature  # 64-byte Ed25519 signature

    envelope = SignatureEnvelope(
        signer_id=signer_record.signer_id,
        kid=signer_record.kid,
        algorithm="Ed25519",
        signature=_to_b64url(signature_bytes),
        signed_at=_now_iso(),
    )

    return document, envelope


def verify(
    document: dict,
    signature_envelope: SignatureEnvelope,
    public_key_b64url: str,
) -> bool:
    """Verify a document's signature.

    Recomputes canonical(document) → SHA-256 → verifies Ed25519 signature.
    Does NOT evaluate key status — that is the verifier's responsibility
    (SIGNER_TRUST_POLICY.md §3–4).

    Args:
        document: The document that was signed.
        signature_envelope: The signature envelope.
        public_key_b64url: Base64url-encoded Ed25519 public key.

    Returns:
        True if the cryptographic signature is valid.
    """
    try:
        canonical_str = canonical(document)
        hash_bytes = hashlib.sha256(canonical_str.encode("utf-8")).digest()
        signature_bytes = _from_b64url(signature_envelope.signature)
        public_key_bytes = _from_b64url(public_key_b64url)

        verify_key = VerifyKey(public_key_bytes)
        verify_key.verify(hash_bytes, signature_bytes)
        return True
    except (BadSignatureError, Exception):
        return False


def rotate_key(
    existing_record: SignerRecord,
) -> tuple[SignerRecord, SignerRecord, bytes]:
    """Rotate a key: create a new kid under the same signer_id.

    The existing record transitions to 'rotated'. A new record is created
    with status 'active'. Prior signatures remain valid against the old kid
    (SIGNER_TRUST_POLICY.md §2, Q2 quarantine).

    Args:
        existing_record: The current active SignerRecord.

    Returns:
        Tuple of (updated_old_record, new_record, new_private_key).

    Raises:
        ValueError: If the existing record is not active.
    """
    if existing_record.status != "active":
        raise ValueError(
            f"Cannot rotate {existing_record.status} key "
            f"(kid: {existing_record.kid}). Only active keys can be rotated."
        )

    new_record, new_private_key = generate_key_pair(
        existing_record.signer_id,
        existing_record.org_id,
        existing_record.signer_type,
    )

    now = _now_iso()

    updated_record = replace(
        existing_record,
        status="rotated",
        superseded_by_kid=new_record.kid,
        deactivated_at=now,
    )

    return updated_record, new_record, new_private_key
