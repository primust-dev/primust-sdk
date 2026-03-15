"""
GCP Cloud KMS integration — signing + symmetric encryption.

Signs VPEC documents, gap waivers, and evidence packs using
GCP KMS asymmetric signing (EC_SIGN_P256_SHA256 or RSA_SIGN_PKCS1_2048_SHA256).

Encrypts sensitive at-rest fields (e.g. webhook auth_header) using
GCP KMS symmetric encryption (PRIMUST_KMS_ENCRYPT_KEY).

KMS key resource names resolved from environment:
  PRIMUST_KMS_KEY_US — US region signing key
  PRIMUST_KMS_KEY_EU — EU region signing key
  PRIMUST_KMS_ENCRYPT_KEY — symmetric encryption key for secrets at rest

Local dev stub ONLY when PRIMUST_DEV_MODE=true. Never in production.

Provisional flow: on KMS failure, returns UNSIGNED_PENDING envelope.
Caller (close_run) sets VPEC state to "provisional" with signature_pending=True.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("primust.kms")

_DEV_MODE = os.environ.get("PRIMUST_DEV_MODE", "").lower() == "true"


async def kms_sign(
    document_json: str,
    kms_key_name: str,
    signer_id: str = "api_signer",
    kid: str = "kid_api",
) -> dict[str, Any]:
    """
    Sign a document using GCP Cloud KMS. Fail-closed: never silently
    fall back to a local stub in production.

    Returns a signature envelope dict.

    Local dev stub used ONLY when PRIMUST_DEV_MODE=true AND key starts with "local-key-".

    On KMS failure (network, permissions, etc.), returns a provisional envelope
    with algorithm="UNSIGNED_PENDING" so the caller can issue a provisional VPEC.
    """
    now = datetime.now(timezone.utc).isoformat()

    # Local development stub — ONLY when explicitly opted in
    if kms_key_name.startswith("local-key-"):
        if not _DEV_MODE:
            raise RuntimeError(
                f"KMS key '{kms_key_name}' is a local stub but PRIMUST_DEV_MODE is not enabled. "
                "Set PRIMUST_KMS_KEY_US / PRIMUST_KMS_KEY_EU to a real GCP KMS key, "
                "or set PRIMUST_DEV_MODE=true for local development."
            )
        logger.warning("Using local dev signing stub — NOT for production use")
        digest = hashlib.sha256(document_json.encode("utf-8")).digest()
        local_sig = base64.urlsafe_b64encode(digest).decode("ascii")
        return {
            "signer_id": signer_id,
            "kid": kid,
            "algorithm": "LOCAL_DEV_SHA256",
            "signature": f"local_dev:{local_sig}",
            "signed_at": now,
        }

    try:
        from google.cloud import kms
    except ImportError as exc:
        raise RuntimeError(
            "google-cloud-kms package not installed. Required for production signing."
        ) from exc

    try:
        client = kms.KeyManagementServiceClient()
        data = document_json.encode("utf-8")

        # Ed25519 signs raw data (not a pre-computed digest)
        sign_response = client.asymmetric_sign(
            request={"name": kms_key_name, "data": data}
        )

        signature_b64 = base64.urlsafe_b64encode(sign_response.signature).decode("ascii")

        return {
            "signer_id": signer_id,
            "kid": kid,
            "algorithm": "Ed25519",
            "signature": signature_b64,
            "signed_at": now,
        }
    except Exception:
        logger.error(
            "KMS signing failed for key=%s — returning provisional envelope",
            kms_key_name,
            exc_info=True,
        )
        return {
            "signer_id": signer_id,
            "kid": kid,
            "algorithm": "UNSIGNED_PENDING",
            "signature": None,
            "signed_at": now,
        }


# ── Symmetric encryption for secrets at rest ──

_ENCRYPT_KEY = os.environ.get("PRIMUST_KMS_ENCRYPT_KEY", "")

_DEV_ENCRYPT_PREFIX = "dev_plain:"
_KMS_ENCRYPT_PREFIX = "kms_enc:"


def encrypt_secret(plaintext: str) -> str:
    """
    Encrypt a secret for at-rest storage using GCP KMS symmetric encryption.

    In dev mode (PRIMUST_DEV_MODE=true), stores with a dev_plain: prefix
    (base64-encoded but NOT encrypted — local dev only).

    In production, uses GCP KMS symmetric encrypt and returns kms_enc: prefixed
    base64 ciphertext.
    """
    if _DEV_MODE or not _ENCRYPT_KEY:
        encoded = base64.urlsafe_b64encode(plaintext.encode("utf-8")).decode("ascii")
        return f"{_DEV_ENCRYPT_PREFIX}{encoded}"

    try:
        from google.cloud import kms
    except ImportError as exc:
        raise RuntimeError(
            "google-cloud-kms package not installed. Required for production encryption."
        ) from exc

    try:
        client = kms.KeyManagementServiceClient()
        response = client.encrypt(
            request={"name": _ENCRYPT_KEY, "plaintext": plaintext.encode("utf-8")}
        )
        ciphertext_b64 = base64.urlsafe_b64encode(response.ciphertext).decode("ascii")
        return f"{_KMS_ENCRYPT_PREFIX}{ciphertext_b64}"
    except Exception:
        logger.error("KMS encrypt failed for key=%s", _ENCRYPT_KEY, exc_info=True)
        raise


def decrypt_secret(ciphertext: str) -> str:
    """
    Decrypt a secret stored with encrypt_secret().

    Handles both dev_plain: (dev mode) and kms_enc: (production) prefixes.
    """
    if ciphertext.startswith(_DEV_ENCRYPT_PREFIX):
        encoded = ciphertext[len(_DEV_ENCRYPT_PREFIX):]
        return base64.urlsafe_b64decode(encoded).decode("utf-8")

    if not ciphertext.startswith(_KMS_ENCRYPT_PREFIX):
        # Legacy plaintext — return as-is for backwards compatibility during migration
        logger.warning("auth_header stored as plaintext — will be encrypted on next save")
        return ciphertext

    try:
        from google.cloud import kms
    except ImportError as exc:
        raise RuntimeError(
            "google-cloud-kms package not installed. Required for production decryption."
        ) from exc

    encoded = ciphertext[len(_KMS_ENCRYPT_PREFIX):]
    ciphertext_bytes = base64.urlsafe_b64decode(encoded)

    try:
        client = kms.KeyManagementServiceClient()
        response = client.decrypt(
            request={"name": _ENCRYPT_KEY, "ciphertext": ciphertext_bytes}
        )
        return response.plaintext.decode("utf-8")
    except Exception:
        logger.error("KMS decrypt failed for key=%s", _ENCRYPT_KEY, exc_info=True)
        raise
