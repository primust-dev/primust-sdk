"""
GCP Cloud KMS signing integration.

Signs VPEC documents, gap waivers, and evidence packs using
GCP KMS asymmetric signing (EC_SIGN_P256_SHA256 or RSA_SIGN_PKCS1_2048_SHA256).

KMS key resource names resolved from environment:
  PRIMUST_KMS_KEY_US — US region signing key
  PRIMUST_KMS_KEY_EU — EU region signing key

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
        digest = hashlib.sha256(document_json.encode("utf-8")).digest()

        sign_response = client.asymmetric_sign(
            request={"name": kms_key_name, "digest": {"sha256": digest}}
        )

        signature_b64 = base64.urlsafe_b64encode(sign_response.signature).decode("ascii")

        return {
            "signer_id": signer_id,
            "kid": kid,
            "algorithm": "EC_SIGN_P256_SHA256",
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
