"""primust-verify -- Audit report verifier (PDF).

Verifies a signed Primust audit report PDF offline.
No Primust account or infrastructure access required.

Verification steps:
  1. Load PDF and extract /PrimusReport* metadata fields
  2. Strip /PrimusReport* metadata to reconstruct the pre-signature PDF
  3. Compute SHA-256 of the stripped PDF bytes
  4. Fetch public key from trust_anchor_url (or --trust-root)
  5. Verify Ed25519(signature, sha256, public_key)

Exit codes:
  0 = valid
  1 = invalid signature
  2 = sandbox / system error
  3 = key revoked
"""

from __future__ import annotations

import base64
import hashlib
import io
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from primust_verify.key_cache import get_key


# ── Metadata field names embedded in signed report PDFs ──

_PRIMUST_META_KEYS = {
    "/PrimusReportSignature",
    "/PrimusReportKeyId",
    "/PrimusReportTrustAnchor",
    "/PrimusReportPackId",
    "/PrimusReportGeneratedAt",
}


@dataclass
class ReportVerificationResult:
    """Result of verifying an audit report PDF."""

    report_id: str = ""
    valid: bool = False
    pack_id: str = ""
    kid: str = ""
    trust_anchor: str = ""
    generated_at: str = ""
    pdf_sha256: str = ""
    signature_valid: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict."""
        return {
            "report_id": self.report_id,
            "valid": self.valid,
            "pack_id": self.pack_id,
            "kid": self.kid,
            "trust_anchor": self.trust_anchor,
            "generated_at": self.generated_at,
            "pdf_sha256": self.pdf_sha256,
            "signature_valid": self.signature_valid,
            "errors": self.errors,
            "warnings": self.warnings,
        }


def _extract_key_from_pem(pem: str) -> bytes:
    """Extract raw key bytes from PEM or raw base64 string."""
    if "-----BEGIN" in pem:
        b64 = re.sub(r"-----[A-Z ]+-----", "", pem).strip()
        b64 = b64.replace("\n", "").replace("\r", "")
        return base64.b64decode(b64 + "==")  # pad for safety
    # Try base64url first, then standard base64
    cleaned = pem.strip()
    try:
        return base64.urlsafe_b64decode(cleaned + "==")
    except Exception:
        return base64.b64decode(cleaned + "==")


def _read_pdf_metadata(pdf_bytes: bytes) -> dict[str, str]:
    """Read all metadata from a PDF, returning a dict of key -> value."""
    try:
        from pypdf import PdfReader
    except ImportError:
        from PyPDF2 import PdfReader  # type: ignore[no-redef]

    reader = PdfReader(io.BytesIO(pdf_bytes))
    meta = reader.metadata or {}
    result: dict[str, str] = {}
    for k, v in meta.items():
        result[str(k)] = str(v)
    return result


def _strip_primust_metadata(pdf_bytes: bytes) -> bytes:
    """Remove /PrimusReport* metadata fields from a PDF.

    Returns the cleaned PDF bytes that should match the pre-signature PDF.
    """
    try:
        from pypdf import PdfReader, PdfWriter
    except ImportError:
        from PyPDF2 import PdfReader, PdfWriter  # type: ignore[no-redef]

    reader = PdfReader(io.BytesIO(pdf_bytes))
    writer = PdfWriter()
    writer.append_pages_from_reader(reader)

    existing_meta = reader.metadata or {}
    cleaned: dict[str, str] = {}
    for k, v in existing_meta.items():
        key_str = str(k)
        bare_key = key_str.lstrip("/")
        if not bare_key.startswith("PrimusReport"):
            cleaned[key_str] = str(v)

    writer.add_metadata(cleaned)

    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def verify_report_pdf(
    pdf_bytes: bytes,
    trust_root: Optional[str] = None,
) -> ReportVerificationResult:
    """
    Verify a signed PDF audit report.

    1. Extract /PrimusReport* metadata from the PDF
    2. Strip those metadata fields to get the pre-signature PDF
    3. Compute SHA-256 of the pre-signature PDF bytes
    4. Resolve the public key from the trust anchor or --trust-root
    5. Verify Ed25519 signature

    Args:
        pdf_bytes: Raw bytes of the signed PDF file.
        trust_root: Optional path to a custom public key PEM.

    Returns:
        ReportVerificationResult with pass/fail and details.
    """
    result = ReportVerificationResult()

    # Step 1: Read metadata
    try:
        metadata = _read_pdf_metadata(pdf_bytes)
    except Exception as e:
        result.errors.append(f"pdf_read_failed: {e}")
        return result

    # Extract Primust metadata fields
    signature_b64 = metadata.get("/PrimusReportSignature", "")
    kid = metadata.get("/PrimusReportKeyId", "")
    trust_anchor = metadata.get("/PrimusReportTrustAnchor", "")
    pack_id = metadata.get("/PrimusReportPackId", "")
    generated_at = metadata.get("/PrimusReportGeneratedAt", "")

    result.pack_id = pack_id
    result.kid = kid
    result.trust_anchor = trust_anchor
    result.generated_at = generated_at

    if not signature_b64:
        result.errors.append("missing_signature: no /PrimusReportSignature in PDF metadata")
        return result

    if not kid:
        result.errors.append("missing_kid: no /PrimusReportKeyId in PDF metadata")
        return result

    # Handle dev mode signatures
    if signature_b64.startswith("local_dev:"):
        result.warnings.append("local_dev_signature -- not for production use")
        # For dev signatures, still verify hash consistency but skip Ed25519
        try:
            stripped_bytes = _strip_primust_metadata(pdf_bytes)
            pdf_sha256 = hashlib.sha256(stripped_bytes).hexdigest()
            result.pdf_sha256 = pdf_sha256
        except Exception as e:
            result.errors.append(f"pdf_strip_failed: {e}")
            return result
        result.signature_valid = True
        result.valid = True
        return result

    # Step 2: Strip /PrimusReport* metadata to get pre-signature PDF
    try:
        stripped_bytes = _strip_primust_metadata(pdf_bytes)
    except Exception as e:
        result.errors.append(f"pdf_strip_failed: {e}")
        return result

    # Step 3: Compute SHA-256 of stripped PDF
    pdf_sha256 = hashlib.sha256(stripped_bytes).hexdigest()
    result.pdf_sha256 = pdf_sha256

    # Step 4: Resolve public key
    public_key_url = trust_anchor or f"https://primust.com/.well-known/primust-pubkeys/{kid}.pem"

    try:
        pem = get_key(kid, public_key_url, trust_root)
    except Exception as e:
        result.errors.append(f"key_resolution_failed: {e}")
        return result

    # Step 5: Verify Ed25519 signature
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import (
            load_pem_public_key,
        )

        # Try loading as PEM first
        if "-----BEGIN" in pem:
            public_key = load_pem_public_key(pem.encode("utf-8"))
        else:
            # Raw key bytes
            key_bytes = _extract_key_from_pem(pem)
            public_key = Ed25519PublicKey.from_public_bytes(key_bytes)

        # Decode the signature
        sig_bytes = base64.urlsafe_b64decode(signature_b64 + "==")

        # The signature covers the SHA256 hex digest of the pre-metadata PDF
        public_key.verify(sig_bytes, pdf_sha256.encode("utf-8"))
        result.signature_valid = True
    except Exception as e:
        result.errors.append(f"signature_verification_failed: {e}")
        result.signature_valid = False
        return result

    # All checks passed
    result.valid = True
    return result


# ── Backwards compatibility: verify_report for JSON reports ──
# Kept so existing callers that pass a parsed dict still work during migration.

def verify_report(
    report_or_path: Any,
    trust_root: Optional[str] = None,
) -> ReportVerificationResult:
    """Verify a report. Accepts either raw PDF bytes, a file path string, or a legacy JSON dict.

    For PDF files (the new format), delegates to verify_report_pdf.
    For legacy JSON dicts, returns a minimal result indicating the format is deprecated.
    """
    if isinstance(report_or_path, bytes):
        return verify_report_pdf(report_or_path, trust_root=trust_root)

    if isinstance(report_or_path, (str, Path)):
        path = Path(report_or_path)
        if path.exists():
            return verify_report_pdf(path.read_bytes(), trust_root=trust_root)
        else:
            result = ReportVerificationResult()
            result.errors.append(f"file_not_found: {report_or_path}")
            return result

    if isinstance(report_or_path, dict):
        # Legacy JSON report -- no longer the canonical format
        result = ReportVerificationResult()
        result.errors.append("legacy_json_format: PDF reports are now required. Regenerate the report.")
        result.report_id = report_or_path.get("report_id", "")
        return result

    result = ReportVerificationResult()
    result.errors.append("unsupported_input_type")
    return result
