from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical(obj: Any) -> str:
    """Produce a canonical JSON string with sorted keys and minimal separators."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def commitment_hash(data: bytes) -> str:
    """Compute a SHA-256 commitment hash. Returns 'sha256:<hex>' string."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def hash_check_result(check_id: str, passed: bool, evidence: str) -> str:
    """Hash a check result into a commitment without exposing raw content."""
    payload = canonical({"check_id": check_id, "passed": passed, "evidence_hash": commitment_hash(evidence.encode("utf-8"))})
    return commitment_hash(payload.encode("utf-8"))
