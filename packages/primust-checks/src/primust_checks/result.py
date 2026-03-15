from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CheckResult:
    """Result of a single governance check execution."""

    passed: bool
    check_id: str = ""
    evidence: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    proof_ceiling: str = "mathematical"  # mathematical | execution | witnessed | attestation
