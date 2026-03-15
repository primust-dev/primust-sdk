from __future__ import annotations

import functools
from typing import Any, Callable

from .result import CheckResult


class RegisteredCheck:
    """Wrapper around a user-provided check function."""

    def __init__(self, fn: Callable[..., CheckResult], name: str, proof_ceiling: str):
        self.fn = fn
        self.name = name
        self.proof_ceiling = proof_ceiling
        functools.update_wrapper(self, fn)

    def __call__(self, **kwargs: Any) -> CheckResult:
        result = self.fn(**kwargs)
        if not result.check_id:
            result.check_id = self.name
        if result.proof_ceiling == "mathematical" and self.proof_ceiling != "mathematical":
            result.proof_ceiling = self.proof_ceiling
        return result

    def __repr__(self) -> str:
        return f"RegisteredCheck(name={self.name!r}, proof_ceiling={self.proof_ceiling!r})"
