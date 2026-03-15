from __future__ import annotations

import importlib.resources
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from ._canonical import commitment_hash
from ._transport import TransportClient
from .decorator import RegisteredCheck
from .result import CheckResult


@dataclass
class HarnessResult:
    """Aggregate result from running all governance checks."""

    passed: bool
    results: list[CheckResult]
    gaps: list[str]
    vpec: dict | None  # None if no api_key
    observability_only: bool


class Harness:
    """Orchestrates governance checks against a policy bundle.

    Args:
        policy: Bundle ID to load (e.g. 'ai_agent_general_v1').
        api_key: Primust API key. If None, runs in observability-only mode.
        endpoint: Primust API endpoint URL.
    """

    def __init__(
        self,
        policy: str = "ai_agent_general_v1",
        api_key: str | None = None,
        endpoint: str = "https://api.primust.com",
    ):
        self._policy = policy
        self._api_key = api_key
        self._endpoint = endpoint
        self._registered_checks: list[RegisteredCheck] = []
        self._bundle: dict[str, Any] = self._load_bundle(policy)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def checks(self) -> list[RegisteredCheck]:
        """Return all registered checks."""
        return list(self._registered_checks)

    @property
    def bundle(self) -> dict[str, Any]:
        """Return the loaded bundle definition."""
        return dict(self._bundle)

    def check(
        self,
        fn: Callable[..., CheckResult] | None = None,
        *,
        name: str | None = None,
        proof_ceiling: str = "mathematical",
    ) -> Callable[..., CheckResult] | Callable[[Callable[..., CheckResult]], RegisteredCheck]:
        """Decorator to register a custom check (BYOC).

        Can be used with or without arguments::

            @harness.check
            def my_check(*, input, **kw): ...

            @harness.check(name="custom", proof_ceiling="execution")
            def my_check(*, input, **kw): ...
        """

        def _wrap(f: Callable[..., CheckResult]) -> RegisteredCheck:
            check_name = name or f.__name__
            registered = RegisteredCheck(f, name=check_name, proof_ceiling=proof_ceiling)
            self._registered_checks.append(registered)
            return registered

        if fn is not None:
            return _wrap(fn)
        return _wrap

    def run(
        self,
        *,
        input: Any,
        output: Any = None,
        context: dict[str, Any] | None = None,
    ) -> HarnessResult:
        """Run all registered checks against input/output.

        Steps:
            1. Load bundle YAML to get required checks + thresholds.
            2. Run each registered check.
            3. Collect CheckResults.
            4. If api_key set: compute commitment hashes, POST to API, get VPEC.
            5. If no api_key: return results only (observability_only=True).
        """
        bundle_checks = {c["check_id"]: c for c in self._bundle.get("checks", [])}
        results: list[CheckResult] = []

        # Build a lookup of registered checks by name
        check_lookup: dict[str, RegisteredCheck] = {rc.name: rc for rc in self._registered_checks}

        # Run each registered check
        for rc in self._registered_checks:
            config = bundle_checks.get(rc.name, {}).get("config")
            try:
                result = rc(input=input, output=output, context=context, config=config)
            except Exception as exc:
                result = CheckResult(
                    passed=False,
                    check_id=rc.name,
                    evidence=f"check raised: {exc}",
                    proof_ceiling=rc.proof_ceiling,
                )
            results.append(result)

        # Determine gaps: required bundle checks that have no registered implementation
        gaps: list[str] = []
        for cdef in self._bundle.get("checks", []):
            if cdef.get("required", False) and cdef["check_id"] not in check_lookup:
                gaps.append(cdef["check_id"])

        all_passed = all(r.passed for r in results) and len(gaps) == 0

        # Proof layer
        vpec: dict | None = None
        observability_only = self._api_key is None

        if self._api_key is not None:
            try:
                vpec = self._submit_proof(results)
            except Exception:
                # Proof submission failure does not fail the harness run.
                vpec = None

        return HarnessResult(
            passed=all_passed,
            results=results,
            gaps=gaps,
            vpec=vpec,
            observability_only=observability_only,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _load_bundle(self, policy: str) -> dict[str, Any]:
        """Load a bundle YAML by policy name from the bundles/ directory."""
        bundles_dir = Path(__file__).parent / "bundles"
        # Try matching by bundle_id across all yaml files
        for yaml_file in bundles_dir.glob("*.yaml"):
            with open(yaml_file, "r") as f:
                data = yaml.safe_load(f)
                if data and data.get("bundle_id") == policy:
                    return data
        # Fallback: empty bundle (allows running with no policy match)
        return {"bundle_id": policy, "checks": []}

    def _submit_proof(self, results: list[CheckResult]) -> dict[str, Any]:
        """Submit check results to the Primust API proof layer."""
        client = TransportClient(api_key=self._api_key, endpoint=self._endpoint)  # type: ignore[arg-type]
        try:
            manifest_id = "manifest:" + uuid.uuid4().hex[:16]
            run_id = client.open_run(manifest_id=manifest_id, policy=self._policy)

            for result in results:
                client.record_check(run_id, result)

            vpec = client.close_run(run_id)
            return vpec
        finally:
            client.close()
