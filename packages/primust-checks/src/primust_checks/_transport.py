from __future__ import annotations

from typing import Any

import httpx

from ._canonical import commitment_hash, hash_check_result
from .result import CheckResult


class TransportClient:
    """httpx-based API client for the Primust proof layer.

    Zero content transit: only CheckResult.passed, commitment hashes,
    manifest_id, and proof_level are sent. Never raw strings.
    """

    def __init__(self, api_key: str, endpoint: str = "https://api.primust.com"):
        self._api_key = api_key
        self._endpoint = endpoint.rstrip("/")
        self._client = httpx.Client(
            base_url=self._endpoint,
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            timeout=30.0,
        )

    def open_run(self, manifest_id: str, policy: str) -> str:
        """POST /api/v1/runs to open a new compliance run. Returns run_id."""
        resp = self._client.post(
            "/api/v1/runs",
            json={"manifest_id": manifest_id, "policy": policy},
        )
        resp.raise_for_status()
        return resp.json()["run_id"]

    def record_check(self, run_id: str, result: CheckResult) -> None:
        """POST /api/v1/runs/{run_id}/records for a single check result.

        Only sends commitment hashes -- never raw evidence or details.
        """
        result_commitment = hash_check_result(
            check_id=result.check_id,
            passed=result.passed,
            evidence=result.evidence,
        )
        self._client.post(
            f"/api/v1/runs/{run_id}/records",
            json={
                "check_id": result.check_id,
                "passed": result.passed,
                "proof_ceiling": result.proof_ceiling,
                "commitment": result_commitment,
            },
        ).raise_for_status()

    def close_run(self, run_id: str) -> dict[str, Any]:
        """POST /api/v1/runs/{run_id}/close to finalize and get VPEC."""
        resp = self._client.post(f"/api/v1/runs/{run_id}/close")
        resp.raise_for_status()
        return resp.json()

    def close(self) -> None:
        """Close the underlying httpx client."""
        self._client.close()
