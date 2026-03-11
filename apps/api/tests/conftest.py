"""
Test fixtures for Primust API tests.

Uses FastAPI TestClient with mocked database layer.
"""

from __future__ import annotations

import json
import os
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient


# Set env vars before importing app
os.environ.setdefault("DATABASE_URL_US", "postgresql://test:test@localhost:5432/primust_us")
os.environ.setdefault("DATABASE_URL_EU", "postgresql://test:test@localhost:5432/primust_eu")


from primust_api.main import app  # noqa: E402


# ── In-memory database mock ──


class InMemoryDB:
    """Simple in-memory database for testing."""

    def __init__(self) -> None:
        self.tables: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._parse_inserts = True

    def reset(self) -> None:
        self.tables.clear()

    async def fetch_one(
        self, _region: str, query: str, *args: Any
    ) -> dict[str, Any] | None:
        table = self._extract_table(query)
        if not table:
            return None

        rows = self.tables.get(table, [])
        # Simple primary key lookup
        for row in rows:
            if self._matches(row, query, args):
                return row
        return None

    async def fetch_all(
        self, _region: str, query: str, *args: Any
    ) -> list[dict[str, Any]]:
        table = self._extract_table(query)
        if not table:
            return []

        rows = self.tables.get(table, [])
        result = []
        for row in rows:
            if self._matches(row, query, args):
                result.append(row)
        return result

    async def execute(
        self, _region: str, query: str, *args: Any
    ) -> str:
        q = query.strip().upper()
        if q.startswith("INSERT"):
            self._handle_insert(query, args)
        elif q.startswith("UPDATE"):
            self._handle_update(query, args)
        return "OK"

    def _extract_table(self, query: str) -> str | None:
        """Extract primary table name from query."""
        q = query.upper()
        if "FROM" in q:
            parts = q.split("FROM")[1].strip().split()
            return parts[0].lower().strip()
        return None

    def _matches(
        self, row: dict[str, Any], query: str, args: tuple[Any, ...]
    ) -> bool:
        """Check if a row matches WHERE conditions (simple $N matching)."""
        q = query.upper()
        if "WHERE" not in q:
            return True

        where = query.split("WHERE")[1] if "WHERE" in query else query.split("where")[1]
        # Parse simple conditions: column = $N
        conditions = where.replace("AND", "&").split("&")
        for cond in conditions:
            cond = cond.strip()
            if "ORDER" in cond.upper():
                cond = cond[:cond.upper().index("ORDER")].strip()
            if "LIMIT" in cond.upper():
                cond = cond[:cond.upper().index("LIMIT")].strip()
            if "=" not in cond or "$" not in cond:
                continue
            parts = cond.split("=")
            if len(parts) != 2:
                continue
            col = parts[0].strip().split(".")[-1].strip()
            param_str = parts[1].strip()
            if not param_str.startswith("$"):
                continue
            param_idx = int(param_str[1:]) - 1
            if param_idx < len(args):
                if row.get(col) != args[param_idx]:
                    return False
        return True

    def _handle_insert(self, query: str, args: tuple[Any, ...]) -> None:
        """Parse INSERT and store row."""
        q = query.strip()
        # Extract table name
        upper = q.upper()
        into_idx = upper.index("INTO") + 4
        rest = q[into_idx:].strip()
        table = rest.split("(")[0].strip().split()[0].lower()

        # Extract column names
        col_start = q.index("(", q.upper().index("INTO") + 4) + 1
        col_end = q.index(")", col_start)
        columns = [c.strip() for c in q[col_start:col_end].split(",")]

        # Map $N params to values
        row: dict[str, Any] = {}
        for i, col in enumerate(columns):
            if i < len(args):
                val = args[i]
                # Auto-parse JSON strings
                if isinstance(val, str) and (val.startswith("{") or val.startswith("[")):
                    try:
                        val = json.loads(val)
                    except (json.JSONDecodeError, ValueError):
                        pass
                row[col] = val
            else:
                row[col] = None

        self.tables[table].append(row)

    def _handle_update(self, query: str, args: tuple[Any, ...]) -> None:
        """Simple UPDATE handling."""
        q = query.strip()
        upper = q.upper()

        # Extract table
        table = q[upper.index("UPDATE") + 6:upper.index("SET")].strip().lower()

        # Find matching rows and update
        rows = self.tables.get(table, [])
        if "WHERE" not in upper:
            return

        where_part = q[upper.index("WHERE"):]
        for row in rows:
            if self._matches(row, f"SELECT * FROM {table} {where_part}", args):
                # Parse SET clause
                set_part = q[upper.index("SET") + 3:upper.index("WHERE")].strip()
                for assignment in set_part.split(","):
                    if "=" not in assignment:
                        continue
                    col, val = assignment.split("=", 1)
                    col = col.strip()
                    val = val.strip()
                    if val.startswith("$"):
                        idx = int(val[1:]) - 1
                        if idx < len(args):
                            row[col] = args[idx]
                    elif val.startswith("'") and val.endswith("'"):
                        row[col] = val[1:-1]


# ── Fixtures ──

_db = InMemoryDB()


class _MockRegionConfig:
    """Mock region config for tests."""
    def __init__(self, region: str = "us") -> None:
        self.region = region
        self.kms_key = f"local-key-{region}"
        self.tsa_url = "http://timestamp.digicert.com"
        self.r2_bucket = f"primust-{region}"


def _mock_get_region_config(region: str) -> _MockRegionConfig:
    return _MockRegionConfig(region)


async def _mock_kms_sign(document_json: str, kms_key_name: str, **kwargs: Any) -> dict[str, Any]:
    """Mock KMS signing — returns deterministic local signature."""
    import base64, hashlib
    digest = hashlib.sha256(document_json.encode("utf-8")).digest()
    sig = base64.urlsafe_b64encode(digest).decode("ascii")
    now = datetime.now(timezone.utc).isoformat()
    return {
        "signer_id": kwargs.get("signer_id", "api_signer"),
        "kid": kwargs.get("kid", "kid_api"),
        "algorithm": "Ed25519",
        "signature": f"test_kms:{sig}",
        "signed_at": now,
    }


async def _mock_get_timestamp_anchor(document_json: str, **kwargs: Any) -> dict[str, Any]:
    """Mock TSA — returns simulated RFC 3161 anchor."""
    return {
        "type": "rfc3161",
        "tsa": "digicert_us",
        "value": "dGVzdF90aW1lc3RhbXBfdG9rZW4=",  # base64("test_timestamp_token")
    }


@pytest.fixture(autouse=True)
def mock_db():
    """Mock all database calls, KMS signing, and TSA timestamping."""
    _db.reset()
    with (
        patch("primust_api.routes.runs.fetch_one", side_effect=_db.fetch_one),
        patch("primust_api.routes.runs.fetch_all", side_effect=_db.fetch_all),
        patch("primust_api.routes.runs.execute", side_effect=_db.execute),
        patch("primust_api.routes.runs.kms_sign", side_effect=_mock_kms_sign),
        patch("primust_api.routes.runs.get_timestamp_anchor", side_effect=_mock_get_timestamp_anchor),
        patch("primust_api.routes.runs.get_region_config", side_effect=_mock_get_region_config),
        patch("primust_api.routes.vpecs.fetch_one", side_effect=_db.fetch_one),
        patch("primust_api.routes.packs.fetch_one", side_effect=_db.fetch_one),
        patch("primust_api.routes.packs.fetch_all", side_effect=_db.fetch_all),
        patch("primust_api.routes.packs.execute", side_effect=_db.execute),
        patch("primust_api.routes.packs.kms_sign", side_effect=_mock_kms_sign),
        patch("primust_api.routes.packs.get_region_config", side_effect=_mock_get_region_config),
        patch("primust_api.routes.gaps.fetch_one", side_effect=_db.fetch_one),
        patch("primust_api.routes.gaps.fetch_all", side_effect=_db.fetch_all),
        patch("primust_api.routes.gaps.execute", side_effect=_db.execute),
        patch("primust_api.routes.gaps.kms_sign", side_effect=_mock_kms_sign),
        patch("primust_api.routes.gaps.get_region_config", side_effect=_mock_get_region_config),
    ):
        yield _db


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def api_key_us():
    return "pk_live_org001_us_secret123"


@pytest.fixture
def api_key_test():
    return "pk_test_org001_us_secret123"


@pytest.fixture
def jwt_token():
    """Create a simple JWT for testing (no verification in dev mode)."""
    import jwt as pyjwt

    payload = {
        "sub": "user_001",
        "org_id": "org001",
        "org_region": "us",
        "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
    }
    return pyjwt.encode(payload, "test_secret", algorithm="HS256")


def seed_policy_pack(db: InMemoryDB, org_id: str = "org001") -> str:
    """Seed a policy pack and return its ID."""
    pack_id = f"pp_{uuid.uuid4().hex[:8]}"
    db.tables["policy_packs"].append({
        "policy_pack_id": pack_id,
        "org_id": org_id,
        "name": "test_pack",
        "version": "1.0.0",
        "checks": [
            {
                "check_id": "chk_001",
                "manifest_id": "manifest_001",
                "required": True,
                "evaluation_scope": "per_action_unit",
                "action_unit_count": None,
            }
        ],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "signer_id": "signer_001",
        "kid": "kid_001",
        "signature": {"signer_id": "signer_001", "kid": "kid_001", "algorithm": "Ed25519", "signature": "stub", "signed_at": datetime.now(timezone.utc).isoformat()},
    })
    return pack_id


def seed_surface(db: InMemoryDB, org_id: str = "org001") -> str:
    """Seed an observation surface and return its ID."""
    surface_id = f"surf_{uuid.uuid4().hex[:8]}"
    db.tables["observation_surfaces"].append({
        "surface_id": surface_id,
        "org_id": org_id,
        "environment": "production",
        "surface_type": "in_process_adapter",
        "surface_name": "test_surface",
        "surface_version": "1.0.0",
        "observation_mode": "pre_action",
        "scope_type": "full_workflow",
        "scope_description": "Test",
        "surface_coverage_statement": "All observed",
        "proof_ceiling": "mathematical",
        "gaps_detectable": [],
        "gaps_not_detectable": [],
        "registered_at": datetime.now(timezone.utc).isoformat(),
    })
    return surface_id


def seed_run(
    db: InMemoryDB,
    org_id: str = "org001",
    surface_id: str = "surf_001",
    state: str = "open",
) -> str:
    """Seed a process run and return its ID."""
    run_id = f"run_{uuid.uuid4().hex[:8]}"
    db.tables["process_runs"].append({
        "run_id": run_id,
        "workflow_id": "wf_001",
        "org_id": org_id,
        "surface_id": surface_id,
        "policy_snapshot_hash": "sha256:" + "aa" * 32,
        "process_context_hash": None,
        "state": state,
        "action_unit_count": 0,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "closed_at": None,
        "ttl_seconds": 3600,
    })
    return run_id
