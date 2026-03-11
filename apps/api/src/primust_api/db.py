"""
Primust database layer — dual-region Neon Postgres routing.

Region routing:
  org.region → DATABASE_URL_US or DATABASE_URL_EU
  NEVER a single DATABASE_URL. NEVER hardcode a region.

All four resources resolved together per request:
  DATABASE_URL, KMS_KEY, R2_BUCKET, TSA_URL
"""

from __future__ import annotations

import os
from typing import Any

import asyncpg

# ── Region config ──

REGION_US = "us"
REGION_EU = "eu"

BANNED_COLUMNS = frozenset(
    ["agent_id", "pipeline_id", "tool_name", "session_id", "trace_id", "reliance_mode"]
)


class RegionConfig:
    """Per-request region-resolved configuration."""

    def __init__(self, region: str) -> None:
        if region not in (REGION_US, REGION_EU):
            raise ValueError(f"Invalid region: {region}. Must be 'us' or 'eu'.")
        self.region = region

    @property
    def database_url(self) -> str:
        key = f"DATABASE_URL_{self.region.upper()}"
        url = os.environ.get(key)
        if not url:
            raise RuntimeError(f"{key} not configured")
        return url

    @property
    def kms_key(self) -> str:
        key = f"PRIMUST_KMS_KEY_{self.region.upper()}"
        return os.environ.get(key, f"local-key-{self.region}")

    @property
    def r2_bucket(self) -> str:
        key = f"R2_BUCKET_{self.region.upper()}"
        return os.environ.get(key, f"primust-{self.region}")

    @property
    def tsa_url(self) -> str:
        key = f"PRIMUST_TSA_URL_{self.region.upper()}"
        return os.environ.get(key, "none")


def get_region_config(region: str) -> RegionConfig:
    return RegionConfig(region)


# ── Connection pool ──

_pools: dict[str, asyncpg.Pool] = {}


async def get_pool(region: str) -> asyncpg.Pool:
    """Get or create a connection pool for the given region."""
    if region not in _pools:
        config = get_region_config(region)
        _pools[region] = await asyncpg.create_pool(
            config.database_url, min_size=2, max_size=10
        )
    return _pools[region]


async def close_pools() -> None:
    """Close all connection pools."""
    for pool in _pools.values():
        await pool.close()
    _pools.clear()


# ── Query helpers ──


async def fetch_one(
    region: str, query: str, *args: Any
) -> dict[str, Any] | None:
    pool = await get_pool(region)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, *args)
        return dict(row) if row else None


async def fetch_all(
    region: str, query: str, *args: Any
) -> list[dict[str, Any]]:
    pool = await get_pool(region)
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *args)
        return [dict(r) for r in rows]


async def execute(region: str, query: str, *args: Any) -> str:
    pool = await get_pool(region)
    async with pool.acquire() as conn:
        return await conn.execute(query, *args)
