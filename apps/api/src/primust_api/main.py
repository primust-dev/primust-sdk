"""
Primust API — FastAPI control plane.

Deployment: Fly.io (US East + Frankfurt)
Auth: Clerk JWT + API key (pk_live/pk_test)
DB: Neon Postgres, dual-region (DATABASE_URL_US / DATABASE_URL_EU)
"""

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from .db import close_pools, get_pool

# ── Structured logging configuration ──

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger("primust.api")

# KMS health status cache (30s TTL)
_kms_status: dict[str, str] = {}
_kms_status_ts: float = 0

# ── Required env vars (fail-fast at startup) ──

_REQUIRED_ENV = [
    "DATABASE_URL_US",
    "DATABASE_URL_EU",
]

# Auth/KMS/TSA env vars — required unless PRIMUST_DEV_MODE=true
_REQUIRED_ENV_PROD = [
    "PRIMUST_API_KEY_SECRET",
    "CLERK_JWKS_URL",
    "PRIMUST_KMS_KEY_US",
    "PRIMUST_KMS_KEY_EU",
    "PRIMUST_TSA_URL_US",
    "PRIMUST_TSA_URL_EU",
]

_DEV_MODE = os.environ.get("PRIMUST_DEV_MODE", "").lower() == "true"

# Rate limit: requests per minute per API key / IP
_RATE_LIMIT_RPM = int(os.environ.get("PRIMUST_RATE_LIMIT_RPM", "120"))


# Per-endpoint rate limits (requests per minute)
_PATH_RATE_LIMITS: dict[str, int] = {
    "/api/v1/runs": 60,
    "/api/v1/records": 300,
    "/api/v1/close": 30,
}

# Test key daily cap
_TEST_KEY_DAILY_CAP = int(os.environ.get("PRIMUST_TEST_KEY_DAILY_CAP", "500"))


class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory rate limiter: per-endpoint + per-client + test key daily cap."""

    def __init__(self, app: FastAPI, rpm: int = 120) -> None:
        super().__init__(app)
        self.rpm = rpm
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._test_daily: dict[str, int] = defaultdict(int)
        self._test_daily_date: str = ""

    def _get_path_limit(self, path: str) -> int:
        """Get per-endpoint rate limit, falling back to global default."""
        for prefix, limit in _PATH_RATE_LIMITS.items():
            if prefix in path:
                return limit
        return self.rpm

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        # Skip rate limiting for health checks
        if request.url.path == "/api/v1/health":
            return await call_next(request)

        client_id = request.headers.get("X-API-Key") or (request.client.host if request.client else "unknown")
        now = time.monotonic()

        # Test key daily cap
        api_key = request.headers.get("X-API-Key", "")
        if api_key.startswith("pk_test_") or api_key.startswith("pk_sb_"):
            today = time.strftime("%Y-%m-%d")
            if today != self._test_daily_date:
                self._test_daily.clear()
                self._test_daily_date = today
            org_key = api_key.split("_")[2] if len(api_key.split("_")) > 2 else client_id
            self._test_daily[org_key] += 1
            if self._test_daily[org_key] > _TEST_KEY_DAILY_CAP:
                return Response(
                    content='{"detail":"Test key daily limit exceeded"}',
                    status_code=429,
                    media_type="application/json",
                    headers={"Retry-After": "86400"},
                )

        # Per-endpoint + per-client sliding window
        path_limit = self._get_path_limit(request.url.path)
        bucket_key = f"{client_id}:{request.url.path}"
        window = self._buckets[bucket_key]

        # Prune entries older than 60s
        cutoff = now - 60
        self._buckets[bucket_key] = window = [t for t in window if t > cutoff]

        if len(window) >= path_limit:
            return Response(
                content='{"detail":"Rate limit exceeded"}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": "60"},
            )

        window.append(now)
        return await call_next(request)


def _validate_config() -> None:
    """Validate required environment variables. Fail-fast on missing config."""
    missing = [k for k in _REQUIRED_ENV if not os.environ.get(k)]
    if not _DEV_MODE:
        missing.extend(k for k in _REQUIRED_ENV_PROD if not os.environ.get(k))
    if missing:
        raise RuntimeError(
            f"Missing required environment variables: {', '.join(missing)}. "
            "Set PRIMUST_DEV_MODE=true to relax auth requirements for local development."
        )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup validation and graceful shutdown."""
    _validate_config()

    # Verify DB connectivity
    for region in ("us", "eu"):
        try:
            pool = await get_pool(region)
            async with pool.acquire() as conn:
                await conn.execute("SELECT 1")
            logger.info("DB connectivity verified for region=%s", region)
        except Exception:
            logger.exception("DB connectivity check failed for region=%s", region)
            raise

    # Verify KMS connectivity (non-blocking — provisional mode is the fallback)
    if not _DEV_MODE:
        for region in ("us", "eu"):
            try:
                from .db import get_region_config
                region_config = get_region_config(region)
                kms_key = region_config.kms_key
                # Lightweight metadata call — just verify we can reach KMS
                from google.cloud import kms as kms_mod
                kms_client = kms_mod.KeyManagementServiceClient()
                # kms_key is already the full version path (e.g. .../cryptoKeyVersions/1)
                kms_client.get_crypto_key_version(request={"name": kms_key})
                logger.info("KMS connectivity verified for region=%s", region)
            except Exception:
                logger.warning(
                    "KMS connectivity check failed for region=%s — "
                    "signing will use provisional mode until KMS is reachable",
                    region,
                    exc_info=True,
                )

    # Load .well-known public keys from KMS
    from .routes.well_known import load_keys_from_kms
    try:
        await load_keys_from_kms()
    except Exception:
        logger.warning("Could not load .well-known public keys (non-fatal)", exc_info=True)

    # Seed built-in policy bundles
    from .services.bundle_seeder import seed_builtin_bundles
    try:
        await seed_builtin_bundles()
    except Exception:
        logger.warning("Could not seed built-in bundles (non-fatal)", exc_info=True)

    logger.info("Primust API started (dev_mode=%s)", _DEV_MODE)
    yield
    await close_pools()
    logger.info("Primust API shutdown complete")


app = FastAPI(title="Primust API", version="0.1.0", lifespan=lifespan)

# CORS — restrict to known origins in production
_ALLOWED_ORIGINS = os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",")
if _DEV_MODE:
    _ALLOWED_ORIGINS = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _ALLOWED_ORIGINS if o.strip()],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "X-API-Key", "Content-Type"],
)
app.add_middleware(RateLimitMiddleware, rpm=_RATE_LIMIT_RPM)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log method, path, status, duration_ms, org_id. Never log tokens/keys/preimages."""

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        start = time.monotonic()
        response = await call_next(request)
        duration_ms = round((time.monotonic() - start) * 1000, 1)

        # Extract org_id from API key prefix (never log the full key)
        api_key = request.headers.get("X-API-Key", "")
        org_id = api_key.split("_")[2] if len(api_key.split("_")) > 2 else None

        logger.info(
            "request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=duration_ms,
            org_id=org_id,
        )
        return response


app.add_middleware(RequestLoggingMiddleware)

from .routes.gaps import router as gaps_router  # noqa: E402
from .routes.packs import router as packs_router  # noqa: E402
from .routes.proofs import router as proofs_router  # noqa: E402
from .routes.runs import router as runs_router  # noqa: E402
from .routes.vpecs import router as vpecs_router  # noqa: E402
from .routes.webhook import router as webhook_router  # noqa: E402
from .routes.well_known import router as well_known_router  # noqa: E402
from .routes.bundles import router as bundles_router  # noqa: E402
from .routes.manifests import router as manifests_router  # noqa: E402
from .routes.onboard import router as onboard_router  # noqa: E402
from .routes.signing_keys import router as signing_keys_router  # noqa: E402
from .routes.reports import router as reports_router  # noqa: E402

app.include_router(runs_router)
app.include_router(vpecs_router)
app.include_router(packs_router)
app.include_router(gaps_router)
app.include_router(proofs_router)
app.include_router(webhook_router)
app.include_router(well_known_router)
app.include_router(bundles_router)
app.include_router(manifests_router)
app.include_router(onboard_router)
app.include_router(signing_keys_router)
app.include_router(reports_router)


@app.get("/health")
@app.get("/healthz")
@app.get("/api/v1/health")
async def health() -> dict[str, Any]:
    """Health check with DB ping and KMS status."""
    fly_region = os.environ.get("FLY_REGION", os.environ.get("PRIMARY_REGION", "us"))
    # Map Fly region codes to Primust region (us/eu)
    region = "eu" if fly_region.startswith("ams") or fly_region.startswith("fra") or fly_region.startswith("lhr") else "us"
    result: dict[str, Any] = {"status": "ok", "region": region, "fly_region": fly_region}

    # DB check
    try:
        pool = await get_pool(region)
        async with pool.acquire() as conn:
            await conn.execute("SELECT 1")
        result["db"] = "ok"
    except Exception:
        result["status"] = "degraded"
        result["db"] = "unreachable"

    # KMS status (cached, 30s TTL)
    global _kms_status, _kms_status_ts
    now = time.monotonic()
    if now - _kms_status_ts > 30:
        if _DEV_MODE:
            _kms_status = {"us": "dev_stub", "eu": "dev_stub"}
        else:
            for r in ("us", "eu"):
                try:
                    from .db import get_region_config
                    rc = get_region_config(r)
                    from google.cloud import kms as kms_mod
                    kms_client = kms_mod.KeyManagementServiceClient()
                    kms_client.get_crypto_key_version(
                        request={"name": rc.kms_key}
                    )
                    _kms_status[r] = "ok"
                except Exception:
                    _kms_status[r] = "unreachable"
        _kms_status_ts = now

    result["kms"] = dict(_kms_status)
    if any(v == "unreachable" for v in _kms_status.values()):
        result["status"] = "degraded"

    return result
