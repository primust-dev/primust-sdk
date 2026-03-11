"""
Primust API — FastAPI control plane.

Deployment: Fly.io (US East + Frankfurt)
Auth: Clerk JWT + API key (pk_live/pk_test)
DB: Neon Postgres, dual-region (DATABASE_URL_US / DATABASE_URL_EU)
"""

from __future__ import annotations

import os

from fastapi import FastAPI

from .db import close_pools
from .routes.gaps import router as gaps_router
from .routes.packs import router as packs_router
from .routes.runs import router as runs_router
from .routes.vpecs import router as vpecs_router

app = FastAPI(title="Primust API", version="0.1.0")

app.include_router(runs_router)
app.include_router(vpecs_router)
app.include_router(packs_router)
app.include_router(gaps_router)


@app.on_event("shutdown")
async def shutdown() -> None:
    await close_pools()


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    region = os.environ.get("FLY_REGION", os.environ.get("PRIMARY_REGION", "us"))
    return {"status": "ok", "region": region}
