"""
Integration test fixtures — real Postgres + real FastAPI server + real SDK.

Infrastructure:
  - Postgres 15 in Docker on port 5433 (tmpfs, ephemeral)
  - FastAPI API server on port 8100 (host process)
  - SDK pointed at http://localhost:8100

Usage:
  cd tests/integration && bash run.sh
  OR: docker compose up -d --wait && pytest -v (if API already running)
"""

from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

API_PORT = 8100
API_URL = f"http://localhost:{API_PORT}"
API_KEY_SECRET = "test_secret_for_integration"
ORG_ID = "testorg"
REGION = "us"
DB_URL = "postgresql://primust:primust_test@localhost:5433/primust_test"

INTEGRATION_DIR = Path(__file__).parent


def _make_api_key(mode: str = "test", org_id: str = ORG_ID, region: str = REGION) -> str:
    """Generate a valid HMAC-signed API key."""
    prefix = f"pk_{mode}_{org_id}_{region}"
    secret = hmac.new(
        API_KEY_SECRET.encode(), prefix.encode(), hashlib.sha256
    ).hexdigest()[:32]
    return f"{prefix}_{secret}"


# ---------------------------------------------------------------------------
# Session-scoped fixtures (one per test session)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def docker_postgres():
    """Start Postgres container, wait for healthy, yield, tear down."""
    compose_file = INTEGRATION_DIR / "docker-compose.yml"
    subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "up", "-d", "--wait"],
        check=True,
        cwd=str(INTEGRATION_DIR),
    )
    yield
    subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "down", "-v"],
        check=False,
        cwd=str(INTEGRATION_DIR),
    )


@pytest.fixture(scope="session")
def api_server(docker_postgres):
    """Start the FastAPI API server as a subprocess on port 8100."""
    env = os.environ.copy()
    env.update({
        "DATABASE_URL_US": DB_URL,
        "DATABASE_URL_EU": DB_URL,
        "PRIMUST_DEV_MODE": "true",
        "PRIMUST_API_KEY_SECRET": API_KEY_SECRET,
    })

    # Find the API source directory
    api_dir = INTEGRATION_DIR.parent.parent / "apps" / "api"

    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            "primust_api.main:app",
            "--port", str(API_PORT),
            "--host", "127.0.0.1",
            "--log-level", "warning",
        ],
        env=env,
        cwd=str(api_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for API to be ready
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(f"{API_URL}/api/v1/health", timeout=2.0)
            if resp.status_code == 200:
                break
        except httpx.ConnectError:
            pass
        time.sleep(0.5)
    else:
        stdout = proc.stdout.read().decode() if proc.stdout else ""
        stderr = proc.stderr.read().decode() if proc.stderr else ""
        proc.kill()
        pytest.fail(
            f"API server did not start within 30s.\n"
            f"stdout: {stdout[:2000]}\nstderr: {stderr[:2000]}"
        )

    yield proc

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


# ---------------------------------------------------------------------------
# Per-test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def api_key() -> str:
    """Valid test API key."""
    return _make_api_key("test")


@pytest.fixture
def api_url() -> str:
    return API_URL


@pytest.fixture
def http_client(api_server, api_key) -> httpx.Client:
    """httpx client pre-configured with API key auth."""
    return httpx.Client(
        base_url=API_URL,
        headers={"X-API-Key": api_key},
        timeout=10.0,
    )


@pytest.fixture
def legacy_pipeline(api_server, api_key, tmp_path):
    """Legacy Pipeline pointed at the real local API."""
    from primust import Pipeline
    return Pipeline(
        api_key=api_key,
        workflow_id="integration-test",
        policy="default",
        surface_id="default",
        _base_url=API_URL,
        queue_path=tmp_path / "queue.db",
    )


@pytest.fixture
def run_pipeline(api_server, api_key, tmp_path):
    """Run-based Pipeline pointed at the real local API."""
    from primust import Pipeline
    return Pipeline(
        api_key=api_key,
        workflow_id="integration-test-run",
        surface_id="default",
        _base_url=API_URL,
        queue_path=tmp_path / "queue.db",
    )
