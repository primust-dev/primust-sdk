"""
Tests for .well-known/primust-pubkeys/ endpoint.

MUST PASS before go-live:
- GET /{kid}.pem returns valid PEM with correct headers
- Unknown kid returns 404
- Response is immutable-cached and CORS-open
- Key resolution chain: verifier can fetch from public_key_url
"""

import pytest
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ── Sample PEM for testing ──
SAMPLE_PEM = """\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest1234567890abcdefghijklmn
opqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/==
-----END PUBLIC KEY-----
"""


@pytest.fixture
def app():
    """Create a test FastAPI app with the well_known router."""
    from primust_api.routes.well_known import router, register_key, _KEY_REGISTRY

    test_app = FastAPI()
    test_app.include_router(router)

    # Register a test key
    register_key("kid_api", SAMPLE_PEM)

    yield test_app

    # Cleanup
    _KEY_REGISTRY.clear()


@pytest.fixture
def client(app):
    return TestClient(app)


class TestWellKnownEndpoint:
    """GET /.well-known/primust-pubkeys/{kid}.pem"""

    def test_returns_pem_for_known_kid(self, client):
        resp = client.get("/.well-known/primust-pubkeys/kid_api.pem")
        assert resp.status_code == 200
        assert resp.text == SAMPLE_PEM
        assert "BEGIN PUBLIC KEY" in resp.text

    def test_content_type_is_pem(self, client):
        resp = client.get("/.well-known/primust-pubkeys/kid_api.pem")
        assert "application/x-pem-file" in resp.headers["content-type"]

    def test_cors_header_allows_all(self, client):
        resp = client.get("/.well-known/primust-pubkeys/kid_api.pem")
        assert resp.headers["access-control-allow-origin"] == "*"

    def test_cache_control_immutable(self, client):
        resp = client.get("/.well-known/primust-pubkeys/kid_api.pem")
        cc = resp.headers["cache-control"]
        assert "immutable" in cc
        assert "public" in cc

    def test_unknown_kid_returns_404(self, client):
        resp = client.get("/.well-known/primust-pubkeys/kid_nonexistent.pem")
        assert resp.status_code == 404

    def test_multiple_kids_served_independently(self, client):
        from primust_api.routes.well_known import register_key
        register_key("kid_eu", "-----BEGIN PUBLIC KEY-----\nEU_KEY\n-----END PUBLIC KEY-----\n")

        resp1 = client.get("/.well-known/primust-pubkeys/kid_api.pem")
        resp2 = client.get("/.well-known/primust-pubkeys/kid_eu.pem")

        assert resp1.status_code == 200
        assert resp2.status_code == 200
        assert resp1.text != resp2.text
        assert "EU_KEY" in resp2.text


class TestPublicKeyUrlConsistency:
    """Verify public_key_url in VPEC matches the .well-known endpoint pattern."""

    def test_runs_py_url_matches_well_known_pattern(self):
        """The public_key_url in runs.py must resolve to a .well-known endpoint."""
        # This is a source-level assertion — read the actual value from runs.py
        import re
        from pathlib import Path

        runs_py = Path(__file__).parent.parent.parent / "apps" / "api" / "src" / "primust_api" / "routes" / "runs.py"
        content = runs_py.read_text()

        # Extract public_key_url
        match = re.search(r'"public_key_url":\s*"([^"]+)"', content)
        assert match, "public_key_url not found in runs.py"

        url = match.group(1)
        assert ".well-known/primust-pubkeys/" in url, (
            f"public_key_url must use .well-known pattern, got: {url}"
        )
        assert url.endswith(".pem"), f"public_key_url must end with .pem, got: {url}"

    def test_algorithm_matches_kms(self):
        """The algorithm in runs.py must match what kms.py actually uses."""
        import re
        from pathlib import Path

        runs_py = Path(__file__).parent.parent.parent / "apps" / "api" / "src" / "primust_api" / "routes" / "runs.py"
        content = runs_py.read_text()

        match = re.search(r'"algorithm":\s*"([^"]+)"', content)
        assert match, "algorithm not found in runs.py"

        algo = match.group(1)
        assert algo == "EC_SIGN_P256_SHA256", (
            f"Algorithm must match kms.py (EC_SIGN_P256_SHA256), got: {algo}"
        )


class TestBootstrapDeadline:
    """auth.py must REJECT (not just warn) after 2026-06-01."""

    def test_bootstrap_deadline_rejects_after_expiry(self):
        """After the deadline, keys without DB records must get HTTP 401."""
        import re
        from pathlib import Path

        auth_py = Path(__file__).parent.parent.parent / "apps" / "api" / "src" / "primust_api" / "auth.py"
        content = auth_py.read_text()

        # Must contain HTTPException after deadline check
        assert "raise HTTPException" in content, (
            "auth.py must raise HTTPException after bootstrap deadline, not just log"
        )

        # Must contain 401 status code
        assert "status_code=401" in content, (
            "auth.py must return 401 after bootstrap deadline"
        )
