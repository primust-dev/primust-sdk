#!/bin/bash
# Integration test runner — Postgres (Docker) + API (host) + SDK tests
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PYTHON="${PYTHON:-python}"

echo "=== Primust Integration Tests ==="
echo "Repo: $REPO_ROOT"
echo "Python: $($PYTHON --version)"

# 1. Start Postgres
echo "--- Starting Postgres on port 5433 ---"
cd "$SCRIPT_DIR"
docker compose up -d --wait
echo "Postgres ready."

# 2. Install API + SDK + connectors if needed
echo "--- Installing dependencies ---"
cd "$REPO_ROOT/apps/api" && $PYTHON -m pip install -e ".[dev]" -q
cd "$REPO_ROOT/packages/sdk-python" && $PYTHON -m pip install -e ".[dev]" -q
cd "$REPO_ROOT/packages/primust-connectors" && $PYTHON -m pip install -e ".[dev]" -q

# 3. Run tests (conftest.py handles API server lifecycle)
echo "--- Running integration tests ---"
cd "$REPO_ROOT"
$PYTHON -m pytest tests/integration/ -v --tb=short "$@"
EXIT_CODE=$?

# 4. Teardown
echo "--- Tearing down ---"
cd "$SCRIPT_DIR"
docker compose down -v

exit $EXIT_CODE
