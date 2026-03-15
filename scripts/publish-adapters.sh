#!/usr/bin/env bash
# Publish Python AI adapters to PyPI.
#
# Usage:
#   ./scripts/publish-adapters.sh          # publish to PyPI
#   ./scripts/publish-adapters.sh --test   # publish to TestPyPI
#
# Prerequisites:
#   pip install build twine
#   primust>=1.0.0 must already be on PyPI (run publish-python.sh first)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TESTPYPI=""

if [[ "${1:-}" == "--test" ]]; then
    TESTPYPI="--repository testpypi"
    echo "==> Publishing to TestPyPI (dry run)"
else
    echo "==> Publishing to PyPI (production)"
fi

PACKAGES=(
    "packages/primust-langgraph"
    "packages/primust-openai-agents"
    "packages/primust-google-adk"
    "packages/primust-otel"
)

for pkg_dir in "${PACKAGES[@]}"; do
    full_path="${REPO_ROOT}/${pkg_dir}"
    pkg_name=$(grep '^name' "${full_path}/pyproject.toml" | head -1 | sed 's/.*= *"\(.*\)"/\1/')

    echo ""
    echo "──────────────────────────────────────────"
    echo "Building ${pkg_name} from ${pkg_dir}"
    echo "──────────────────────────────────────────"

    rm -rf "${full_path}/dist"
    python -m build "${full_path}"

    echo "Uploading ${pkg_name}..."
    twine upload ${TESTPYPI} "${full_path}/dist/"*

    echo "${pkg_name} published successfully."
done

echo ""
echo "==> All AI adapters published."
echo ""
echo "Verify:"
echo "  pip install primust-langgraph primust-openai-agents primust-google-adk primust-otel"
