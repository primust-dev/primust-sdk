#!/usr/bin/env bash
# Publish Python packages to PyPI.
#
# Usage:
#   ./scripts/publish-python.sh          # publish to PyPI
#   ./scripts/publish-python.sh --test   # publish to TestPyPI (dry run)
#
# Prerequisites:
#   pip install build twine
#   TWINE_USERNAME / TWINE_PASSWORD (or __token__ / pypi-xxx)
#
# Publish order matters — downstream packages depend on upstream:
#   1. primust-artifact-core
#   2. primust (SDK)
#   3. primust-verify

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
    "packages/artifact-core-py"
    "packages/sdk-python"
    "packages/verifier-py"
)

for pkg_dir in "${PACKAGES[@]}"; do
    full_path="${REPO_ROOT}/${pkg_dir}"
    pkg_name=$(grep '^name' "${full_path}/pyproject.toml" | head -1 | sed 's/.*= *"\(.*\)"/\1/')

    echo ""
    echo "──────────────────────────────────────────"
    echo "Building ${pkg_name} from ${pkg_dir}"
    echo "──────────────────────────────────────────"

    # Clean previous builds
    rm -rf "${full_path}/dist"

    # Build sdist + wheel
    python -m build "${full_path}"

    echo "Uploading ${pkg_name}..."
    twine upload ${TESTPYPI} "${full_path}/dist/"*

    echo "${pkg_name} published successfully."
done

echo ""
echo "==> All Python packages published."
echo ""
echo "Verify:"
echo "  pip install primust==$(grep 'version' ${REPO_ROOT}/packages/sdk-python/pyproject.toml | head -1 | sed 's/.*\"\(.*\)\"/\1/')"
echo "  pip install primust-verify==$(grep 'version' ${REPO_ROOT}/packages/verifier-py/pyproject.toml | head -1 | sed 's/.*\"\(.*\)\"/\1/')"
echo "  python -c 'from primust import Pipeline; print(\"SDK OK\")'"
echo "  primust --version"
echo "  primust-verify --help"
