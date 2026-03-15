#!/usr/bin/env bash
# Publish TypeScript packages to npm.
#
# Usage:
#   ./scripts/publish-npm.sh          # publish to npm
#   ./scripts/publish-npm.sh --dry    # dry run (no publish)
#
# Prerequisites:
#   npm login (or NPM_TOKEN set)
#   pnpm install && pnpm build
#
# Publish order matters — downstream packages depend on upstream:
#   1. @primust/artifact-core
#   2. @primust/sdk
#   3. @primust/otel

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DRY_RUN=""

if [[ "${1:-}" == "--dry" ]]; then
    DRY_RUN="--dry-run"
    echo "==> Dry run (no publish)"
else
    echo "==> Publishing to npm (production)"
fi

# Build all packages first
echo "Building all packages..."
cd "${REPO_ROOT}"
pnpm build

PACKAGES=(
    "packages/artifact-core"
    "packages/sdk-js"
    "packages/primust-otel-js"
)

for pkg_dir in "${PACKAGES[@]}"; do
    full_path="${REPO_ROOT}/${pkg_dir}"
    pkg_name=$(node -e "console.log(require('${full_path}/package.json').name)")

    echo ""
    echo "──────────────────────────────────────────"
    echo "Publishing ${pkg_name} from ${pkg_dir}"
    echo "──────────────────────────────────────────"

    cd "${full_path}"
    pnpm publish --access public --no-git-checks ${DRY_RUN}

    echo "${pkg_name} published successfully."
done

echo ""
echo "==> All npm packages published."
echo ""
echo "Verify:"
echo "  npm install @primust/sdk@1.0.0"
echo "  npm install @primust/otel@1.0.0"
