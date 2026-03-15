#!/usr/bin/env bash
# publish-go.sh — Tag and push Go modules for pkg.go.dev indexing
#
# This script tags each Go module at v1.0.0 and pushes the tags.
# pkg.go.dev indexes modules automatically when tags are pushed to GitHub.
#
# Prerequisites:
#   - Git remote "origin" points to github.com/primust-dev/*
#   - No local replace directives in go.mod files
#   - All Go code compiles cleanly
#
# Usage: ./scripts/publish-go.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

VERSION="v1.0.0"

GO_MODULES=(
    "packages/rules-core-go"
    "packages/primust-opa"
)

echo "=== Primust Go Module Publish (P24-D) ==="
echo "Version: $VERSION"
echo ""

# Verify no local replace directives remain
for mod_path in "${GO_MODULES[@]}"; do
    MOD_FILE="$REPO_ROOT/$mod_path/go.mod"
    if [ ! -f "$MOD_FILE" ]; then
        echo "ERROR: $MOD_FILE not found"
        exit 1
    fi
    if grep -q 'replace.*=>.*\.\./' "$MOD_FILE" 2>/dev/null; then
        echo "ERROR: Local replace directive found in $MOD_FILE"
        echo "Remove local replace directives before publishing."
        exit 1
    fi
    echo "OK: $MOD_FILE — no local replace directives"
done

echo ""

# Tag each module
# rules-core-go must be tagged first (dependency for primust-opa)
for mod_path in "${GO_MODULES[@]}"; do
    mod_name="$(basename "$mod_path")"

    # For monorepo tagging, prefix the tag with the module subpath
    TAG="$mod_path/$VERSION"

    echo "--- [$mod_name] tagging $TAG ---"

    if git -C "$REPO_ROOT" rev-parse "$TAG" >/dev/null 2>&1; then
        echo "WARN: Tag $TAG already exists, skipping"
    else
        git -C "$REPO_ROOT" tag -a "$TAG" -m "Release $mod_name $VERSION"
        echo "Created tag: $TAG"
    fi
done

echo ""
echo "Pushing all tags to origin..."
git -C "$REPO_ROOT" push origin --tags

echo ""
echo "=== Go modules tagged and pushed ==="
echo "pkg.go.dev will index these automatically within a few minutes."
echo "Verify at:"
echo "  https://pkg.go.dev/github.com/primust-dev/rules-core-go@$VERSION"
echo "  https://pkg.go.dev/github.com/primust-dev/primust-opa@$VERSION"
