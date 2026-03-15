#!/usr/bin/env bash
# publish-jvm.sh — Build and deploy all Primust JVM packages to Maven Central
# via Sonatype OSSRH. Publishes in dependency order.
#
# Prerequisites:
#   - GPG key configured for signing
#   - ~/.m2/settings.xml with OSSRH credentials (server id: ossrh)
#   - Java 11+ and Maven 3.8+ installed
#
# Usage: ./scripts/publish-jvm.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PACKAGES_DIR="$(cd "$SCRIPT_DIR/../packages" && pwd)"

MODULES=(
    primust-rules-core
    primust-cedar
    primust-drools
    primust-odm
)

echo "=== Primust JVM Publish (P24-D) ==="
echo "Target: Maven Central via Sonatype Central Portal"
echo ""

for module in "${MODULES[@]}"; do
    MODULE_DIR="$PACKAGES_DIR/$module"
    if [ ! -f "$MODULE_DIR/pom.xml" ]; then
        echo "ERROR: $MODULE_DIR/pom.xml not found"
        exit 1
    fi

    echo "--- [$module] clean verify deploy ---"
    mvn -f "$MODULE_DIR/pom.xml" clean deploy \
        -Dmaven.test.skip=false
    echo "--- [$module] deployed ---"
    echo ""
done

echo "=== All JVM packages published to Maven Central ==="
echo "Check https://central.sonatype.com/publishing/deployments for status."
