#!/bin/bash
# Copyright (C) 2025 Joshua Goldstein

# Build script for gemini-pwd deployment
# Builds the Linux amd64 binary and bundles it, with everything deploy.sh
# needs, into deploy/gemini-pwd-<timestamp>.tar.gz.
#
# The archive extracts to a single gemini_pwd/ directory:
#   gemini_pwd/gemini-pwd               application binary
#   gemini_pwd/templates/, static/      web assets
#   gemini_pwd/deploy.sh                server setup script
#   gemini_pwd/gemini_pwd.service       systemd unit
#   gemini_pwd/apache-gemini_pwd.conf   Apache reverse-proxy vhost
#   gemini_pwd/README.md
#
# Usage: ./deploy/build-for-deployment.sh   (works from any directory)
#   SKIP_TESTS=1  skip running the test suite before packaging

set -euo pipefail

echo "=== Building Gemini PWD for Deployment ==="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

if [ ! -f "main.go" ]; then
    echo "Error: main.go not found in $PROJECT_ROOT" >&2
    exit 1
fi

TARGET_OS="linux"
TARGET_ARCH="amd64"
BINARY_NAME="gemini-pwd"
PACKAGE_NAME="gemini_pwd"   # top-level directory inside the archive
ARCHIVE="$SCRIPT_DIR/gemini-pwd-$(date +%Y%m%d-%H%M%S).tar.gz"

# The SQLite driver (mattn/go-sqlite3) requires CGO. Go silently disables CGO
# when cross-compiling, producing a binary that fails at runtime, so build
# natively on linux/amd64 (e.g. WSL) unless a cross C compiler is supplied via CC.
HOST_OS="$(go env GOHOSTOS)"
HOST_ARCH="$(go env GOHOSTARCH)"
if [[ "$HOST_OS/$HOST_ARCH" != "$TARGET_OS/$TARGET_ARCH" && -z "${CC:-}" ]]; then
    echo "Error: host is $HOST_OS/$HOST_ARCH but the target is $TARGET_OS/$TARGET_ARCH." >&2
    echo "The SQLite driver needs CGO, so build on linux/amd64 (e.g. in WSL), or set CC" >&2
    echo "to a $TARGET_OS/$TARGET_ARCH cross C compiler (e.g. CC=x86_64-linux-gnu-gcc)." >&2
    exit 1
fi

if [[ "${SKIP_TESTS:-0}" != "1" ]]; then
    echo "Running tests..."
    CGO_ENABLED=1 go test ./...
fi

# Stage in a fresh temporary directory so no stale files from earlier builds
# end up in the package.
STAGE_ROOT="$(mktemp -d)"
trap 'rm -rf "$STAGE_ROOT"' EXIT
STAGE="$STAGE_ROOT/$PACKAGE_NAME"
mkdir -p "$STAGE"

echo "Building for $TARGET_OS/$TARGET_ARCH..."
CGO_ENABLED=1 GOOS="$TARGET_OS" GOARCH="$TARGET_ARCH" \
    go build -trimpath -ldflags "-s -w" -o "$STAGE/$BINARY_NAME" .

echo "Copying application files..."
cp -r templates "$STAGE/"
cp -r static "$STAGE/"
rm -f "$STAGE/templates/test.html"   # debug page, not for production
cp README.md "$STAGE/"

echo "Copying deployment files..."
cp "$SCRIPT_DIR/deploy.sh" "$SCRIPT_DIR/gemini_pwd.service" "$SCRIPT_DIR/apache-gemini_pwd.conf" "$STAGE/"
# Normalize permissions (sources on a Windows/NTFS mount all appear executable)
find "$STAGE" -type d -exec chmod 755 {} +
find "$STAGE" -type f -exec chmod 644 {} +
chmod 755 "$STAGE/deploy.sh" "$STAGE/$BINARY_NAME"

echo "Creating deployment package..."
tar -czf "$ARCHIVE" -C "$STAGE_ROOT" "$PACKAGE_NAME"

echo ""
echo "Build completed: $ARCHIVE"
echo ""
echo "To deploy on a new server:"
echo "  1. scp \"$ARCHIVE\" user@server:/tmp/"
echo "  2. On the server:"
echo "       cd /tmp && tar -xzf $(basename "$ARCHIVE")"
echo "       sudo /tmp/$PACKAGE_NAME/deploy.sh"
echo ""
echo "deploy.sh performs a full first-time server setup; for upgrading an existing"
echo "server, see the upgrade steps in deploy/DEPLOYMENT.md."
