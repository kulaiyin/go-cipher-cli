#!/usr/bin/env bash
set -euo pipefail

# Build script: prefer goreleaser to build the Debian package; fallback to dpkg-deb.
# Ensure GOPATH and GOROOT are set correctly before running.

cd "$(dirname "$0")/.."

export GOROOT=/usr/local/go
export GOPATH=/home/developer/go
export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"

PACKAGE_NAME="go-cipher-cli"
VERSION="0.1.0"
ARCH="amd64"
OUTPUT_DIR="dist"
DEB_FILE="$OUTPUT_DIR/${PACKAGE_NAME}_${VERSION}_linux_${ARCH}.deb"

mkdir -p "$OUTPUT_DIR"

if ! command -v goreleaser >/dev/null 2>&1; then
  echo "goreleaser not found, trying to install via npm..."
  if command -v npm >/dev/null 2>&1; then
    if npm install -g @goreleaser/goreleaser; then
      export PATH="$PATH:$(npm bin -g)"
    else
      echo "warning: npm install of goreleaser failed, falling back to manual dpkg-deb build." >&2
    fi
  else
    echo "warning: npm not found, cannot auto-install goreleaser." >&2
  fi
fi

if command -v goreleaser >/dev/null 2>&1; then
  echo "building with goreleaser..."
  if goreleaser release --snapshot --clean; then
    echo "build complete, output: dist/"
    exit 0
  fi
  echo "goreleaser build failed, switching to manual dpkg-deb build." >&2
fi

echo "goreleaser unavailable or failed, using manual dpkg-deb build."

BUILD_DIR="build"
PKG_DIR="$BUILD_DIR/package"
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"

# Build the binary
GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 $GOROOT/bin/go build -o "$PKG_DIR/usr/bin/$PACKAGE_NAME" ./main.go

cat > "$PKG_DIR/DEBIAN/control" <<EOF
Package: $PACKAGE_NAME
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Maintainer: Your Name <you@example.com>
Description: A Go CLI tool for configuration, logging, interactive prompts, and progress.
EOF

chmod 0755 "$PKG_DIR/usr/bin/$PACKAGE_NAME"
chmod 0755 "$PKG_DIR/DEBIAN"

rm -f "$DEB_FILE"
dpkg-deb --build "$PKG_DIR" "$DEB_FILE"

echo "manual build complete: $DEB_FILE"
