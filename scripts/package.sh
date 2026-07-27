#!/usr/bin/env bash
set -euo pipefail

# 打包脚本：优先使用 goreleaser 生成 Debian 包；若不可用，则使用 dpkg-deb 手工打包。
# 运行前请确保 GOPATH 和 GOROOT 正确，或手动设置环境变量。

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
  echo "goreleaser 未安装，尝试通过 npm 安装 goreleaser..."
  if command -v npm >/dev/null 2>&1; then
    if npm install -g @goreleaser/goreleaser; then
      export PATH="$PATH:$(npm bin -g)"
    else
      echo "警告：npm 安装 goreleaser 失败，将回退到手工 dpkg-deb 打包。" >&2
    fi
  else
    echo "警告：系统中未找到 npm，无法自动安装 goreleaser。" >&2
  fi
fi

if command -v goreleaser >/dev/null 2>&1; then
  echo "使用 goreleaser 打包..."
  if goreleaser release --snapshot --clean; then
    echo "打包完成，输出目录：dist/"
    exit 0
  fi
  echo "goreleaser 打包失败，改为使用 dpkg-deb 手工打包。" >&2
fi

echo "goreleaser 仍然不可用或打包失败，改为使用 dpkg-deb 手工打包。"

BUILD_DIR="build"
PKG_DIR="$BUILD_DIR/package"
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"

# 编译可执行文件
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

echo "手工打包完成：$DEB_FILE"
