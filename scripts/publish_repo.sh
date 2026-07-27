#!/usr/bin/env bash
set -euo pipefail

# 仓库发布脚本：将生成的 .deb 包添加到 APT 仓库并生成元数据
# 优先使用 reprepro（推荐），其次 aptly，最后回退到 apt-ftparchive。
# 运行前请先执行 scripts/package.sh 生成 .deb。

cd "$(dirname "$0")/.."

REPO_DIR="repo"
PACKAGE_DIR="dist"
DEB_FILE_PATTERN="go-cipher-cli_*.deb"
DISTRIBUTION="stable"
COMPONENT="main"
ARCH="amd64"

# GPG 签名密钥 ID（用于对 Release/InRelease 签名）。
# 可通过环境变量覆盖，默认使用 go-cipher-cli builder 密钥。
GPG_KEY="${GPG_KEY:-}"

if [ ! -d "$REPO_DIR/conf" ]; then
  echo "错误：仓库配置目录不存在：$REPO_DIR/conf" >&2
  exit 1
fi

DEB_FILE=$(find "$PACKAGE_DIR" -maxdepth 2 -type f -name "$DEB_FILE_PATTERN" | sort | tail -n 1)
if [ -z "$DEB_FILE" ]; then
  echo "错误：未找到 .deb 包，请先执行 scripts/package.sh" >&2
  exit 1
fi

echo "使用 .deb 包：$DEB_FILE"

# ---------------------------------------------------------------------------
# 方案 A：reprepro（推荐）
# ---------------------------------------------------------------------------
if command -v reprepro >/dev/null 2>&1; then
  echo "使用 reprepro 发布仓库..."
  reprepro -b "$REPO_DIR" includedeb "$DISTRIBUTION" "$DEB_FILE"
  echo "仓库元数据已更新（reprepro），目录：$REPO_DIR"
  exit 0
fi

# ---------------------------------------------------------------------------
# 方案 B：aptly（替代方案）
# ---------------------------------------------------------------------------
if command -v aptly >/dev/null 2>&1; then
  echo "使用 aptly 发布仓库..."
  APTLY_REPO="go-cipher-cli-repo"
  if ! aptly repo show "$APTLY_REPO" >/dev/null 2>&1; then
    aptly repo create -distribution="$DISTRIBUTION" -component="$COMPONENT" "$APTLY_REPO"
  fi
  aptly repo add "$APTLY_REPO" "$DEB_FILE"
  aptly publish repo -architectures="$ARCH" "$APTLY_REPO"
  echo "仓库元数据已更新（aptly）。"
  exit 0
fi

# ---------------------------------------------------------------------------
# 方案 C：apt-ftparchive（reprepro/aptly 不可用时的回退方案）
# ---------------------------------------------------------------------------
if ! command -v apt-ftparchive >/dev/null 2>&1; then
  echo "错误：未找到 reprepro / aptly / apt-ftparchive，请安装其中之一。" >&2
  exit 1
fi

echo "reprepro/aptly 不可用，回退到 apt-ftparchive 手工生成仓库元数据..."

DIST_DIR="$REPO_DIR/dists/$DISTRIBUTION"
COMP_DIR="$DIST_DIR/$COMPONENT/binary-$ARCH"
POOL_DIR="$REPO_DIR/pool/$COMPONENT/g/go-cipher-cli"
DIST_REL="dists/$DISTRIBUTION"

mkdir -p "$COMP_DIR" "$POOL_DIR"
cp -f "$DEB_FILE" "$POOL_DIR/"

# 注意：apt-ftparchive 必须在仓库根目录内执行，这样 Packages 中的
# Filename 字段才会是相对仓库根的路径（如 pool/main/g/.../x.deb），
# 而不是带 repo/ 前缀的错误路径。
pushd "$REPO_DIR" >/dev/null

# 1. 生成 Packages 索引（输出相对仓库根的 Filename）
apt-ftparchive packages pool > "$DIST_REL/$COMPONENT/binary-$ARCH/Packages"
gzip -kf "$DIST_REL/$COMPONENT/binary-$ARCH/Packages"

# 2. 生成 Release 文件（仅扫描 dists/<suite> 下的内容）。
#    注意：必须先清理旧的 Release/InRelease，并且把输出写到临时文件
#    再移动到位——否则 shell 重定向会先创建空的 Release 文件，
#    apt-ftparchive 扫描目录时就会把它计入自身校验和（自引用）。
rm -f "$DIST_REL/Release" "$DIST_REL/Release.gpg" "$DIST_REL/InRelease"
apt-ftparchive \
  -o APT::FTPArchive::Release::Origin="go-cipher-cli" \
  -o APT::FTPArchive::Release::Label="go-cipher-cli" \
  -o APT::FTPArchive::Release::Suite="$DISTRIBUTION" \
  -o APT::FTPArchive::Release::Codename="$DISTRIBUTION" \
  -o APT::FTPArchive::Release::Architectures="$ARCH" \
  -o APT::FTPArchive::Release::Components="$COMPONENT" \
  release "$DIST_REL" > "$DIST_REL/Release.new"
mv "$DIST_REL/Release.new" "$DIST_REL/Release"

popd >/dev/null

echo "已生成 $DIST_DIR/Release"

# 3. 签名（生成 Release.gpg 与 InRelease）
if [ -n "$GPG_KEY" ]; then
  gpg --default-key "$GPG_KEY" --batch --yes -abs -o "$DIST_DIR/Release.gpg" "$DIST_DIR/Release"
  gpg --default-key "$GPG_KEY" --batch --yes --clearsign -o "$DIST_DIR/InRelease" "$DIST_DIR/Release"
  echo "已使用 GPG Key $GPG_KEY 生成 Release.gpg 与 InRelease"
elif gpg --list-keys >/dev/null 2>&1 && [ -n "$(gpg --list-keys --with-colons | grep '^pub')" ]; then
  gpg --batch --yes -abs -o "$DIST_DIR/Release.gpg" "$DIST_DIR/Release"
  gpg --batch --yes --clearsign -o "$DIST_DIR/InRelease" "$DIST_DIR/Release"
  echo "已使用默认 GPG Key 生成 Release.gpg 与 InRelease"
else
  echo "警告：未配置 GPG 密钥，跳过签名。客户端安装时需使用 [trusted=yes]。" >&2
fi

echo "仓库元数据已更新（apt-ftparchive），目录：$REPO_DIR"
