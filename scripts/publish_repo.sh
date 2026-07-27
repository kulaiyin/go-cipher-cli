#!/usr/bin/env bash
set -euo pipefail

# 仓库发布脚本：将生成的 .deb 包添加到 APT 仓库并生成元数据
# 优先使用 reprepro（推荐），其次 aptly，最后回退到 apt-ftparchive。
# 运行前请先执行 scripts/package.sh 生成 .deb。
#
# 用法：
#   bash scripts/publish_repo.sh                  # 输出到默认的 repo/ 目录
#   bash scripts/publish_repo.sh --output-dir DIR # 输出到指定目录（便于 CI 聚合部署内容）
#
# 环境变量：
#   GPG_KEY  覆盖签名 key id（默认读 repo/conf/distributions 的 SignWith）

cd "$(dirname "$0")/.."

REPO_DIR="repo"
PACKAGE_DIR="dist"
DEB_FILE_PATTERN="go-cipher-cli_*.deb"
DISTRIBUTION="stable"
COMPONENT="main"
ARCH="amd64"
OUTPUT_DIR=""   # 默认就地更新 repo/；指定时则把产物复制到该目录

# ---------- 解析参数 ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --output-dir=*)
      OUTPUT_DIR="${1#*=}"
      shift
      ;;
    -h|--help)
      sed -n '3,14p' "$0"
      exit 0
      ;;
    *)
      echo "未知参数：$1（使用 -h 查看帮助）" >&2
      exit 2
      ;;
  esac
done

# GPG 签名密钥 ID（用于对 Release/InRelease 签名）。
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
else
  # ---------------------------------------------------------------------------
  # 方案 B/C：aptly 或 apt-ftparchive
  # 两者都手工构建 dists/ pool/ 结构，便于在 --output-dir 模式下整体复制
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
  #    必须先清理旧的 Release/InRelease，并且把输出写到临时文件再移动到位
  #    ——否则 shell 重定向会先创建空的 Release 文件，apt-ftparchive 扫描
  #    目录时就会把它计入自身校验和（自引用）。
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
fi

# ---------------------------------------------------------------------------
# 签名（生成 Release.gpg 与 InRelease）
#    选 key 的优先级：
#      ① 环境变量 GPG_KEY
#      ② repo/conf/distributions 中的 SignWith 行
#      ③ gpg 默认 key
#    这样无论 gpg 默认 key 是哪个，都会用配置里声明的 key 签名，
#    保证 distributions 声明、实际签名、repo.gpg.key 三者一致。
# ---------------------------------------------------------------------------
DIST_DIR="$REPO_DIR/dists/$DISTRIBUTION"
if [ -z "$GPG_KEY" ]; then
  GPG_KEY=$(awk -F': ' '/^SignWith:/ {print $2; exit}' "$REPO_DIR/conf/distributions" | tr -d ' ')
fi

if [ -n "$GPG_KEY" ] && [ "$GPG_KEY" != "YOUR-KEY-ID" ]; then
  # 提供无 TTY 的密码管道（密钥若无密码则无影响）
  gpg --default-key "$GPG_KEY" --batch --yes --pinentry-mode loopback \
    -abs -o "$DIST_DIR/Release.gpg" "$DIST_DIR/Release"
  gpg --default-key "$GPG_KEY" --batch --yes --pinentry-mode loopback \
    --clearsign -o "$DIST_DIR/InRelease" "$DIST_DIR/Release"
  echo "已使用 GPG Key $GPG_KEY 生成 Release.gpg 与 InRelease"
elif gpg --list-keys >/dev/null 2>&1 && [ -n "$(gpg --list-keys --with-colons | awk -F: '/^pub/{print $5}' | head -1)" ]; then
  gpg --batch --yes --pinentry-mode loopback -abs -o "$DIST_DIR/Release.gpg" "$DIST_DIR/Release"
  gpg --batch --yes --pinentry-mode loopback --clearsign -o "$DIST_DIR/InRelease" "$DIST_DIR/Release"
  echo "已使用默认 GPG Key 生成 Release.gpg 与 InRelease"
else
  echo "警告：未配置 GPG 密钥，跳过签名。客户端安装时需使用 [trusted=yes]。" >&2
fi

# ---------------------------------------------------------------------------
# 导出公钥到 repo/repo.gpg.key（客户端 apt 安装时需要导入）
# ---------------------------------------------------------------------------
if [ -n "$GPG_KEY" ] && [ "$GPG_KEY" != "YOUR-KEY-ID" ]; then
  gpg --armor --export "$GPG_KEY" > "$REPO_DIR/repo.gpg.key"
  echo "已导出公钥到 $REPO_DIR/repo.gpg.key"
elif gpg --list-keys >/dev/null 2>&1; then
  DEFAULT_KEY=$(gpg --list-keys --with-colons | awk -F: '/^pub/{print $5; exit}')
  if [ -n "$DEFAULT_KEY" ]; then
    gpg --armor --export "$DEFAULT_KEY" > "$REPO_DIR/repo.gpg.key"
    echo "已导出默认公钥到 $REPO_DIR/repo.gpg.key"
  fi
fi

# ---------------------------------------------------------------------------
# --output-dir：把仓库产物整体复制到指定目录（CI 部署用）
# ---------------------------------------------------------------------------
if [ -n "$OUTPUT_DIR" ]; then
  mkdir -p "$OUTPUT_DIR"
  rm -rf "$OUTPUT_DIR/dists" "$OUTPUT_DIR/pool"
  cp -r "$REPO_DIR/dists" "$REPO_DIR/pool" "$OUTPUT_DIR/"
  [ -f "$REPO_DIR/repo.gpg.key" ] && cp "$REPO_DIR/repo.gpg.key" "$OUTPUT_DIR/"
  echo "已复制仓库产物到：$OUTPUT_DIR"
fi

echo "仓库元数据已更新，目录：$REPO_DIR"
