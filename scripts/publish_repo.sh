#!/usr/bin/env bash
set -euo pipefail

# Repo publish script: adds a .deb to the APT repo and generates metadata.
# Prefers reprepro (recommended), then aptly, finally falls back to apt-ftparchive.
# Run scripts/package.sh first to build the .deb.
#
# Usage:
#   bash scripts/publish_repo.sh                  # output to default repo/ dir
#   bash scripts/publish_repo.sh --output-dir DIR # output to given dir (for CI aggregation)
#
# Environment:
#   GPG_KEY  overrides the signing key ID (default: read from repo/conf/distributions SignWith)

cd "$(dirname "$0")/.."

REPO_DIR="repo"
PACKAGE_DIR="dist"
DISTRIBUTION="stable"
COMPONENT="main"
ARCH="amd64"
DEB_FILE_PATTERN="go-cipher-cli_*_linux_${ARCH}.deb"
OUTPUT_DIR=""   # empty: update repo/ in-place; set: copy artifacts to target dir

# ---------- arg parsing ----------
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
      echo "unknown argument: $1 (use -h for help)" >&2
      exit 2
      ;;
  esac
done

# GPG signing key ID (used to sign Release/InRelease).
GPG_KEY="${GPG_KEY:-}"

if [ ! -d "$REPO_DIR/conf" ]; then
  echo "error: repo config directory not found: $REPO_DIR/conf" >&2
  exit 1
fi

DEB_FILE=$(find "$PACKAGE_DIR" -maxdepth 2 -type f -name "$DEB_FILE_PATTERN" | sort | tail -n 1)
if [ -z "$DEB_FILE" ]; then
  echo "error: no .deb package found, run scripts/package.sh first" >&2
  exit 1
fi

echo "using .deb package: $DEB_FILE"

# ---------------------------------------------------------------------------
# Option A: reprepro (recommended)
# ---------------------------------------------------------------------------
if command -v reprepro >/dev/null 2>&1; then
  echo "publishing repo with reprepro..."
  reprepro -b "$REPO_DIR" includedeb "$DISTRIBUTION" "$DEB_FILE"
  echo "repo metadata updated (reprepro), dir: $REPO_DIR"
else
  # ---------------------------------------------------------------------------
  # Options B/C: aptly or apt-ftparchive
  # Both manually build dists/ pool/ structure for easy --output-dir copy
  # ---------------------------------------------------------------------------
  if command -v aptly >/dev/null 2>&1; then
    echo "publishing repo with aptly..."
    APTLY_REPO="go-cipher-cli-repo"
    if ! aptly repo show "$APTLY_REPO" >/dev/null 2>&1; then
      aptly repo create -distribution="$DISTRIBUTION" -component="$COMPONENT" "$APTLY_REPO"
    fi
    aptly repo add "$APTLY_REPO" "$DEB_FILE"
    aptly publish repo -architectures="$ARCH" "$APTLY_REPO"
    echo "repo metadata updated (aptly)."
    exit 0
  fi

  if ! command -v apt-ftparchive >/dev/null 2>&1; then
    echo "error: reprepro / aptly / apt-ftparchive not found, install one of them." >&2
    exit 1
  fi

  echo "reprepro/aptly unavailable, falling back to apt-ftparchive manual metadata generation..."

  DIST_DIR="$REPO_DIR/dists/$DISTRIBUTION"
  COMP_DIR="$DIST_DIR/$COMPONENT/binary-$ARCH"
  POOL_DIR="$REPO_DIR/pool/$COMPONENT/g/go-cipher-cli"
  DIST_REL="dists/$DISTRIBUTION"

  mkdir -p "$COMP_DIR" "$POOL_DIR"
  cp -f "$DEB_FILE" "$POOL_DIR/"

  # NOTE: apt-ftparchive must run inside the repo root so Packages
  # Filename fields are relative to the repo root (e.g. pool/main/g/.../x.deb)
  # rather than incorrectly prefixed with repo/.
  pushd "$REPO_DIR" >/dev/null

  # 1. Generate Packages index (Filename relative to repo root)
  apt-ftparchive packages pool > "$DIST_REL/$COMPONENT/binary-$ARCH/Packages"
  gzip -kf "$DIST_REL/$COMPONENT/binary-$ARCH/Packages"

  # 2. Generate Release file (scans dists/<suite> only).
  #    Must clean old Release/InRelease and write to temp file first,
  #    otherwise shell redirection creates an empty Release file that
  #    apt-ftparchive includes in its own checksum (self-reference).
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

  echo "generated $DIST_DIR/Release"
fi

# ---------------------------------------------------------------------------
# Signing (generate Release.gpg and InRelease)
#    Key selection priority:
#      ① GPG_KEY environment variable
#      ② SignWith line in repo/conf/distributions
#      ③ gpg default key
#    This ensures the declared key, actual signature, and repo.gpg.key stay consistent.
# ---------------------------------------------------------------------------
DIST_DIR="$REPO_DIR/dists/$DISTRIBUTION"
if [ -z "$GPG_KEY" ]; then
  GPG_KEY=$(awk -F': ' '/^SignWith:/ {print $2; exit}' "$REPO_DIR/conf/distributions" | tr -d ' ')
fi

# pinentry-mode loopback for CI (no TTY) environments; no-op if key has no password
if [ -n "$GPG_KEY" ] && [ "$GPG_KEY" != "YOUR-KEY-ID" ]; then
  gpg --default-key "$GPG_KEY" --batch --yes --pinentry-mode loopback \
    -abs -o "$DIST_DIR/Release.gpg" "$DIST_DIR/Release"
  gpg --default-key "$GPG_KEY" --batch --yes --pinentry-mode loopback \
    --clearsign -o "$DIST_DIR/InRelease" "$DIST_DIR/Release"
  echo "Release.gpg and InRelease generated with GPG Key $GPG_KEY"
elif gpg --list-keys >/dev/null 2>&1 && [ -n "$(gpg --list-keys --with-colons | awk -F: '/^pub/{print $5}' | head -1)" ]; then
  gpg --batch --yes --pinentry-mode loopback -abs -o "$DIST_DIR/Release.gpg" "$DIST_DIR/Release"
  gpg --batch --yes --pinentry-mode loopback --clearsign -o "$DIST_DIR/InRelease" "$DIST_DIR/Release"
  echo "Release.gpg and InRelease generated with default GPG Key"
else
  echo "warning: no GPG key configured, skipping signature. Clients need [trusted=yes]." >&2
fi

# ---------------------------------------------------------------------------
# Export public key to repo/repo.gpg.key (needed by apt clients)
# ---------------------------------------------------------------------------
if [ -n "$GPG_KEY" ] && [ "$GPG_KEY" != "YOUR-KEY-ID" ]; then
  gpg --armor --export "$GPG_KEY" > "$REPO_DIR/repo.gpg.key"
  echo "public key exported to $REPO_DIR/repo.gpg.key"
elif gpg --list-keys >/dev/null 2>&1; then
  DEFAULT_KEY=$(gpg --list-keys --with-colons | awk -F: '/^pub/{print $5; exit}')
  if [ -n "$DEFAULT_KEY" ]; then
    gpg --armor --export "$DEFAULT_KEY" > "$REPO_DIR/repo.gpg.key"
    echo "default public key exported to $REPO_DIR/repo.gpg.key"
  fi
fi

# ---------------------------------------------------------------------------
# --output-dir: copy repo artifacts to a target directory (CI deployment)
# ---------------------------------------------------------------------------
if [ -n "$OUTPUT_DIR" ]; then
  mkdir -p "$OUTPUT_DIR"
  rm -rf "$OUTPUT_DIR/dists" "$OUTPUT_DIR/pool"
  cp -r "$REPO_DIR/dists" "$REPO_DIR/pool" "$OUTPUT_DIR/"
  [ -f "$REPO_DIR/repo.gpg.key" ] && cp "$REPO_DIR/repo.gpg.key" "$OUTPUT_DIR/"
  echo "repo artifacts copied to: $OUTPUT_DIR"
fi

echo "repo metadata updated, dir: $REPO_DIR"
