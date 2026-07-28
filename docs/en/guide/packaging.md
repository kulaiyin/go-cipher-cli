# Packaging and Release

This project builds its release pipeline around **goreleaser**: first generate the `.deb` package, then produce and sign the APT repository metadata, and finally publish to GitHub Pages. See [CI/CD Pipeline](./ci-cd) for the full automated workflow.

## Directory Structure

```
go-cipher-cli/
├── main.go                 # Entry point
├── cmd/                    # CLI commands (root / run / version)
├── .goreleaser.yml         # goreleaser configuration (generates .deb)
├── scripts/
│   ├── package.sh          # Packaging script (generates .deb)
│   └── publish_repo.sh     # APT repository publishing script
├── repo/conf/              # APT repository configuration (distributions)
├── docs/                   # VitePress documentation site source
└── .github/workflows/      # GitHub Actions workflows
```

## Prerequisites

| Tool | Purpose | Install Command |
| --- | --- | --- |
| `go` >= 1.21 | Compile the binary | See https://go.dev/dl/ |
| `goreleaser` | Generate `.deb` (recommended) | `go install github.com/goreleaser/goreleaser@latest` |
| `dpkg-deb` | Build `.deb` manually (fallback, bundled with Debian/Ubuntu) | `apt install dpkg-dev` |
| `reprepro` | Generate APT repository metadata (recommended) | `apt install reprepro` |
| `aptly` | Generate APT repository metadata (alternative) | See https://www.aptly.info/ |
| `apt-ftparchive` | Generate repository metadata (fallback when reprepro unavailable) | `apt install apt-utils` |
| `gpg` | Sign `Release`/`InRelease` | `apt install gnupg` |

::: tip Fallback Mechanism
Both `package.sh` and `publish_repo.sh` have automatic fallbacks: when goreleaser is unavailable they fall back to dpkg-deb, and when reprepro/aptly is unavailable they fall back to apt-ftparchive. So even with an incomplete toolchain, basic packaging can still be completed.
:::

## Two-Step Process

```
┌──────────────────┐     ┌──────────────────────────┐
│  Step 1: Package │     │  Step 2: Publish          │
│  scripts/        │ ──> │  scripts/publish_repo.sh  │
│  package.sh      │     │  Generates dists/ pool/   │
│  Generates .deb  │     │  Signs Release/InRelease  │
└──────────────────┘     └──────────────────────────┘
```

### Step 1: Generate the .deb

```bash
bash scripts/package.sh
```

Script logic (with priority-based fallback):

1. **goreleaser** (preferred): runs `goreleaser release --snapshot --clean`; output is in `dist/`.
2. **dpkg-deb** (fallback): when goreleaser is unavailable, builds the binary manually and packages it with `dpkg-deb --build`.

Output: `dist/go-cipher-cli_<version>_linux_amd64.deb`

The goreleaser configuration is in [`.goreleaser.yml`](https://github.com/kulaiyin/go-cipher-cli/blob/main/.goreleaser.yml), where the `nfpms` section defines the package name, maintainer, description, and install path (automatically installed to `/usr/bin/go-cipher-cli`).

#### Using Only goreleaser (Optional)

If you want to build only with `goreleaser` (skipping the fallback logic):

```bash
goreleaser release --snapshot --clean
```

#### Inspecting the .deb

```bash
dpkg-deb -I dist/go-cipher-cli_0.1.0_linux_amd64.deb   # View control info
dpkg-deb -c dist/go-cipher-cli_0.1.0_linux_amd64.deb   # View file list
```

### Step 2: Publish to the APT Repository

```bash
bash scripts/publish_repo.sh
```

This script reads the latest `.deb` in `dist/` and generates the APT repository metadata. For detailed usage of the three tools and their fallback order, see [APT Repository and GitHub Pages](./apt-repo).

## Related Topics

- [APT Repository and GitHub Pages](./apt-repo): three repository metadata generation approaches, GitHub Pages hosting, and client installation.
- [CI/CD Pipeline](./ci-cd): the fully automated release flow triggered by pushing a tag, and signing key management.
