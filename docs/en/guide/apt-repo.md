# APT Repository and GitHub Pages

The go-cipher-cli APT repository is hosted on **GitHub Pages**. GitHub Pages provides HTTPS static file hosting, and an APT repository is essentially just a set of static files (`dists/`, `pool/`, `Release`, `InRelease`), making the two a natural fit.

## Repository URL

```
https://kulaiyin.github.io/go-cipher-cli/apt
```

The Pages site hosts two sets of content simultaneously:

```
https://kulaiyin.github.io/go-cipher-cli/
├── index.html              ← The VitePress documentation site you are viewing (root path)
├── guide/...               ← Documentation pages
└── apt/                    ← APT repository (/apt subpath)
    ├── dists/stable/...    ← Release / InRelease / Packages
    ├── pool/main/.../...deb
    └── repo.gpg.key        ← Client-importable GPG public key
```

## Client Installation

Three steps (see the [Installation guide](./installation) for details):

```bash
# 1. Import the GPG public key
curl -fsSL https://kulaiyin.github.io/go-cipher-cli/apt/repo.gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/go-cipher-cli.gpg

# 2. Add the source
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/go-cipher-cli.gpg] https://kulaiyin.github.io/go-cipher-cli/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/go-cipher-cli.list

# 3. Install
sudo apt update
sudo apt install go-cipher-cli
```

## Repository Metadata Generation Approaches

`scripts/publish_repo.sh` automatically selects one of the following tools by priority. Any one of the three approaches is sufficient.

### Approach A: reprepro (Recommended)

```bash
bash scripts/publish_repo.sh
```

The script internally:

1. Finds the latest `.deb` package in `dist/`.
2. Calls `reprepro -b repo includedeb stable <deb-file>` to add it to the repository.
3. Generates `repo/dists/`, `repo/pool/`, and the `Release` / `InRelease` metadata.

### Approach B: aptly (Alternative)

When reprepro is unavailable, the script automatically switches to aptly:

```bash
aptly repo create -distribution=stable -component=main go-cipher-cli-repo
aptly repo add go-cipher-cli-repo dist/go-cipher-cli_0.1.0_linux_amd64.deb
aptly publish repo -architectures=amd64 go-cipher-cli-repo
```

### Approach C: apt-ftparchive (Fallback When reprepro/aptly Unavailable)

When both `reprepro` and `aptly` are unavailable, you can use `apt-ftparchive` to manually generate the repository metadata. The script falls back to this approach automatically; the equivalent manual commands are:

```bash
cd repo
# 1. Copy the .deb into the pool directory
mkdir -p pool/main/g/go-cipher-cli
cp ../dist/go-cipher-cli_0.1.0_linux_amd64.deb pool/main/g/go-cipher-cli/

# 2. Generate the Packages index
apt-ftparchive packages pool > dists/stable/main/binary-amd64/Packages
gzip -kf dists/stable/main/binary-amd64/Packages

# 3. Generate the Release file (write to a temp file first, then mv, to avoid self-referencing checksums)
apt-ftparchive \
  -o APT::FTPArchive::Release::Origin="go-cipher-cli" \
  -o APT::FTPArchive::Release::Label="go-cipher-cli" \
  -o APT::FTPArchive::Release::Suite="stable" \
  -o APT::FTPArchive::Release::Codename="stable" \
  -o APT::FTPArchive::Release::Architectures="amd64" \
  -o APT::FTPArchive::Release::Components="main" \
  release dists/stable > dists/stable/Release.new
mv dists/stable/Release.new dists/stable/Release

# 4. Sign (generate InRelease and Release.gpg)
gpg --default-key YOUR-KEY-ID -abs -o dists/stable/Release.gpg dists/stable/Release
gpg --default-key YOUR-KEY-ID --clearsign -o dists/stable/InRelease dists/stable/Release
```

::: warning Avoid Self-Reference
`apt-ftparchive release` must output to a temporary file and then `mv` it; it cannot redirect directly to `Release`. Otherwise, the shell will create an empty `Release` file first, and when apt-ftparchive scans the directory it will include it in its own checksums, causing client verification to fail.
:::

## Repository Structure

| File | Purpose |
| --- | --- |
| `dists/stable/Release` | Repository metadata: architectures, components, file checksums (MD5/SHA1/SHA256/SHA512) |
| `dists/stable/InRelease` | Inline GPG signature of Release (clearsign); apt verifies this file first |
| `dists/stable/Release.gpg` | Detached signature of Release; fallback when InRelease is unavailable |
| `dists/stable/main/binary-amd64/Packages` | Index listing of all `.deb` files (name, version, dependencies, path) |
| `dists/stable/main/binary-amd64/Packages.gz` | Gzip-compressed version of Packages |
| `pool/main/g/go-cipher-cli/*.deb` | The actual package files |
| `repo.gpg.key` | Publisher's GPG public key (ASCII armored), to be imported by clients |

## Signing and Trust

The APT repository is signed by GPG key `9E38A2B39666B218` (fingerprint `E489 52BD 5A15 B74A 3259 9B6D 9E38 A2B3 9666 B218`). The client establishes trust by importing `repo.gpg.key` and using `signed-by=` in the source declaration, without needing global trust.

The private key is stored in a GitHub Repository Secret and never enters the codebase. For configuration and rotation procedures, see the "Signing Key Management" section of [CI/CD Pipeline](./ci-cd).

## Hosting on a Custom HTTP Server

GitHub Pages is the default hosting method, but if you want to self-host on an HTTP server (nginx, object storage, etc.), simply upload the contents of the `repo/` directory (`dists/`, `pool/`, `repo.gpg.key`) as a whole:

```bash
rsync -avz --delete repo/dists repo/pool repo/repo.gpg.key \
  user@your-server:/var/www/go-cipher-cli/apt/
```

Ensure the remote directory is accessible via `https://your-server/go-cipher-cli/apt/`, then point the client source URL to your server.

## Architecture and Distribution

- **Architecture**: `amd64`
- **Distribution codename (Codename/Suite)**: `stable`
- **Component**: `main`

To add new architectures (e.g. `arm64`) or distributions (e.g. `testing`), you need to modify `repo/conf/distributions` and the build targets in `.goreleaser.yml`.
