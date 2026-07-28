# CI/CD Pipeline

go-cipher-cli uses **GitHub Actions** for fully automated releases. When you push a tag in `v*` format (e.g. `v0.1.0`), the pipeline automatically completes the entire process of compiling, packaging, signing, documentation building, and deployment.

The workflow definition is in [`.github/workflows/release.yml`](https://github.com/kulaiyin/go-cipher-cli/blob/main/.github/workflows/release.yml).

## Trigger Conditions

```yaml
on:
  push:
    tags:
      - 'v*'
```

That is, any tag push in the form of `v0.1.0`, `v1.2.3` will trigger it.

## Pipeline Steps

```
┌────────────────────────────────────────────────────────────────┐
│  push v* tag                                                    │
│      │                                                          │
│      ▼                                                          │
│  1. Checkout (fetch-depth: 0, goreleaser needs full history)    │
│      │                                                          │
│      ▼                                                          │
│  2. Set up the Go environment                                   │
│      │                                                          │
│      ▼                                                          │
│  3. Set up the Node environment (VitePress build)               │
│      │                                                          │
│      ▼                                                          │
│  4. goreleaser release (official goreleaser-action)             │
│     ├─ Compile the linux/amd64 binary                           │
│     ├─ Generate the .deb                                        │
│     └─ Create the GitHub Release, upload .deb / tar.gz / checksums │
│      │                                                          │
│      ▼                                                          │
│  5. Import the GPG private key (decoded from Secret GPG_SIGNING_KEY) │
│      │                                                          │
│      ▼                                                          │
│  6. Run scripts/publish_repo.sh                                 │
│     ├─ Generate dists/ pool/ Release InRelease                  │
│     └─ Sign with the imported key                               │
│      │                                                          │
│      ▼                                                          │
│  7. Export the GPG public key to repo/repo.gpg.key              │
│      │                                                          │
│      ▼                                                          │
│  8. Build the VitePress documentation site (npm ci && npm run docs:build) │
│      │                                                          │
│      ▼                                                          │
│  9. Aggregate deployment content (docs + APT repository)        │
│      │                                                          │
│      ▼                                                          │
│  10. Deploy to the gh-pages branch                              │
│      ├─ Documentation site → root path                          │
│      └─ APT repository (repo/) → /apt subpath                   │
└────────────────────────────────────────────────────────────────┘
```

## Release Version Number

The version number comes from the **git tag**:

- tag `v0.1.0` → goreleaser produces `go-cipher-cli_0.1.0_linux_amd64.deb`
- The version is also written into the APT repository's `Packages` index

Therefore, the only action required for a release is to push a tag:

```bash
git tag v0.1.0
git push origin v0.1.0
# Everything after this is fully automatic, no intervention needed
```

## Signing Key Management

The GPG private key is injected via a **GitHub Repository Secret**; the private key itself never enters the codebase.

### Generate or Reuse a GPG Key

Generate locally (or reuse an existing one):

```bash
gpg --gen-key
# Note the generated Key ID, e.g. 9E38A2B39666B218
```

### Export the Private Key and Base64 Encode It

```bash
gpg --armor --export-secret-keys 9E38A2B39666B218 | base64 -w0
```

`base64 -w0` outputs a single line, avoiding newlines in the Secret that would cause import failures.

### Configure the GitHub Secret

1. Open `https://github.com/kulaiyin/go-cipher-cli/settings/secrets/actions` in your browser
2. Click `New repository secret`
3. **Name**: `GPG_SIGNING_KEY`
4. **Value**: paste the base64 output from the previous step
5. Save

Also ensure that the `SignWith:` in `repo/conf/distributions` matches this Key ID (currently `9E38A2B39666B218`). The CI `publish_repo.sh` reads this value automatically and signs with the imported private key.

::: warning Private Key Security
If the private key is leaked, anyone can forge your repository signature. Please:
- Store it only in the GitHub Secret, never write it to any file or log
- Rotate it periodically (generate a new key, update the Secret, republish once so clients import the new public key)
:::

### Rotating Keys

1. Generate a new key locally.
2. Update the `SignWith:` in `repo/conf/distributions` to the new Key ID.
3. Update the GitHub Secret `GPG_SIGNING_KEY`.
4. Trigger a release again; `repo.gpg.key` will be automatically updated to the new public key.
5. Notify clients to re-run the public key import step (`curl ... | sudo gpg --dearmor`).

## Enabling GitHub Pages (First Deployment)

After the first successful release, the `gh-pages` branch will be created. You need to enable Pages in the repository settings:

1. Open `https://github.com/kulaiyin/go-cipher-cli/settings/pages` in your browser
2. **Source** → select `Deploy from a branch`
3. **Branch** → select `gh-pages`, directory `/ (root)`
4. Save

Within a few minutes, `https://kulaiyin.github.io/go-cipher-cli/` will be accessible.

## Previewing Release Artifacts Locally

No need to actually push a tag — the whole process can be reproduced locally:

```bash
# 1. Package
bash scripts/package.sh

# 2. Generate the APT repository
bash scripts/publish_repo.sh

# 3. Preview the documentation site locally
npm install
npm run docs:dev
```

## FAQ

- **`goreleaser: command not found`**: CI uses the official `goreleaser-action` and requires no manual installation; locally you can run `go install github.com/goreleaser/goreleaser@latest`.
- **`reprepro: command not found`**: `publish_repo.sh` will automatically fall back to apt-ftparchive; see Approach C in [APT Repository and GitHub Pages](./apt-repo).
- **Signing failure / `InRelease` error**: First generate a key with `gpg --gen-key`, and set `SignWith:` in `repo/conf/distributions` to the real Key ID.
- **Signing failure in CI**: Check whether the Secret `GPG_SIGNING_KEY` is configured, whether it is in `base64 -w0` single-line format, and whether `SignWith` is consistent.
- **Client `NO_PUBKEY` error**: The publisher's public key was not imported correctly, or the public key has been rotated; re-import it per the [Installation guide](./installation).
- **Client `Could not handshake` / connection reset**: Usually because `*.github.io` is being interfered with by the network (e.g. GFW). Configure a proxy for apt, switch to the jsDelivr CDN mirror, or download the `.deb` directly from GitHub Release and install manually.
- **gh-pages not updating**: Pages is not enabled or the wrong branch is selected. Confirm `gh-pages` is selected in Settings → Pages.
