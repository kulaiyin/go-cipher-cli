# Installation

go-cipher-cli offers two installation methods: install via the APT repository (recommended, supports automatic updates), or build from source.

## Install via the APT Repository (Recommended)

::: tip Repository URL
The APT repository is hosted on GitHub Pages: `https://kulaiyin.github.io/go-cipher-cli/apt`
:::

### 1. Import the GPG Public Key

The APT repository is GPG-signed, so the client must first import the publisher's public key to verify integrity:

```bash
curl -fsSL https://kulaiyin.github.io/go-cipher-cli/apt/repo.gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/go-cipher-cli.gpg
```

### 2. Add the APT Source

```bash
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/go-cipher-cli.gpg] https://kulaiyin.github.io/go-cipher-cli/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/go-cipher-cli.list
```

### 3. Install

```bash
sudo apt update
sudo apt install go-cipher-cli
```

### 4. Verify

```bash
go-cipher-cli version
# Output: v0.1.0
```

## Build from Source

Requires Go 1.21+.

```bash
git clone https://github.com/kulaiyin/go-cipher-cli.git
cd go-cipher-cli
go build -o go-cipher-cli ./main.go
```

The build produces a `go-cipher-cli` binary in the current directory, which can be manually copied to `/usr/local/bin/`.

## Download from GitHub Release

On every tag release, CI automatically uploads `.deb` packages and archives to the [GitHub Release page](https://github.com/kulaiyin/go-cipher-cli/releases). You can download and install directly:

```bash
# After downloading the .deb
sudo dpkg -i go-cipher-cli_*_linux_amd64.deb
```

## Upgrade and Uninstall

```bash
# Upgrade to the latest version (APT users)
sudo apt update && sudo apt upgrade go-cipher-cli

# Uninstall
sudo apt remove go-cipher-cli
```

## Network Troubleshooting

If `apt update` reports `Could not handshake` or curl reports "connection reset by peer", it is usually because `*.github.io` is being interfered with by the network (e.g. the GFW in mainland China). There are three workarounds:

### Option 1: Configure a Proxy for apt

```bash
sudo https_proxy=http://your-proxy-address:port apt update
sudo https_proxy=http://your-proxy-address:port apt install go-cipher-cli
```

### Option 2: Use a jsDelivr CDN Mirror (No Proxy Required)

jsDelivr mirrors GitHub repository content and is typically reachable from within China:

```bash
# Use the jsDelivr mirror for the public key
curl -fsSL https://cdn.jsdelivr.net/gh/kulaiyin/go-cipher-cli@gh-pages/apt/repo.gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/go-cipher-cli.gpg

# Use jsDelivr for the source URL
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/go-cipher-cli.gpg] https://cdn.jsdelivr.net/gh/kulaiyin/go-cipher-cli@gh-pages/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/go-cipher-cli.list

sudo apt update
sudo apt install go-cipher-cli
```

::: tip jsDelivr Cache
jsDelivr's cache has a delay (a few hours to a day); newly released versions may need to wait for the cache to refresh.
:::

### Option 3: Download the .deb Directly and Install Manually

Bypass the APT repository and download directly from GitHub Release (the `github.com` domain is usually more reachable than `github.io`):

```bash
curl -fsSL -o /tmp/go-cipher-cli.deb \
  https://github.com/kulaiyin/go-cipher-cli/releases/download/v0.1.0/go-cipher-cli_0.1.0_linux_amd64.deb
sudo dpkg -i /tmp/go-cipher-cli.deb
go-cipher-cli version
```
