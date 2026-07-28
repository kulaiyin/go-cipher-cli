# go-cipher-cli

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/kulaiyin/go-cipher-cli)](https://github.com/kulaiyin/go-cipher-cli/releases)

**English** | [简体中文](./README.zh-CN.md)

A Go-based CLI demo project showcasing integration of configuration management, structured logging, interactive prompts, and progress bars, distributed via an APT repository hosted on GitHub Pages.

📖 **Full documentation**: https://kulaiyin.github.io/go-cipher-cli/

## Features

- **Password-to-key**: Argon2id (64MB / 3 passes) + HKDF-Expand (SHA-256) domain separation, **byte-level interoperable with the [web tool](https://tools.wcheer.com/)**
- **Diceware mnemonic passphrase**: EFF large wordlist (7776 words) with cryptographically secure random dice rolls, generating memorable yet high-entropy passphrases
- **Command framework**: [Cobra](https://github.com/spf13/cobra)
- **Configuration**: [Viper](https://github.com/spf13/viper) — config file / environment variables / defaults / `--config`
- **Logging**: [Zap](https://go.uber.org/zap) — `debug` / `info` / `warn` / `error`
- **Distribution**: goreleaser builds `.deb` → GitHub Actions auto-publishes to a GitHub Pages APT repository

## Quick Start

### Install via APT (Debian/Ubuntu)

```bash
# 1. Import the GPG public key
curl -fsSL https://kulaiyin.github.io/go-cipher-cli/apt/repo.gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/go-cipher-cli.gpg

# 2. Add the repository
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/go-cipher-cli.gpg] https://kulaiyin.github.io/go-cipher-cli/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/go-cipher-cli.list

# 3. Install
sudo apt update
sudo apt install go-cipher-cli
go-cipher-cli version   # prints the version
```

> Network issues (`Could not handshake`)? See [Installation — Network troubleshooting](https://kulaiyin.github.io/go-cipher-cli/guide/installation#网络问题应对).

### Build from source

```bash
git clone https://github.com/kulaiyin/go-cipher-cli.git
cd go-cipher-cli
go build -o go-cipher-cli ./main.go
```

## Commands

```bash
# Password to key (interoperable with the web tool)
go-cipher-cli enhance -p "password"                       # derive a 256-bit key
go-cipher-cli enhance -p "password" -s google             # different salt suffix → different key

# Diceware mnemonic passphrase
go-cipher-cli diceware                                    # 5-word default passphrase (no separator)
go-cipher-cli diceware -n 8 --sep hyphen                  # 8 words, hyphen-separated

# Others
go-cipher-cli version                                     # prints the version
go-cipher-cli --help                                      # show help
```

See the [Usage guide](https://kulaiyin.github.io/go-cipher-cli/guide/usage) and [Key management](https://kulaiyin.github.io/go-cipher-cli/guide/key-management) for full details.

## Documentation

| Topic | Link |
| --- | --- |
| Installation | https://kulaiyin.github.io/go-cipher-cli/guide/installation |
| Usage | https://kulaiyin.github.io/go-cipher-cli/guide/usage |
| Key management | https://kulaiyin.github.io/go-cipher-cli/guide/key-management |
| Packaging & release | https://kulaiyin.github.io/go-cipher-cli/guide/packaging |
| APT repository | https://kulaiyin.github.io/go-cipher-cli/guide/apt-repo |
| CI/CD | https://kulaiyin.github.io/go-cipher-cli/guide/ci-cd |

## Project Structure

```
├── main.go                 # Entry point
├── cmd/                    # CLI commands
├── docs/                   # VitePress documentation site source
├── scripts/                # Packaging & release scripts
├── repo/conf/              # APT repository configuration
├── .github/workflows/      # GitHub Actions workflows
├── .goreleaser.yml         # goreleaser configuration
└── go.mod                  # Go module definition
```

## License

[MIT](LICENSE)
