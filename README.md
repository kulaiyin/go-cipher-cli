# go-cipher-cli

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/kulaiyin/go-cipher-cli)](https://github.com/kulaiyin/go-cipher-cli/releases)

**English** | [简体中文](./README.zh-CN.md)

A Go-based CLI tool for password-to-key derivation and Diceware passphrase generation, byte-level interoperable with the [web tool](https://tools.wcheer.com/).

📖 **Full documentation**: https://kulaiyin.github.io/go-cipher-cli/

## Features

- **Password-to-key**: hardens a password via Argon2id (64MB / 3 passes) + HKDF-Expand (SHA-256) domain separation into a 256-bit high-entropy key, **byte-level interoperable with the web tool**
- **Diceware passphrase**: generates memorable yet high-entropy passphrases using the EFF large wordlist (7776 words) with cryptographically secure random dice rolls

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

> Network issues (`Could not handshake`)? See [Installation — Network troubleshooting](https://kulaiyin.github.io/go-cipher-cli/en/guide/installation#network-troubleshooting).

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

# Diceware passphrase
go-cipher-cli diceware                                    # 5-word default passphrase (no separator)
go-cipher-cli diceware -n 8 --sep hyphen                  # 8 words, hyphen-separated

# Others
go-cipher-cli version                                     # prints the version
go-cipher-cli --help                                      # show help
```

See the [Usage guide](https://kulaiyin.github.io/go-cipher-cli/en/guide/usage) and [Key management](https://kulaiyin.github.io/go-cipher-cli/en/guide/key-management) for full details.

## Documentation

| Topic | Link |
| --- | --- |
| Installation | https://kulaiyin.github.io/go-cipher-cli/en/guide/installation |
| Usage | https://kulaiyin.github.io/go-cipher-cli/en/guide/usage |
| Key management | https://kulaiyin.github.io/go-cipher-cli/en/guide/key-management |
| Packaging & release | https://kulaiyin.github.io/go-cipher-cli/en/guide/packaging |
| APT repository | https://kulaiyin.github.io/go-cipher-cli/en/guide/apt-repo |
| CI/CD | https://kulaiyin.github.io/go-cipher-cli/en/guide/ci-cd |

## License

[MIT](LICENSE)
