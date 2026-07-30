# go-cipher-cli

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/kulaiyin/go-cipher-cli)](https://github.com/kulaiyin/go-cipher-cli/releases)

**English** | [简体中文](./README.zh-CN.md)

A Go-based CLI tool for password-to-key derivation, data encryption and Diceware passphrase generation, byte-level interoperable with the [web tool](https://tools.wcheer.com/).

📖 **Full documentation**: https://kulaiyin.github.io/go-cipher-cli/

## Features

- **Data encryption**: AES-256-GCM encrypt/decrypt of text or files, producing web-interoperable ZIP bundles (`encrypted-data.bin` + `meta-data.json` with dual HMAC integrity), **byte-level interoperable with the web tool**
- **Key derivation**: derives a set of strong keys (3 × 512-bit keys + UUID) from input + password for use in data encryption, **interoperable with the web tool**
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
# Data encryption (interoperable with the web tool, produces a .zip bundle)
#   First derive 3 strong keys with key-derive, then encrypt with them
#   (mirrors the web tool's "derive keys → import keys → encrypt")
go-cipher-cli key-derive --mode generate -i "memorable input" -p "derive-password"   # derive a key set
go-cipher-cli key-derive --mode generate -i "memorable input" -p "derive-password" \
  --output recovery.txt    # derive and write a recovery config (salt + key UUIDs) for later verification

#   restore: re-derive with the original input+password, compare against the UUIDs in the config
go-cipher-cli key-derive --mode restore -i "memorable input" -p "derive-password" \
  --config recovery.txt    # "key restored successfully" + exit 0 on match, else "key restore failed" + exit 1 (input/password/strength must match generate)

#   Encrypt text
go-cipher-cli data-cipher --mode encrypt \
  --input-type text --text "secret content" \
  --hint "optional hint" \
  -p "<key1-128hex>" -p "<key2-128hex>" -p "<key3-128hex>" -p "<password1>" \
  -o encrypted.zip

#   Encrypt a file (positional arg = --file)
go-cipher-cli data-cipher secret.txt --mode encrypt \
  -p "<key1-128hex>" -p "<key2-128hex>" -p "<key3-128hex>" -p "<password1>"

#   Decrypt (-p order must match the encryption)
go-cipher-cli data-cipher --mode decrypt encrypted.zip \
  -p "<key1-128hex>" -p "<key2-128hex>" -p "<key3-128hex>" -p "<password1>"

# Password to key (interoperable with the web tool)
go-cipher-cli enhance -p "password"                       # derive a 256-bit key
go-cipher-cli enhance -p "password" -s google             # different salt suffix → different key

# Diceware passphrase
go-cipher-cli diceware                                    # 5-word default passphrase (no separator)
go-cipher-cli diceware -n 8 --sep hyphen                  # 8 words, hyphen-separated

# Update
go-cipher-cli update --check                              # check for new versions
go-cipher-cli update                                      # check and install latest version

# Others
go-cipher-cli version                                     # prints the version
go-cipher-cli --help                                      # show help
```

> **`-p` ordering** (`data-cipher`): the first three must be 128-hex strong keys (from `key-derive`), the fourth is password1; order and count must match the encryption exactly, or the derived key differs and decryption fails. Keys 1/2/3 are enforced high-strength; password1 must satisfy the composite rule (high strength OR letter + digit + special char with length ≥ 8).

> Running `data-cipher` / `key-derive` with no arguments enters interactive mode, guiding you step by step in the order mode → input type → content → hint → keys/passwords → output path (matching the web tool's form).

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
