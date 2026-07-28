# Usage

go-cipher-cli provides two core features — password-to-key conversion and Diceware mnemonic passphrase generation — both byte-level interoperable with the [web tool](https://tools.wcheer.com/).

## Command Overview

```bash
go-cipher-cli --help
```

```
Available Commands:
  completion  Generate the autocompletion script for the specified shell
  diceware    Generate a Diceware mnemonic passphrase (EFF wordlist, 7776 words)
  enhance     Convert a password into a 256-bit high-entropy key (password-to-key)
  help        Help about any command
  version     Print the CLI version
```

## Version

```bash
go-cipher-cli version
# Output: v0.3.1
```

## Password to Key (enhance)

Takes a password you "use often but might not be strong enough" and hardens it via the Argon2id slow function into a 256-bit high-entropy key. The same password + salt suffix **deterministically** derives the same key, and the password cannot be reversed from the key.

### Algorithm Flow

1. **Argon2id slow function resists brute force**: takes the user password as input and "fixed salt + user salt suffix" as the salt, with parameters 64MB / 3 iterations / 1 parallelism lane, outputting a 64-byte master key (PRK)
2. **HKDF-Expand(SHA-256) domain separation**: pure Expand on the PRK, outputting 32 bytes (256 bits) of subkey
3. **Output**: a 64-character hex string, convenient for cross-platform copy and alignment

### Basic Usage

```bash
# Derive a 256-bit key
go-cipher-cli enhance -p "MyMaster@2024"

# Different salt suffixes derive different keys (recommended)
go-cipher-cli enhance -p "MyMaster@2024" -s google
go-cipher-cli enhance -p "MyMaster@2024" -s firefox
```

Example output:

```
算法:     Argon2id(64MB/3轮/1路并行) + HKDF-Expand(SHA-256)
Domain:   default-v1
盐后缀:   google
密钥(hex):     3aac7a86fd8c549020841738920154a05bcae6dd116c116a991144df33a440eb
密钥(base64):  oqx6hv2MVJAg...9E3zOkDr
密钥长度:      256 位 (256 bit)
```

| Parameter | Description |
| --- | --- |
| `-p, --password` | The password to convert (required) |
| `-s, --salt-suffix` | Optional salt suffix (e.g. site name, device name); different suffixes derive different keys |
| `--domain` | Domain label (default `default-v1`, generally unchanged) |

::: tip Interoperability with the Web Client
As long as the "password + salt suffix" combination is identical, the CLI and the [web tool](https://tools.wcheer.com/) will derive exactly the same 256-bit key.
:::

::: tip Salt Suffix Recommendations
Use different salt suffixes for different purposes (e.g. `google`, `firefox`) to derive distinct keys from the same password, avoiding the "one leak compromises all" scenario.
:::

## Diceware Mnemonic Passphrase (diceware)

Uses the EFF large wordlist (7776 words) and cryptographically secure random dice rolls to generate memorable yet high-entropy passphrases.

### Security Principles

- Randomness source: `crypto/rand` (Go CSPRNG), using rejection sampling to eliminate modulo bias
- Each word provides approximately **12.9 bit** of entropy:
  - 5 words → ~64.6 bit
  - 6 words → ~77.5 bit
  - 8 words → ~103.4 bit
- Number of possible combinations = 7776^word_count (5 words ≈ 2.8×10^19)

### Basic Usage

```bash
# Default 5 words, no separator
go-cipher-cli diceware

# Specify word count and separator
go-cipher-cli diceware -n 8 --sep hyphen
go-cipher-cli diceware -n 6 --sep none
```

Example output:

```
口令:         cavity-puppy-lego-vanquish-sediment
长度:         35 字符
词数:         5
信息熵:       64.62 bit
可能组合数:   2.84 × 10^19
分隔符:       连字符 (-)

逐词掷骰详情:
   1. [15264] cavity
   2. [45662] puppy
   3. [35656] lego
   4. [65415] vanquish
   5. [53443] sediment
```

| Parameter | Description |
| --- | --- |
| `-n, --num-words` | Number of words (1-20, default 5) |
| `--sep` | Separator: `space` / `hyphen` / `none`, default `none` |

## Global Parameters

### Specifying a Configuration File

```bash
go-cipher-cli --config /path/to/config.yaml enhance -p test
```

Supported config formats: YAML / JSON / TOML, etc. (auto-detected by Viper from the file extension).

If `--config` is not specified, a file named `config` will be searched for in the following order:

1. Current directory `.`
2. `$HOME/.go-cipher-cli/`

Example `config.yaml`:

```yaml
log:
  level: info   # debug | info | warn | error
```

### Setting the Log Level

```bash
go-cipher-cli --log-level debug diceware
```

Available values: `debug` / `info` / `warn` / `error`, default `info`.

::: tip Environment Variables
All configuration items can be overridden via environment variables, prefixed with `GOCIPHER_`, with `.` replaced by `_`.
For example, `log.level` maps to the environment variable `GOCIPHER_LOG_LEVEL`:

```bash
GOCIPHER_LOG_LEVEL=warn go-cipher-cli enhance -p test
```
:::

## Exit Codes

| Exit Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Execution error (e.g. config load failure, command error) |
