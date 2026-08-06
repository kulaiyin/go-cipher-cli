# go-cipher-cli

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/kulaiyin/go-cipher-cli)](https://github.com/kulaiyin/go-cipher-cli/releases)

[English](./README.md) | **简体中文**

一个基于 Go 的命令行工具，提供密钥派生、数据加密、密码强化器与 Diceware 助记口令生成。

📖 **完整文档**：https://kulaiyin.github.io/go-cipher-cli/

## 功能特性

- **密钥派生**：从输入内容 + 密码派生一组强密钥（3 把 512 位密钥 + UUID），供数据加密使用
- **数据加密**：用 AES-256-GCM 加密/解密文本或文件，产出 ZIP 包（含 `encrypted-data.bin` + `meta-data.json`，双重 HMAC 完整性校验）
- **密码强化器**：通过 Argon2id(64MB/3轮) + HKDF-Expand(SHA-256) 域分离，把密码加固成 256 位高熵密钥
- **Diceware 助记口令**：使用 EFF 大型词表（7776 词）和密码学安全随机掷骰，生成易记但高熵的口令

## 快速开始

<!--
### 通过 APT 安装（Debian/Ubuntu）

```bash
# 1. 导入 GPG 公钥
curl -fsSL https://kulaiyin.github.io/go-cipher-cli/apt/repo.gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/go-cipher-cli.gpg

# 2. 添加源
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/go-cipher-cli.gpg] https://kulaiyin.github.io/go-cipher-cli/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/go-cipher-cli.list

# 3. 安装
sudo apt update
sudo apt install go-cipher-cli
go-cipher-cli version   # 输出版本号
```

> 遇到网络问题（`Could not handshake`）？参见[安装文档 - 网络问题应对](https://kulaiyin.github.io/go-cipher-cli/zh/guide/installation#网络问题应对)。
-->

### 从源码构建

```bash
git clone https://github.com/kulaiyin/go-cipher-cli.git
cd go-cipher-cli
go build -o go-cipher-cli ./main.go
```

## 命令

### 密钥派生 — `key-derive`

从输入内容 + 密码派生一组强密钥（3 把 512 位密钥 + UUID）。

```bash
# 派生密钥集
go-cipher-cli key-derive --mode generate -i "我的seed2024安全密钥派生示例txt" -p "D3rive-P@ss"

# 派生并把恢复配置写入文件（内含盐和密钥 UUID，便于日后校验）
go-cipher-cli key-derive --mode generate -i "我的seed2024安全密钥派生示例txt" -p "D3rive-P@ss" \
  --output recovery.txt

# 自定义提示信息（默认取输入内容前 10 个字符），随恢复配置一并保存
go-cipher-cli key-derive --mode generate -i "我的seed2024安全密钥派生示例txt" -p "D3rive-P@ss" \
  --hint "恢复提示" --output recovery.txt

# restore：用原始 input+password 重新派生，与配置里的 UUID 比对校验是否还原了同一组密钥
go-cipher-cli key-derive --mode restore -i "我的seed2024安全密钥派生示例txt" -p "D3rive-P@ss" \
  --config recovery.txt
```

匹配时输出「密钥恢复成功」退出码 0；不匹配输出「密钥恢复失败」退出码 1（input/password/强度须与 `generate` 时一致）。

> **`key-derive` 校验规则**：`-p`（密码）至少 8 位，须包含字母、数字和特殊字符（或满足高强度校验）。`-i`（输入内容）去空白后至少 20 个字符。flag 传入和交互式输入均受此规则约束。

### 数据加密/解密 — `data-cipher`

用 AES-256-GCM 加密/解密文本或文件，产出 ZIP 包。先用 `key-derive` 派生 3 把强密钥，再用它们加密。

```bash
# 加密文本
go-cipher-cli data-cipher --mode encrypt \
  --input-type text --text "要加密的内容" \
  --hint "可选提示" \
  -k "51e4bd5f6cbb041cfc8afff10f7b887d436d82e9f9dda7a3483572019d5c56b9692ed4b1b6071d8fe1c6aadd07013bccc140a93a42a528846157d366a161f57c" -k "a205793f30b9e078182df7da66f3a19ce2def1be44dc303d1a5c9ca741197dde71e429d367cc6092b1c6218457c34e74c27fa78850bfc67a9d3a33fdc4abcfef" -k "bba970b4f2c786ec9a98aa5bca6a7aa677b5f22a0f0d0258226a3902ff66115dfa38e9ce4356ed4dd11cc366742cbcd015ae6ff6419d53355bc4ad6857830572" -p "consonant-overdraft-urgency-roamer7" \
  -o encrypted.zip

# 加密文件（位置参数 = --file）
go-cipher-cli data-cipher secret.txt --mode encrypt \
  -k "51e4bd5f6cbb041cfc8afff10f7b887d436d82e9f9dda7a3483572019d5c56b9692ed4b1b6071d8fe1c6aadd07013bccc140a93a42a528846157d366a161f57c" -k "a205793f30b9e078182df7da66f3a19ce2def1be44dc303d1a5c9ca741197dde71e429d367cc6092b1c6218457c34e74c27fa78850bfc67a9d3a33fdc4abcfef" -k "bba970b4f2c786ec9a98aa5bca6a7aa677b5f22a0f0d0258226a3902ff66115dfa38e9ce4356ed4dd11cc366742cbcd015ae6ff6419d53355bc4ad6857830572" -p "consonant-overdraft-urgency-roamer7"

# 第三方调用：密钥（-k）+ 密码1（-p）+ 一个普通额外密码
go-cipher-cli data-cipher secret.txt --mode encrypt \
  -k "51e4bd5f6cbb041cfc8afff10f7b887d436d82e9f9dda7a3483572019d5c56b9692ed4b1b6071d8fe1c6aadd07013bccc140a93a42a528846157d366a161f57c" -k "a205793f30b9e078182df7da66f3a19ce2def1be44dc303d1a5c9ca741197dde71e429d367cc6092b1c6218457c34e74c27fa78850bfc67a9d3a33fdc4abcfef" -k "bba970b4f2c786ec9a98aa5bca6a7aa677b5f22a0f0d0258226a3902ff66115dfa38e9ce4356ed4dd11cc366742cbcd015ae6ff6419d53355bc4ad6857830572" -p "consonant-overdraft-urgency-roamer7" \
  --extra-password "<额外普通密码>"

# 解密（必须使用与加密时相同的参数）
go-cipher-cli data-cipher --mode decrypt encrypted.zip \
  -k "51e4bd5f6cbb041cfc8afff10f7b887d436d82e9f9dda7a3483572019d5c56b9692ed4b1b6071d8fe1c6aadd07013bccc140a93a42a528846157d366a161f57c" -k "a205793f30b9e078182df7da66f3a19ce2def1be44dc303d1a5c9ca741197dde71e429d367cc6092b1c6218457c34e74c27fa78850bfc67a9d3a33fdc4abcfef" -k "bba970b4f2c786ec9a98aa5bca6a7aa677b5f22a0f0d0258226a3902ff66115dfa38e9ce4356ed4dd11cc366742cbcd015ae6ff6419d53355bc4ad6857830572" -p "consonant-overdraft-urgency-roamer7"
```

> **密钥与密码**：`key-derive` 派生的 3 把强密钥用 `-k`（密钥1/2/3，强制高强度校验）；密码1 用 `-p`（单值，需高强度，或 字母+数字+特殊字符且≥8位）。`--extra-password` 在末尾追加一个可选普通密码（无强度要求）——它参与加密，解密时需重复提供。参数集合与个数必须与加密时完全一致，否则派生密钥不同、解密失败。

### 密码强化器 — `enhance`

把常用密码加固成 256 位高熵密钥。

```bash
go-cipher-cli enhance -p "密码"                              # 派生 256 位密钥
go-cipher-cli enhance -p "密码" -s google                      # 不同盐后缀派生不同密钥
```

### Argon2id 密钥派生 — `argon2id`

直接使用 Argon2id 从密码派生密钥（默认 64 MB / 3 轮 / 1 路并行，密钥长度 64 字节）。

```bash
# 使用随机盐派生（人类可读输出，带进度转圈）
go-cipher-cli argon2id -p "密码"

# 使用固定 hex 盐进行确定性派生
go-cipher-cli argon2id -p "密码" --salt <64位hex>

# 自定义参数（内存单位为 MB）
go-cipher-cli argon2id -p "密码" --iterations 4 --memory 128 --parallelism 2 --key-length 32

# 机器可读输出（含 processing_time_ms）
go-cipher-cli argon2id -p "密码" --json
```

> 运行期间 `argon2id` 会在 stderr 显示带耗时的进度转圈（stdout/stderr 被重定向或使用 `--json` 时关闭）；最终输出始终包含处理耗时。

### Diceware 助记口令 — `diceware`

```bash
go-cipher-cli diceware                                       # 5 词默认口令（无分隔符）
go-cipher-cli diceware -n 8 --sep hyphen                     # 8 词连字符分隔
```

### 更新及其他 — `update` / `version`

```bash
go-cipher-cli update --check                                 # 检查新版本
go-cipher-cli update                                         # 检查并安装最新版本
go-cipher-cli version                                        # 输出版本号
go-cipher-cli --help                                         # 查看帮助
```

> 不带任何参数运行 `data-cipher` 或 `key-derive` 会进入交互模式。`data-cipher` 按 模式 → 输入类型 → 内容 → 提示 → 密钥/密码 → 输出路径 的顺序逐步引导；`key-derive` 按 模式 → 输入 → 提示 → 密码 → 强度 → 输出路径 的顺序逐步引导。

完整用法见 [使用说明](https://kulaiyin.github.io/go-cipher-cli/zh/guide/usage) 和 [密钥管理](https://kulaiyin.github.io/go-cipher-cli/zh/guide/key-management)。

## 文档

| 主题 | 链接 |
| --- | --- |
| 安装 | https://kulaiyin.github.io/go-cipher-cli/zh/guide/installation |
| 使用 | https://kulaiyin.github.io/go-cipher-cli/zh/guide/usage |
| 密钥管理 | https://kulaiyin.github.io/go-cipher-cli/zh/guide/key-management |
| 打包与发布 | https://kulaiyin.github.io/go-cipher-cli/zh/guide/packaging |
| APT 仓库 | https://kulaiyin.github.io/go-cipher-cli/zh/guide/apt-repo |
| CI/CD | https://kulaiyin.github.io/go-cipher-cli/zh/guide/ci-cd |

## License

[MIT](LICENSE)
