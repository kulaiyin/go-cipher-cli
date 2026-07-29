# go-cipher-cli

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/kulaiyin/go-cipher-cli)](https://github.com/kulaiyin/go-cipher-cli/releases)

[English](./README.md) | **简体中文**

一个基于 Go 的命令行工具，提供密码转密钥与 Diceware 助记口令生成，与 [web 工具](https://tools.wcheer.com/) 字节级互通。

📖 **完整文档**：https://kulaiyin.github.io/go-cipher-cli/

## 功能特性

- **密码转密钥**：通过 Argon2id(64MB/3轮) + HKDF-Expand(SHA-256) 域分离，把密码加固成 256 位高熵密钥，**与 web 工具字节级互通**
- **Diceware 助记口令**：使用 EFF 大型词表（7776 词）和密码学安全随机掷骰，生成易记但高熵的口令

## 快速开始

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

### 从源码构建

```bash
git clone https://github.com/kulaiyin/go-cipher-cli.git
cd go-cipher-cli
go build -o go-cipher-cli ./main.go
```

## 命令

```bash
# 密码转密钥（与 web 工具互通）
go-cipher-cli enhance -p "密码"                              # 派生 256 位密钥
go-cipher-cli enhance -p "密码" -s google                      # 不同盐后缀派生不同密钥

# Diceware 助记口令
go-cipher-cli diceware                                       # 5 词默认口令（无分隔符）
go-cipher-cli diceware -n 8 --sep hyphen                     # 8 词连字符分隔

# 更新
go-cipher-cli update --check                                 # 检查新版本
go-cipher-cli update                                         # 检查并安装最新版本

# 其他
go-cipher-cli version                                        # 输出版本号
go-cipher-cli --help                                         # 查看帮助
```

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
