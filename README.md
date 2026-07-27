# go-cipher-cli

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/kulaiyin/go-cipher-cli)](https://github.com/kulaiyin/go-cipher-cli/releases)

一个基于 Go 的 CLI 演示项目，演示如何集成配置管理、结构化日志、交互式提示和进度条，并通过 GitHub Pages 托管的 APT 仓库分发。

📖 **完整文档**：https://kulaiyin.github.io/go-cipher-cli/

## 功能特性

- **命令框架**：[Cobra](https://github.com/spf13/cobra)
- **配置管理**：[Viper](https://github.com/spf13/viper) — 配置文件 / 环境变量 / 默认值 / `--config`
- **日志**：[Zap](https://go.uber.org/zap) — `debug` / `info` / `warn` / `error`
- **交互提示**：[Survey](https://github.com/AlecAivazis/survey/v2) — 操作类型选择、目标输入
- **进度条**：[MPB](https://github.com/vbauerster/mpb/v8)
- **分发**：goreleaser 打包 `.deb` → GitHub Actions 自动发布到 GitHub Pages APT 仓库

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
go-cipher-cli version   # 输出 v0.1.0
```

> 遇到网络问题（`Could not handshake`）？参见[安装文档 - 网络问题应对](https://kulaiyin.github.io/go-cipher-cli/guide/installation#网络问题应对)。

### 从源码构建

```bash
git clone https://github.com/kulaiyin/go-cipher-cli.git
cd go-cipher-cli
go build -o go-cipher-cli ./main.go
```

## 命令

```bash
go-cipher-cli              # 显示帮助
go-cipher-cli version      # 输出版本号
go-cipher-cli run          # 交互式演示任务（提示 + 进度条）
go-cipher-cli --help       # 查看帮助
```

## 文档

| 主题 | 链接 |
| --- | --- |
| 安装 | https://kulaiyin.github.io/go-cipher-cli/guide/installation |
| 使用 | https://kulaiyin.github.io/go-cipher-cli/guide/usage |
| 打包与发布 | https://kulaiyin.github.io/go-cipher-cli/guide/packaging |
| APT 仓库 | https://kulaiyin.github.io/go-cipher-cli/guide/apt-repo |
| CI/CD | https://kulaiyin.github.io/go-cipher-cli/guide/ci-cd |

## 项目结构

```
├── main.go                 # 程序入口
├── cmd/                    # CLI 命令
├── docs/                   # VitePress 文档站源码
├── scripts/                # 打包与发布脚本
├── repo/conf/              # APT 仓库配置
├── .github/workflows/      # GitHub Actions 工作流
├── .goreleaser.yml         # goreleaser 配置
└── go.mod                  # Go 模块定义
```

## License

[MIT](LICENSE)
