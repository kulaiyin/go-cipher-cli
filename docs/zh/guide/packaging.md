# 打包与发布

本项目围绕 **goreleaser** 构建发布流程：先生成 `.deb` 包，再生成 APT 仓库元数据并签名，最后发布到 GitHub Pages。完整自动化流程见 [CI/CD 流水线](./ci-cd)。

## 目录结构

```
go-cipher-cli/
├── main.go                 # 程序入口
├── cmd/                    # CLI 命令（root / run / version）
├── .goreleaser.yml         # goreleaser 配置（生成 .deb）
├── scripts/
│   ├── package.sh          # 打包脚本（生成 .deb）
│   └── publish_repo.sh     # APT 仓库发布脚本
├── repo/conf/              # APT 仓库配置（distributions）
├── docs/                   # VitePress 文档站源码
└── .github/workflows/      # GitHub Actions 工作流
```

## 前提条件

| 工具 | 用途 | 安装命令 |
| --- | --- | --- |
| `go` >= 1.21 | 编译二进制 | 参考 https://go.dev/dl/ |
| `goreleaser` | 生成 `.deb`（推荐） | `go install github.com/goreleaser/goreleaser@latest` |
| `dpkg-deb` | 手工生成 `.deb`（回退方案，Debian/Ubuntu 自带） | `apt install dpkg-dev` |
| `reprepro` | 生成 APT 仓库元数据（推荐） | `apt install reprepro` |
| `aptly` | 生成 APT 仓库元数据（替代方案） | 参考 https://www.aptly.info/ |
| `apt-ftparchive` | 生成仓库元数据（reprepro 不可用时的回退方案） | `apt install apt-utils` |
| `gpg` | 对 `Release`/`InRelease` 签名 | `apt install gnupg` |

::: tip 回退机制
`package.sh` 与 `publish_repo.sh` 都有自动回退：goreleaser 不可用时回退到 dpkg-deb，reprepro/aptly 不可用时回退到 apt-ftparchive。因此即使环境不全，也能完成基础打包。
:::

## 两步流程

```
┌──────────────────┐     ┌──────────────────────────┐
│  第一步：打包      │     │  第二步：发布              │
│  scripts/         │ ──> │  scripts/publish_repo.sh  │
│  package.sh       │     │  生成 dists/ pool/        │
│  生成 .deb        │     │  Release/InRelease 签名   │
└──────────────────┘     └──────────────────────────┘
```

### 第一步：生成 .deb

```bash
bash scripts/package.sh
```

脚本逻辑（按优先级回退）：

1. **goreleaser**（首选）：执行 `goreleaser release --snapshot --clean`，产物位于 `dist/`。
2. **dpkg-deb**（回退）：当 goreleaser 不可用时，手工编译二进制并用 `dpkg-deb --build` 打包。

产物：`dist/go-cipher-cli_<version>_linux_amd64.deb`

goreleaser 的配置见 [`.goreleaser.yml`](https://github.com/kulaiyin/go-cipher-cli/blob/main/.goreleaser.yml)，其中 `nfpms` 段定义了包名、维护者、描述、安装路径（自动装到 `/usr/bin/go-cipher-cli`）。

#### 仅使用 goreleaser（可选）

如果你只想用 `goreleaser` 构建（不走回退逻辑）：

```bash
goreleaser release --snapshot --clean
```

#### 校验 .deb

```bash
dpkg-deb -I dist/go-cipher-cli_0.1.0_linux_amd64.deb   # 查看控制信息
dpkg-deb -c dist/go-cipher-cli_0.1.0_linux_amd64.deb   # 查看文件列表
```

### 第二步：发布到 APT 仓库

```bash
bash scripts/publish_repo.sh
```

该脚本读取 `dist/` 中最新的 `.deb`，生成 APT 仓库元数据。三种工具的详细用法与回退顺序见 [APT 仓库与 GitHub Pages](./apt-repo)。

## 相关主题

- [APT 仓库与 GitHub Pages](./apt-repo)：三种仓库元数据生成方案、GitHub Pages 托管、客户端安装。
- [CI/CD 流水线](./ci-cd)：push tag 后的全自动发布流程与签名密钥管理。
