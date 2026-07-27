# 打包与发布概述

go-cipher-cli 的发布流程围绕 **goreleaser** 构建，分为两步：先生成 `.deb` 包，再生成 APT 仓库元数据并签名。完整流程由 GitHub Actions 自动化执行，详见 [CI/CD 流水线](./ci-cd)。

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

### 第二步：发布到 APT 仓库

```bash
bash scripts/publish_repo.sh
```

该脚本读取 `dist/` 中最新的 `.deb`，生成 APT 仓库元数据，并按优先级选择工具：

1. **reprepro**（推荐）
2. **aptly**（替代方案）
3. **apt-ftparchive**（回退方案，无外部依赖时使用）

生成产物位于 `repo/` 目录：

```
repo/
├── conf/distributions       # 仓库描述（Suite、Codename、SignWith 等）
├── dists/stable/
│   ├── InRelease            # GPG 内联签名
│   ├── Release
│   ├── Release.gpg          # GPG 分离签名
│   └── main/binary-amd64/
│       ├── Packages
│       └── Packages.gz
└── pool/main/g/go-cipher-cli/
    └── go-cipher-cli_<version>_linux_amd64.deb
```

## 校验 .deb

```bash
dpkg-deb -I dist/go-cipher-cli_0.1.0_linux_amd64.deb   # 查看控制信息
dpkg-deb -c dist/go-cipher-cli_0.1.0_linux_amd64.deb   # 查看文件列表
```

## 详细子主题

- [APT 仓库与 GitHub Pages](./apt-repo)：如何把仓库托管到 GitHub Pages，客户端如何安装。
- [CI/CD 流水线](./ci-cd)：push tag 后的全自动发布流程。
- 完整手工流程与常见问题排查见仓库根目录的 [PACKAGING.md](https://github.com/kulaiyin/go-cipher-cli/blob/main/PACKAGING.md)。
