# go-cipher-cli

一个基于 Go 的 CLI 演示项目，演示如何集成配置管理、结构化日志、交互式提示和进度条，并支持打包为 Debian 安装包（`.deb`）发布到自托管 APT 仓库。

## 功能特性

- **命令框架**：[Cobra](https://github.com/spf13/cobra)
- **配置管理**：[Viper](https://github.com/spf13/viper) — 支持配置文件（YAML/JSON/TOML）、环境变量、默认值、`--config` 指定路径
- **日志**：[Zap](https://go.uber.org/zap) — 支持 `debug` / `info` / `warn` / `error` 级别
- **交互提示**：[Survey](https://github.com/AlecAivazis/survey/v2) — 选择操作类型、输入目标名称
- **进度条**：[MPB](https://github.com/vbauerster/mpb/v8)

## 命令

```bash
go-cipher-cli              # 显示帮助
go-cipher-cli version      # 输出版本号
go-cipher-cli run          # 执行交互式演示任务（提示 + 进度条）
go-cipher-cli --help       # 查看帮助
```

全局参数：

```bash
--config <path>            # 指定配置文件
--log-level <level>        # debug | info | warn | error（默认 info）
```

## 快速开始

### 从源码构建

```bash
go build -o go-cipher-cli ./main.go
```

### 通过 APT 安装（Debian/Ubuntu）

详见 [PACKAGING.md](PACKAGING.md)。

```bash
# 1. 导入仓库 GPG 公钥
curl -fsSL https://your-server/apt/repo.gpg.key | sudo gpg --dearmor \
  -o /usr/share/keyrings/go-cipher-cli.gpg

# 2. 添加源
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/go-cipher-cli.gpg] https://your-server/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/go-cipher-cli.list

# 3. 安装
sudo apt update
sudo apt install go-cipher-cli
```

## 打包与发布

打包与发布分两步完成：

```bash
# 第一步：生成 .deb（使用 goreleaser，失败回退到 dpkg-deb）
bash scripts/package.sh

# 第二步：发布到 APT 仓库并生成元数据（dists/ pool/ Release InRelease）
bash scripts/publish_repo.sh
```

详细的打包、签名、APT 仓库发布说明见 [PACKAGING.md](PACKAGING.md)。

## 项目结构

```
.
├── main.go                 # 程序入口
├── cmd/                    # CLI 命令（root / run / version）
├── .goreleaser.yml         # goreleaser 配置（生成 .deb）
├── scripts/
│   ├── package.sh          # 打包脚本
│   └── publish_repo.sh     # APT 仓库发布脚本
├── repo/conf/              # APT 仓库配置（reprepro distributions）
├── PACKAGING.md            # 打包与发布指南
└── REQUIREMENTS.md         # 项目需求说明
```

## License

MIT
