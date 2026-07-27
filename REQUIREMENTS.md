# 项目需求说明

## 目标

创建一个基于 Go 语言的 CLI 工具，使用 Cobra 作为命令框架，并集成配置管理、日志、交互提示和进度条功能。

## 主要需求

1. CLI 基础框架
   - 使用 `github.com/spf13/cobra`
   - 程序入口为 `main.go`
   - 命令逻辑组织在 `cmd/` 目录下

2. 配置管理
   - 使用 `github.com/spf13/viper`
   - 支持配置文件（YAML/JSON/TOML 等）
   - 支持环境变量读取
   - 支持默认值配置
   - 支持通过 `--config` 指定配置文件路径

3. 日志管理
   - 使用 `go.uber.org/zap`
   - 支持日志级别配置：`debug`、`info`、`warn`、`error`
   - 程序启动时初始化全局 Logger

4. 交互提示
   - 使用 `github.com/AlecAivazis/survey/v2`
   - 支持用户选择操作类型（例如 `Encrypt` / `Decrypt`）
   - 支持用户输入目标名称或其他参数

5. 进度条
   - 使用 `github.com/vbauerster/mpb/v8`
   - 在执行任务时显示进度条

6. CLI 命令
   - `run`：执行交互式演示任务
   - `version`：输出版本号
   - 根命令显示帮助信息

7. 打包与发布
   - 支持生成 Debian 安装包（`.deb`）
   - 支持通过远程 APT 仓库发布安装
   - 打包和发布应分为两步完成：
     1. 先生成 `.deb` 包
     2. 再将 `.deb` 包发布到远程仓库并生成仓库元数据
   - 推荐使用 `goreleaser` 生成 `.deb`
   - 推荐使用 `reprepro` 或 `aptly` 生成 APT 仓库元数据
   - 仓库应包含 `dists/`、`pool/`、`Release`、`InRelease` 等结构
   - 客户端通过添加源并执行 `apt update` 后安装
8. 通过 GitHub Pages 托管发布物
   - 将 APT 仓库（`dists/`、`pool/`、`Release`、`InRelease`、GPG 公钥）作为静态文件托管在 GitHub Pages
   - 客户端通过 `https://<owner>.github.io/<repo>/apt` 作为 APT 源地址安装
9. 文档网站
   - 使用 `VitePress` 构建中文文档网站，说明如何部署及使用
   - 文档网站与 APT 仓库共同托管在同一个 GitHub Pages 站点（文档在根路径，APT 仓库在 `/apt` 子路径）
10. CI/CD 自动化
   - 使用 GitHub Actions，在推送 `v*` tag 时自动执行：编译 → 生成 `.deb` → 生成 APT 仓库元数据 → GPG 签名 → 构建 VitePress → 部署到 GitHub Pages
   - GPG 签名私钥通过 GitHub Repository Secret 注入，不进入代码库

## 当前实现状态
- 已创建项目基础结构：`main.go`、`cmd/root.go`、`cmd/run.go`、`cmd/version.go`
- 已初始化 Go 模块并生成 `go.mod` / `go.sum`
- 已集成 `cobra`、`viper`、`zap`、`survey`、`mpb`
- 已编写中文 `PACKAGING.md`，说明如何构建 `.deb` 和发布远程 APT 仓库
- 已添加 `.goreleaser.yml` 用于生成 Debian 包
- 已初始化 git 仓库并推送至 GitHub，打好 `v0.1.0` tag
- 已新增 `VitePress` 中文文档站（`docs/` 目录）
- 已新增 GitHub Actions 工作流（`.github/workflows/release.yml`），push tag 时自动构建 `.deb`、APT 仓库元数据、VitePress 文档，并部署到 GitHub Pages

## 未来可扩展点

- 支持非交互式命令参数，如 `--action` 和 `--target`
- 增加更多子命令，例如 `encrypt`/`decrypt`/`config`
- 增加更完善的配置项和日志输出选项
