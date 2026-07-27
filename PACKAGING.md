# 打包与发布指南

本文档说明如何为 `go-cipher-cli` 构建 Debian 安装包（`.deb`），并将其发布到自托管的 APT 仓库，供客户端通过 `apt` 安装。

整个流程严格分为**两步**完成：

1. **打包**：使用 `goreleaser`（或回退到 `dpkg-deb`）生成 `.deb` 文件。
2. **发布**：将 `.deb` 加入本地 APT 仓库，并生成仓库元数据（`dists/`、`pool/`、`Release`、`InRelease`）。

---

## 一、目录结构概览

```
go-cipher-cli/
├── main.go                 # 程序入口
├── cmd/                    # CLI 命令实现
├── .goreleaser.yml         # goreleaser 配置（生成 .deb）
├── scripts/
│   ├── package.sh          # 第一步：生成 .deb
│   └── publish_repo.sh     # 第二步：发布到 APT 仓库
├── dist/                   # 构建产物（.deb 输出目录）
├── build/                  # 手工 dpkg-deb 打包的中间目录
└── repo/                   # APT 仓库根目录
    └── conf/
        └── distributions   # reprepro 仓库描述文件
```

---

## 二、前提条件

请确保系统中已安装下列工具：

| 工具 | 用途 | 安装命令 |
| --- | --- | --- |
| `go` >= 1.21 | 编译二进制 | 参考 https://go.dev/dl/ |
| `goreleaser` | 生成 `.deb`（推荐） | `go install github.com/goreleaser/goreleaser@latest` 或 `npm i -g @goreleaser/goreleaser` |
| `dpkg-deb` | 手工生成 `.deb`（回退方案，Debian/Ubuntu 自带） | `apt install dpkg-dev` |
| `reprepro` | 生成 APT 仓库元数据（推荐） | `apt install reprepro` |
| `aptly` | 生成 APT 仓库元数据（替代方案） | 参考 https://www.aptly.info/ |
| `apt-ftparchive` | 生成仓库元数据（reprepro 不可用时的回退方案） | `apt install apt-utils` |
| `gpg` | 对 `Release`/`InRelease` 签名 | `apt install gnupg` |

---

## 三、第一步：生成 `.deb` 包

执行打包脚本：

```bash
bash scripts/package.sh
```

脚本会：

1. 优先尝试使用 `goreleaser release --snapshot --clean` 构建。
2. 如果 `goreleaser` 不可用，会尝试通过 `npm` 自动安装。
3. 若仍然失败，则回退到 `dpkg-deb` 手工打包。

构建完成后，产物位于：

```
dist/go-cipher-cli_<version>_linux_amd64.deb
```

> 当前版本：`0.1.0`，架构：`amd64`。

### 仅使用 goreleaser（可选）

如果你只想用 `goreleaser` 构建：

```bash
goreleaser release --snapshot --clean
```

`.goreleaser.yml` 的 `nfpms` 段定义了 `.deb` 的元数据（包名、维护者、描述、安装路径 `/usr/bin/go-cipher-cli` 等）。

### 校验 .deb

```bash
dpkg-deb -I dist/go-cipher-cli_0.1.0_linux_amd64.deb   # 查看控制信息
dpkg-deb -c dist/go-cipher-cli_0.1.0_linux_amd64.deb   # 查看文件列表
```

---

## 四、第二步：发布到 APT 仓库

### 4.1 准备仓库配置

仓库描述文件已存在于 `repo/conf/distributions`：

```
Origin: go-cipher-cli
Label: go-cipher-cli
Suite: stable
Codename: stable
Architectures: amd64
Components: main
Description: go-cipher-cli APT repository
SignWith: YOUR-KEY-ID
```

> 发布前请将 `SignWith: YOUR-KEY-ID` 替换为你的真实 GPG Key ID（可通过 `gpg --list-keys` 查看），或删除该行以跳过签名。

### 4.2 方案 A：使用 reprepro（推荐）

```bash
bash scripts/publish_repo.sh
```

该脚本会自动：

1. 在 `dist/` 中查找最新的 `.deb` 包。
2. 调用 `reprepro -b repo includedeb stable <deb文件>`，将其加入仓库。
3. 生成 `repo/dists/`、`repo/pool/` 以及 `Release` / `InRelease` 元数据。

完成后仓库结构如下：

```
repo/
├── conf/
│   └── distributions
├── dists/
│   └── stable/
│       ├── InRelease
│       ├── Release
│       ├── Release.gpg
│       └── main/
│           └── binary-amd64/
│               ├── Packages
│               └── Packages.gz
└── pool/
    └── main/
        └── g/
            └── go-cipher-cli/
                └── go-cipher-cli_0.1.0_linux_amd64.deb
```

### 4.3 方案 B：使用 aptly（替代方案）

```bash
aptly repo create -distribution=stable -component=main go-cipher-cli-repo
aptly repo add go-cipher-cli-repo dist/go-cipher-cli_0.1.0_linux_amd64.deb
aptly publish repo -architectures=amd64 go-cipher-cli-repo
```

### 4.4 方案 C：使用 apt-ftparchive（无 reprepro 时的回退方案）

当 `reprepro` 与 `aptly` 均不可用时，可使用 `apt-ftparchive` 手工生成仓库元数据：

```bash
cd repo
# 1. 将 .deb 拷贝到 pool 目录
mkdir -p pool/main/g/go-cipher-cli
cp ../dist/go-cipher-cli_0.1.0_linux_amd64.deb pool/main/g/go-cipher-cli/

# 2. 生成 Packages 索引
apt-ftparchive packages pool > dists/stable/main/binary-amd64/Packages
gzip -kf dists/stable/main/binary-amd64/Packages

# 3. 生成 Release 文件
apt-ftparchive \
  -o APT::FTPArchive::Release::Origin="go-cipher-cli" \
  -o APT::FTPArchive::Release::Label="go-cipher-cli" \
  -o APT::FTPArchive::Release::Suite="stable" \
  -o APT::FTPArchive::Release::Codename="stable" \
  -o APT::FTPArchive::Release::Architectures="amd64" \
  -o APT::FTPArchive::Release::Components="main" \
  release dists/stable > dists/stable/Release

# 4. 签名（生成 InRelease 与 Release.gpg）
gpg --default-key YOUR-KEY-ID -abs -o dists/stable/Release.gpg dists/stable/Release
gpg --default-key YOUR-KEY-ID --clearsign -o dists/stable/InRelease dists/stable/Release
```

---

## 五、将仓库发布到 GitHub Pages（推荐）

本项目默认通过 **GitHub Pages** 托管 APT 仓库，过程由 GitHub Actions 自动完成（详见第十节）。仓库最终地址为：

```
https://kulaiyin.github.io/go-cipher-cli/apt
```

如果你希望自己手工发布到任意静态 HTTP 服务器（如 nginx、对象存储），把 `repo/` 目录的内容（`dists/`、`pool/`、`repo.gpg.key`）整体上传即可：

```bash
rsync -avz --delete repo/dists repo/pool repo/repo.gpg.key \
  user@your-server:/var/www/go-cipher-cli/apt/
```

确保远程目录可通过 `https://your-server/go-cipher-cli/apt/` 访问。

---

## 六、客户端安装

### 6.1 添加 APT 源

```bash
# 信任发布者 GPG 公钥（首次）
curl -fsSL https://kulaiyin.github.io/go-cipher-cli/apt/repo.gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/go-cipher-cli.gpg

# 添加源
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/go-cipher-cli.gpg] https://kulaiyin.github.io/go-cipher-cli/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/go-cipher-cli.list
```

### 6.2 安装

```bash
sudo apt update
sudo apt install go-cipher-cli
```

安装完成后即可使用：

```bash
go-cipher-cli version
go-cipher-cli run
```

---

## 七、CI 签名密钥配置（GitHub Actions）

CI 在 push tag 时会自动对 APT 仓库签名，私钥通过 **GitHub Repository Secret** 注入，私钥本身永不进入代码库。首次发布前需完成一次性配置。

### 7.1 生成或复用 GPG key

本地生成（如已有可复用）：

```bash
gpg --gen-key
# 记下 Key ID，例如 9E38A2B39666B218
```

### 7.2 导出私钥并 base64 编码

```bash
gpg --armor --export-secret-keys 9E38A2B39666B218 | base64 -w0
```

`base64 -w0` 输出单行，避免 Secret 里出现换行导致导入失败。

### 7.3 配置 GitHub Secret

1. 浏览器打开 `https://github.com/kulaiyin/go-cipher-cli/settings/secrets/actions`
2. 点击 `New repository secret`
3. **Name**：`GPG_SIGNING_KEY`
4. **Value**：粘贴上一步的 base64 输出
5. 保存

同时确保 `repo/conf/distributions` 里的 `SignWith:` 与该 Key ID 一致（当前为 `9E38A2B39666B218`）。CI 的 `publish_repo.sh` 会自动读取这个值并用导入的私钥签名。

### 7.4 安全须知

- 私钥泄露后任何人都能伪造你的仓库签名。请只在 GitHub Secret 中存储，**绝不**写入任何文件或日志。
- 轮换密钥：生成新 key → 更新 `SignWith` → 更新 Secret `GPG_SIGNING_KEY` → 重新触发发布 → 通知客户端重新导入公钥。

---

## 八、常见问题

- **`goreleaser: command not found`**：执行 `scripts/package.sh` 会自动尝试通过 `npm` 安装；或手动 `go install github.com/goreleaser/goreleaser@latest`。
- **`reprepro: command not found`**：改用本文档 4.4 节的 `apt-ftparchive` 回退方案。
- **签名失败 / `InRelease` 报错**：先用 `gpg --gen-key` 生成密钥，并把仓库配置中的 `YOUR-KEY-ID` 替换为真实 Key ID。
- **客户端 `NO_PUBKEY` 报错**：未正确导入发布者公钥，请按 6.1 节导入。
- **CI 中签名失败**：检查 Secret `GPG_SIGNING_KEY` 是否配置、是否为 `base64 -w0` 单行格式，以及 `SignWith` 是否一致。
