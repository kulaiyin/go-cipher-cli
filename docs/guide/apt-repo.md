# APT 仓库与 GitHub Pages

go-cipher-cli 的 APT 仓库托管在 **GitHub Pages** 上。GitHub Pages 提供 HTTPS 静态文件托管，而 APT 仓库本质上就是一组静态文件（`dists/`、`pool/`、`Release`、`InRelease`），两者天然契合。

## 仓库地址

```
https://kulaiyin.github.io/go-cipher-cli/apt
```

Pages 站点同时托管两套内容：

```
https://kulaiyin.github.io/go-cipher-cli/
├── index.html              ← 你正在看的 VitePress 文档站（根路径）
├── guide/...               ← 文档页面
└── apt/                    ← APT 仓库（/apt 子路径）
    ├── dists/stable/...    ← Release / InRelease / Packages
    ├── pool/main/.../...deb
    └── repo.gpg.key        ← 客户端导入用 GPG 公钥
```

## 客户端安装

三步完成（详见 [安装指南](./installation)）：

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
```

## 仓库元数据生成方案

`scripts/publish_repo.sh` 按优先级自动选择以下工具之一。三个方案任选其一即可。

### 方案 A：reprepro（推荐）

```bash
bash scripts/publish_repo.sh
```

脚本内部执行：

1. 在 `dist/` 中查找最新的 `.deb` 包。
2. 调用 `reprepro -b repo includedeb stable <deb文件>`，将其加入仓库。
3. 生成 `repo/dists/`、`repo/pool/` 以及 `Release` / `InRelease` 元数据。

### 方案 B：aptly（替代方案）

当 reprepro 不可用时，脚本会自动改用 aptly：

```bash
aptly repo create -distribution=stable -component=main go-cipher-cli-repo
aptly repo add go-cipher-cli-repo dist/go-cipher-cli_0.1.0_linux_amd64.deb
aptly publish repo -architectures=amd64 go-cipher-cli-repo
```

### 方案 C：apt-ftparchive（无 reprepro/aptly 时的回退方案）

当 `reprepro` 与 `aptly` 均不可用时，可使用 `apt-ftparchive` 手工生成仓库元数据。脚本会自动回退到此方案，手工等价命令如下：

```bash
cd repo
# 1. 将 .deb 拷贝到 pool 目录
mkdir -p pool/main/g/go-cipher-cli
cp ../dist/go-cipher-cli_0.1.0_linux_amd64.deb pool/main/g/go-cipher-cli/

# 2. 生成 Packages 索引
apt-ftparchive packages pool > dists/stable/main/binary-amd64/Packages
gzip -kf dists/stable/main/binary-amd64/Packages

# 3. 生成 Release 文件（先写到临时文件再 mv，避免自引用校验和）
apt-ftparchive \
  -o APT::FTPArchive::Release::Origin="go-cipher-cli" \
  -o APT::FTPArchive::Release::Label="go-cipher-cli" \
  -o APT::FTPArchive::Release::Suite="stable" \
  -o APT::FTPArchive::Release::Codename="stable" \
  -o APT::FTPArchive::Release::Architectures="amd64" \
  -o APT::FTPArchive::Release::Components="main" \
  release dists/stable > dists/stable/Release.new
mv dists/stable/Release.new dists/stable/Release

# 4. 签名（生成 InRelease 与 Release.gpg）
gpg --default-key YOUR-KEY-ID -abs -o dists/stable/Release.gpg dists/stable/Release
gpg --default-key YOUR-KEY-ID --clearsign -o dists/stable/InRelease dists/stable/Release
```

::: warning 避免自引用
`apt-ftparchive release` 必须输出到临时文件再 `mv`，不能直接重定向到 `Release`。否则 shell 会先创建空的 `Release` 文件，apt-ftparchive 扫描目录时就会把它计入自身校验和，导致客户端校验失败。
:::

## 仓库结构说明

| 文件 | 作用 |
| --- | --- |
| `dists/stable/Release` | 仓库元数据：架构、组件、文件校验和（MD5/SHA1/SHA256/SHA512） |
| `dists/stable/InRelease` | Release 的内联 GPG 签名（clearsign），apt 优先校验此文件 |
| `dists/stable/Release.gpg` | Release 的分离签名，InRelease 不可用时的回退 |
| `dists/stable/main/binary-amd64/Packages` | 所有 `.deb` 的索引清单（包名、版本、依赖、路径） |
| `dists/stable/main/binary-amd64/Packages.gz` | Packages 的 gzip 压缩版 |
| `pool/main/g/go-cipher-cli/*.deb` | 实际的安装包文件 |
| `repo.gpg.key` | 发布者 GPG 公钥（ASCII armored），客户端需导入 |

## 签名与信任

APT 仓库由 GPG key `9E38A2B39666B218`（指纹 `E489 52BD 5A15 B74A 3259 9B6D 9E38 A2B3 9666 B218`）签名。客户端通过导入 `repo.gpg.key` 并在源声明中使用 `signed-by=` 建立信任关系，无需全局信任。

私钥保存在 GitHub Repository Secret 中，不进入代码库。配置与轮换流程见 [CI/CD 流水线](./ci-cd) 的"签名密钥管理"一节。

## 自定义 HTTP 服务器托管

GitHub Pages 是默认托管方式，但如果你希望自建 HTTP 服务器（nginx、对象存储等），把 `repo/` 目录的内容（`dists/`、`pool/`、`repo.gpg.key`）整体上传即可：

```bash
rsync -avz --delete repo/dists repo/pool repo/repo.gpg.key \
  user@your-server:/var/www/go-cipher-cli/apt/
```

确保远程目录可通过 `https://your-server/go-cipher-cli/apt/` 访问，然后把客户端源地址换成你的服务器地址。

## 架构与发行版

- **架构**：`amd64`
- **发行版代号（Codename/Suite）**：`stable`
- **组件**：`main`

如需新增架构（如 `arm64`）或发行版（如 `testing`），需修改 `repo/conf/distributions` 与 `.goreleaser.yml` 的 build 目标。
