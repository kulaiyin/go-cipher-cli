# APT 仓库与 GitHub Pages

go-cipher-cli 的 APT 仓库托管在 **GitHub Pages** 上。GitHub Pages 提供 HTTPS 静态文件托管，APT 仓库本质上就是一组静态文件（`dists/`、`pool/`、`Release`、`InRelease`），两者天然契合。

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

## 架构与发行版

- **架构**：`amd64`
- **发行版代号（Codename/Suite）**：`stable`
- **组件**：`main`

如需新增架构（如 `arm64`）或发行版（如 `testing`），需修改 `repo/conf/distributions` 与 `.goreleaser.yml` 的 build 目标。
