# 安装

go-cipher-cli 提供两种安装方式：通过 APT 仓库安装（推荐，支持自动更新），或从源码构建。

## 通过 APT 仓库安装（推荐）

::: tip 仓库地址
APT 仓库托管于 GitHub Pages：`https://kulaiyin.github.io/go-cipher-cli/apt`
:::

### 1. 导入 GPG 公钥

APT 仓库使用 GPG 签名，客户端需先导入发布者公钥以校验完整性：

```bash
curl -fsSL https://kulaiyin.github.io/go-cipher-cli/apt/repo.gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/go-cipher-cli.gpg
```

### 2. 添加 APT 源

```bash
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/go-cipher-cli.gpg] https://kulaiyin.github.io/go-cipher-cli/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/go-cipher-cli.list
```

### 3. 安装

```bash
sudo apt update
sudo apt install go-cipher-cli
```

### 4. 验证

```bash
go-cipher-cli version
# 输出: v0.1.0
```

## 从源码构建

需要 Go 1.21+。

```bash
git clone https://github.com/kulaiyin/go-cipher-cli.git
cd go-cipher-cli
go build -o go-cipher-cli ./main.go
```

编译产物为当前目录下的 `go-cipher-cli` 二进制，可手动复制到 `/usr/local/bin/`。

## 从 GitHub Release 下载

每次发布 tag 时，CI 会自动在 [GitHub Release 页面](https://github.com/kulaiyin/go-cipher-cli/releases) 上传 `.deb` 与压缩包，可直接下载后安装：

```bash
# 下载 .deb 后
sudo dpkg -i go-cipher-cli_*_linux_amd64.deb
```

## 升级与卸载

```bash
# 升级到最新版（APT 安装的用户）
sudo apt update && sudo apt upgrade go-cipher-cli

# 卸载
sudo apt remove go-cipher-cli
```

## 网络问题应对

如果 `apt update` 报 `Could not handshake` 或 curl 报"连接被对方重置"，通常是 `*.github.io` 被网络干扰（如中国大陆的 GFW）。可选三种应对方式：

### 方式 1：为 apt 配置代理

```bash
sudo https_proxy=http://你的代理地址:端口 apt update
sudo https_proxy=http://你的代理地址:端口 apt install go-cipher-cli
```

### 方式 2：改用 jsDelivr CDN 镜像（无需代理）

jsDelivr 会镜像 GitHub 仓库内容，国内通常可达：

```bash
# 公钥改用 jsDelivr 镜像
curl -fsSL https://cdn.jsdelivr.net/gh/kulaiyin/go-cipher-cli@gh-pages/apt/repo.gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/go-cipher-cli.gpg

# 源地址改用 jsDelivr
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/go-cipher-cli.gpg] https://cdn.jsdelivr.net/gh/kulaiyin/go-cipher-cli@gh-pages/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/go-cipher-cli.list

sudo apt update
sudo apt install go-cipher-cli
```

::: tip jsDelivr 缓存
jsDelivr 缓存有延迟（几小时到一天），刚发布的新版本可能需要等待缓存刷新。
:::

### 方式 3：直接下载 .deb 手工安装

绕过 APT 仓库，直接从 GitHub Release 下载（`github.com` 域名通常比 `github.io` 更可达）：

```bash
curl -fsSL -o /tmp/go-cipher-cli.deb \
  https://github.com/kulaiyin/go-cipher-cli/releases/download/v0.1.0/go-cipher-cli_0.1.0_linux_amd64.deb
sudo dpkg -i /tmp/go-cipher-cli.deb
go-cipher-cli version
```
