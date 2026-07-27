# CI/CD 流水线

go-cipher-cli 使用 **GitHub Actions** 实现全自动发布。当你推送一个 `v*` 格式的 tag（如 `v0.1.0`）时，流水线会自动完成编译、打包、签名、文档构建、部署的全过程。

工作流定义见 [`.github/workflows/release.yml`](https://github.com/kulaiyin/go-cipher-cli/blob/main/.github/workflows/release.yml)。

## 触发条件

```yaml
on:
  push:
    tags:
      - 'v*'
```

即任何形如 `v0.1.0`、`v1.2.3` 的 tag 推送都会触发。

## 流水线步骤

```
┌────────────────────────────────────────────────────────────────┐
│  push v* tag                                                    │
│      │                                                          │
│      ▼                                                          │
│  1. Checkout（fetch-depth: 0，goreleaser 需完整历史）            │
│      │                                                          │
│      ▼                                                          │
│  2. 设置 Go 环境                                                 │
│      │                                                          │
│      ▼                                                          │
│  3. goreleaser release                                          │
│     ├─ 编译 linux/amd64 二进制                                   │
│     ├─ 生成 .deb                                                 │
│     └─ 创建 GitHub Release，上传 .deb / tar.gz / checksums       │
│      │                                                          │
│      ▼                                                          │
│  4. 导入 GPG 私钥（从 Secret GPG_SIGNING_KEY 解码）              │
│      │                                                          │
│      ▼                                                          │
│  5. 运行 scripts/publish_repo.sh                                │
│     ├─ 生成 dists/ pool/ Release InRelease                      │
│     └─ 用导入的 key 签名                                         │
│      │                                                          │
│      ▼                                                          │
│  6. 导出 GPG 公钥到 repo/repo.gpg.key                            │
│      │                                                          │
│      ▼                                                          │
│  7. 构建 VitePress 文档站（npm ci && npm run docs:build）        │
│      │                                                          │
│      ▼                                                          │
│  8. 部署到 gh-pages 分支                                         │
│     ├─ 文档站 → 根路径                                           │
│     └─ APT 仓库 (repo/) → /apt 子路径                            │
└────────────────────────────────────────────────────────────────┘
```

## 发布版本号

版本号来源于 **git tag**：

- tag `v0.1.0` → goreleaser 产出 `go-cipher-cli_0.1.0_linux_amd64.deb`
- 同时该版本写入 APT 仓库的 `Packages` 索引

因此发版的唯一动作就是打 tag：

```bash
git tag v0.1.0
git push origin v0.1.0
# 此后全自动，无需干预
```

## 签名密钥管理

GPG 私钥通过 **GitHub Repository Secret** 注入，私钥本身永远不会进入代码库。

### 一次性配置（首次发布前）

1. **本地生成或复用 GPG key**（如已有可跳过）：

   ```bash
   gpg --gen-key
   # 记下生成的 Key ID，例如 9E38A2B39666B218
   ```

2. **导出私钥并 base64 编码**：

   ```bash
   gpg --armor --export-secret-keys 9E38A2B39666B218 | base64 -w0
   ```

3. **添加到仓库 Secret**：浏览器打开
   `https://github.com/kulaiyin/go-cipher-cli/settings/secrets/actions`
   → `New repository secret` → Name 填 `GPG_SIGNING_KEY`，Value 粘贴上一步的输出。

::: warning
`GPG_SIGNING_KEY` 是私钥，泄露后任何人都能伪造你的仓库签名。请：
- 仅在 GitHub Secret 中存储，不要写入任何文件
- 定期轮换（生成新 key，更新 Secret，重新发布一次让客户端导入新公钥）
:::

### 轮换密钥

1. 本地生成新 key。
2. 更新 `repo/conf/distributions` 的 `SignWith:` 为新 Key ID。
3. 更新 GitHub Secret `GPG_SIGNING_KEY`。
4. 重新触发一次发布，`repo.gpg.key` 会自动更新为新公钥。
5. 客户端需重新执行公钥导入步骤（`curl ... | sudo gpg --dearmor`）。

## 开启 GitHub Pages（首次部署）

首次发布成功后，`gh-pages` 分支会被创建。需在仓库设置中开启 Pages：

1. 浏览器打开 `https://github.com/kulaiyin/go-cipher-cli/settings/pages`
2. **Source** 选择 `Deploy from a branch`
3. **Branch** 选 `gh-pages`，目录选 `/ (root)`
4. 保存

几分钟后即可访问 `https://kulaiyin.github.io/go-cipher-cli/`。

## 本地预览发布产物

无需真的 push tag，可在本地复现整个流程：

```bash
# 1. 打包
bash scripts/package.sh

# 2. 生成 APT 仓库（指定输出目录便于隔离）
bash scripts/publish_repo.sh

# 3. 本地预览文档站
npm install
npm run docs:dev
```

## 失败排查

| 现象 | 可能原因 | 处理 |
| --- | --- | --- |
| goreleaser 步骤失败 | git tag 未推送 / 远端无 tag | 确认 `git push origin <tag>` |
| GPG 签名失败 | Secret `GPG_SIGNING_KEY` 未配置或格式错误 | 按上文重新导出并配置 |
| gh-pages 未更新 | Pages 未开启或分支选错 | 在 Settings → Pages 确认选 `gh-pages` |
| 客户端 `NO_PUBKEY` | 公钥未导入或已轮换 | 客户端重新执行公钥导入命令 |
