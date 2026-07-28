# 使用说明

go-cipher-cli 提供密钥管理、加密解密、哈希计算等命令，核心加密能力与 [web 工具](https://tools.wcheer.com/) 字节级互通——CLI 加密的文件可用 web 端解密，反之亦然。

## 命令总览

```bash
go-cipher-cli --help
```

```
Available Commands:
  completion  Generate the autocompletion script for the specified shell
  decrypt     解密容器（与 encrypt 或 web 工具产物兼容）
  encrypt     用 AES-256-GCM 加密文件（输出 web 兼容容器）
  fuse        融合多个密码（对应 computeFinalPassword）
  hash        文本哈希（MD5/SHA1/SHA2/SHA3）
  hint-match  验证提示/UUID 匹配（对应 validateHintAndKeysUuidMatch）
  hmac        计算 HMAC
  keygen      从盐 + 密码派生密钥（argon2id）
  recover     验证密钥恢复（对应 validateKeyRecovery）
  run         交互式演示任务
  version     输出版本号
```

## 版本号

```bash
go-cipher-cli version
# 输出: v0.2.0
```

## 加密与解密

### 加密文件（encrypt）

```bash
go-cipher-cli encrypt secret.txt -p "MyPass123" -p "SecondPass!" --salt "7a7a...7a7a"
```

输出：

```
Encrypted 75 bytes -> secret.txt.enc (salt embedded, version=10000)
```

参数说明：

| 参数 | 说明 |
| --- | --- |
| `-p, --password` | 密码，可重复（`-p a -p b`）。**密码顺序无关**，加密时用任意顺序，解密时也用任意顺序即可 |
| `--salt` | 可选，128 位十六进制盐。省略时自动随机生成并嵌入容器 |

加密后盐值嵌入容器，解密时只需密码。

::: tip 与 web 端互通
生成的 `.enc` 文件采用与 web 工具一致的容器格式，可直接上传到 [web 端](https://tools.wcheer.com/) 用相同密码解密。
:::

### 解密文件（decrypt）

```bash
# 密码顺序可与加密时不同
go-cipher-cli decrypt secret.txt.enc -p "SecondPass!" -p "MyPass123"
```

输出（还原为去掉 `.enc` 后缀的文件名）：

```
Decrypted 75 bytes -> secret.txt
```

密码错误时 GCM 认证失败：

```
decrypt: 密码错误！
```

::: warning 容器格式
`.enc` 文件是二进制容器（小端）：`version(4) | reserved(4) | salt_seed(64) | length(4) | 密文`。密文部分为 `iv(12) | 加密数据 | GCM tag(16)`。
:::

## 密钥派生（keygen）

用 argon2id 从密码派生密钥，可用于配置其他工具。

```bash
go-cipher-cli keygen -p "MyPass123" --salt "7a7a...7a7a" --hash-length 32
```

输出：

```
key (hex):      c34adb02a84ae6f8ba5f60560ea27d75adfd9f7b37442a93603f63e6d69179da
key (base64):   w0rbAqhK5vi6X2BWDqJ9da39n3s3RCqTYD9j5taRedo=
iterations:     3
hash length:    32 bytes
processing:     54ms
```

| 参数 | 说明 |
| --- | --- |
| `-p, --password` | 密码，可重复。**多密码会先用融合算法合并**（对应 web 端密码生成器的行为） |
| `--salt` | 可选，128 位十六进制盐。省略时随机生成 |
| `--hash-length` | 派生密钥字节数，默认 32 |

## 哈希计算

### 文本哈希（hash）

```bash
go-cipher-cli hash "hello" --algo sha256
# 输出: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

支持的算法（`--algo`）：

| 算法 | 示例值 |
| --- | --- |
| `md5` | `5d41402abc4b2a76b9719d911017c592` |
| `sha1` / `sha224` / `sha256` / `sha384` / `sha512` | SHA-2 家族 |
| `sha3-224` / `sha3-256` / `sha3-384` / `sha3-512` | SHA-3 家族 |

```bash
go-cipher-cli hash "hello" --algo sha3-512
# 输出: 75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976
```

默认算法为 `sha256`。

### HMAC（hmac）

```bash
go-cipher-cli hmac "hello" --algo hmac-sha256 --key "secret"
# 输出: 88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b
```

`--algo` 支持 `hmac-sha224` / `hmac-sha256` / `hmac-sha384` / `hmac-sha512` / `hmac-sha3-*`，也可省略 `hmac-` 前缀（如 `sha256`）。

## 密码与密钥恢复

### 密码融合（fuse）

将多个密码按前端算法融合为一个密码（去空格 + Unicode NFC + 融合打乱 + 插入特殊字符）。

```bash
go-cipher-cli fuse --salt "a76fdc37b135f1c3" -p "123456789" -p "shanghai" -p "@"
# 输出: a4s373h6a9^6ca2f1i5n8d1gfc7h@1b3573
```

设计为 1–3 个密码，融合结果与 web 端密码生成器完全一致。

### 密钥恢复验证（recover）

验证生成密钥的"前 8 位 + 后 8 位"是否出现在存储的 uuid 列表中（对应 web 端的密钥恢复校验）。

```bash
# 匹配
go-cipher-cli recover "abcdef1234567890WVWXYZ12345678" --uuid "abcdef1212345678"
# 输出: MATCH

# 不匹配
go-cipher-cli recover "abcdef1234567890WVWXYZ12345678" --uuid "nomatch00000000"
# 输出: NO MATCH
```

`--uuid` 可重复提供多个候选。

### 提示/UUID 匹配（hint-match）

比对加密提示和元数据提示中嵌入的 `密钥UUID:`，用于校验密钥归属。

```bash
go-cipher-cli hint-match --encrypted "密钥UUID: ab12cd34ef" --meta "密钥UUID: ab12cd34ef"
# 输出: MATCH
```

## 交互式演示（run）

```bash
go-cipher-cli run
```

执行流程：

1. **选择操作类型**（交互式下拉）：`Encrypt` 或 `Decrypt`，默认 `Encrypt`。
2. **输入目标名称**：文件名、key 或任意标识符。
3. **显示进度条**：以 MPB 渲染 0%→100% 进度。
4. **输出结果**与结构化日志（Zap）。

## 全局参数

### 指定配置文件

```bash
go-cipher-cli --config /path/to/config.yaml run
```

支持的配置格式：YAML / JSON / TOML 等（由 Viper 自动识别扩展名）。

若未指定 `--config`，将按以下顺序查找名为 `config` 的文件：

1. 当前目录 `.`
2. `$HOME/.go-cipher-cli/`

示例 `config.yaml`：

```yaml
log:
  level: info   # debug | info | warn | error
```

### 设置日志级别

```bash
go-cipher-cli --log-level debug run
```

可选值：`debug` / `info` / `warn` / `error`，默认 `info`。

::: tip 环境变量
所有配置项均可通过环境变量覆盖，前缀为 `GOCIPHER_`，`.` 替换为 `_`。
例如 `log.level` 对应环境变量 `GOCIPHER_LOG_LEVEL`：

```bash
GOCIPHER_LOG_LEVEL=warn go-cipher-cli run
```
:::

## 退出码

| 退出码 | 含义 |
| --- | --- |
| `0` | 成功 |
| `1` | 执行出错（如配置加载失败、命令返回错误、解密时密码错误） |
