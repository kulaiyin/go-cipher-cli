# 使用说明

go-cipher-cli 提供密码转密钥和 Diceware 助记口令生成两个核心功能，与 [web 工具](https://tools.wcheer.com/) 字节级互通。

## 命令总览

```bash
go-cipher-cli --help
```

```
Available Commands:
  completion  Generate the autocompletion script for the specified shell
  diceware    生成 Diceware 助记口令（EFF 词表，7776 词）
  enhance     将密码转换为 256 位高熵密钥（密码转密钥）
  help        Help about any command
  version     Print the CLI version
```

## 版本号

```bash
go-cipher-cli version
# 输出: v0.3.0
```

## 密码转密钥（enhance）

把你"常用但可能不够强"的密码，通过 Argon2id 慢函数加固，转换成 256 位高熵密钥。同一组密码 + 盐后缀**确定性**派生出相同的密钥，无法由密钥反推密码。

### 算法流程

1. **Argon2id 慢函数抗爆破**：以用户密码为输入，以「固定盐 + 用户盐后缀」为盐，参数 64MB / 3 轮迭代 / 1 路并行，输出 64 字节主密钥 (PRK)
2. **HKDF-Expand(SHA-256) 域分离**：对 PRK 做纯 Expand，输出 32 字节（256 位）子密钥
3. **输出**：64 位十六进制字符串，方便跨平台复制与对齐

### 基本用法

```bash
# 派生 256 位密钥
go-cipher-cli enhance -p "MyMaster@2024"

# 不同盐后缀派生不同密钥（推荐做法）
go-cipher-cli enhance -p "MyMaster@2024" --salt-suffix google
go-cipher-cli enhance -p "MyMaster@2024" --salt-suffix firefox
```

输出示例：

```
算法:     Argon2id(64MB/3轮/1路并行) + HKDF-Expand(SHA-256)
Domain:   default-v1
盐后缀:   google
密钥(hex):     3aac7a86fd8c549020841738920154a05bcae6dd116c116a991144df33a440eb
密钥(base64):  oqx6hv2MVJAg...9E3zOkDr
密钥长度:      256 位 (256 bit)
```

| 参数 | 说明 |
| --- | --- |
| `-p, --password` | 要转换的密码（必填） |
| `--salt-suffix` | 可选盐后缀（如站点名、设备名），不同后缀派生不同密钥 |
| `--domain` | 域标签（默认 `default-v1`，一般不修改） |

::: tip 与 web 端互通
只要「密码 + 盐后缀」相同，CLI 和 [web 工具](https://tools.wcheer.com/) 会派生出完全相同的 256 位密钥。
:::

::: tip 盐后缀的使用建议
为不同用途使用不同盐后缀（如 `google`、`firefox`），即可从同一密码派生出互不相同的密钥，避免"一处泄露处处泄露"。
:::

## Diceware 助记口令（diceware）

用 EFF 大型词表（7776 词）和密码学安全随机掷骰，生成易记但高熵的口令。

### 安全原理

- 随机源：`crypto/rand`（Go CSPRNG），采用拒绝采样消除模偏差
- 每词提供约 **12.9 bit** 信息熵：
  - 5 词 → ~64.6 bit
  - 6 词 → ~77.5 bit
  - 8 词 → ~103.4 bit
- 可能组合数 = 7776^词数（5 词约为 2.8×10^19）

### 基本用法

```bash
# 默认 5 词，无分隔符
go-cipher-cli diceware

# 指定词数和分隔符
go-cipher-cli diceware -n 8 --sep hyphen
go-cipher-cli diceware -n 6 --sep none
```

输出示例：

```
口令:         cavity-puppy-lego-vanquish-sediment
长度:         35 字符
词数:         5
信息熵:       64.62 bit
可能组合数:   2.84 × 10^19
分隔符:       连字符 (-)

逐词掷骰详情:
   1. [15264] cavity
   2. [45662] puppy
   3. [35656] lego
   4. [65415] vanquish
   5. [53443] sediment
```

| 参数 | 说明 |
| --- | --- |
| `-n, --num-words` | 单词数量（1-20，默认 5） |
| `--sep` | 分隔符：`space`（空格）/ `hyphen`（连字符） / `none`（无），默认 `none` |

## 全局参数

### 指定配置文件

```bash
go-cipher-cli --config /path/to/config.yaml enhance -p test
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
go-cipher-cli --log-level debug diceware
```

可选值：`debug` / `info` / `warn` / `error`，默认 `info`。

::: tip 环境变量
所有配置项均可通过环境变量覆盖，前缀为 `GOCIPHER_`，`.` 替换为 `_`。
例如 `log.level` 对应环境变量 `GOCIPHER_LOG_LEVEL`：

```bash
GOCIPHER_LOG_LEVEL=warn go-cipher-cli enhance -p test
```
:::

## 退出码

| 退出码 | 含义 |
| --- | --- |
| `0` | 成功 |
| `1` | 执行出错（如配置加载失败、命令返回错误） |
