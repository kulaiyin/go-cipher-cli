# 使用说明

go-cipher-cli 提供三个命令入口：根命令（帮助）、`version`（版本）、`run`（交互式演示）。

## 查看帮助

```bash
go-cipher-cli --help
```

输出：

```
go-cipher-cli is a CLI demo project using Cobra, Viper, Zap, Survey, and MPB.
It demonstrates configuration loading, structured logging, interactive prompts,
and progress bars.

Usage:
  go-cipher-cli [command]

Available Commands:
  run         Run an interactive demo task
  version     Print the CLI version

Flags:
      --config string      config file path
      --log-level string   log level (debug, info, warn, error) (default "info")
```

## 版本号

```bash
go-cipher-cli version
# 输出: v0.1.0
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

示例运行：

```
? Choose the operation: Encrypt
? Enter the target name: secret.dat
Processing...
Progress: 100%
Operation Encrypt completed for secret.dat
```

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
| `1` | 执行出错（如配置加载失败、Logger 初始化失败、命令返回错误） |
