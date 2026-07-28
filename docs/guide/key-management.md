# 密钥管理

本文介绍 go-cipher-cli 的密钥管理能力，以及它与 [web 工具](https://tools.wcheer.com/) 的互通关系。

## 核心能力

go-cipher-cli 复刻了 web 工具的密钥管理逻辑，使用同一套加密管线，做到**字节级互通**：

- CLI 加密的文件，web 端能用相同密码解密
- web 端加密的文件，CLI 也能解密
- 密钥派生、密码融合结果与 web 端完全一致

## 加密管线

加密栈是一条链：**argon2id → HMAC-SHA3-512 → HKDF(SHA3-512) → AES-256-GCM**。

```
密码 + 盐
   │
   ▼
1. SHA256(每个密码) → 排序 → 拼接为 salt_text
2. salt_prk = HMAC-SHA3-512(盐, salt_text)
3. 由 salt_prk 经 HKDF 派生 4 个子密钥（盐/密钥/数据）
4. 弱密码用 argon2id 强化（基于硬件成本，抵抗暴力破解）
5. 强化后的密码组合 → 派生最终的 AES-256 密钥
   │
   ▼
AES-256-GCM 加密（每次随机 IV + 128 位认证标签）
```

## 典型工作流

### 场景一：加密文件

```bash
# 1. 加密（盐自动生成并嵌入容器）
go-cipher-cli encrypt report.pdf -p "我的密码A" -p "我的密码B"
# 生成 report.pdf.enc

# 2. 解密（密码顺序无关）
go-cipher-cli decrypt report.pdf.enc -p "我的密码B" -p "我的密码A"
# 还原 report.pdf
```

盐值嵌入容器，**无需单独保存盐**，只需记住密码。

### 场景二：与 web 端协作

```bash
# CLI 加密
go-cipher-cli encrypt data.json -p "shared-secret"
# 生成 data.json.enc

# 把 data.json.enc 上传到 web 工具的"数据加密"页面
# 输入相同密码 "shared-secret" 即可解密
```

反之，web 端加密下载的文件，也能用 CLI 解密。

### 场景三：派生密钥给其他工具用

```bash
# 用 argon2id 从密码派生 32 字节密钥
go-cipher-cli keygen -p "我的主密码" --hash-length 32
# 输出 hex 和 base64 两种格式，可用于配置其他需要密钥的工具
```

## 安全说明

### 密码顺序无关

加密/解密时密码数组会先 SHA256 排序再参与派生，所以 `-p a -p b` 和 `-p b -p a` 等价。但**密码集合必须完全一致**（数量和内容）。

### 多密码增强

`encrypt` 和 `keygen` 支持多个密码：

- `encrypt`：多密码直接参与密钥派生（顺序无关）
- `keygen`：多密码会先用融合算法合并为一个再派生（对应 web 端密码生成器行为）

### 弱密码自动强化

输入弱密码时，CLI 会自动用 argon2id（3 次迭代、32 MiB 内存、2 并行度）进行强化，抵抗暴力破解。无需手动处理。

### AES-256-GCM 认证

每次加密生成随机 IV，附带 128 位 GCM 认证标签。密码错误时**不会输出错误数据**，而是认证失败报错，保证完整性。

## 与 web 工具的功能对照

| 能力 | CLI 命令 | web 工具对应 |
| --- | --- | --- |
| AES-256-GCM 加解密 | `encrypt` / `decrypt` | 数据加密页面 |
| argon2id 密钥派生 | `keygen` | 密钥派生页面 |
| 密码融合 | `fuse` | 密码生成器（多密码合并） |
| 哈希计算 | `hash` | 哈希工具（MD5/SHA/SHA3） |
| HMAC | `hmac` | HMAC 工具 |
| 密钥恢复验证 | `recover` | 密钥派生（恢复校验） |
| 提示/UUID 匹配 | `hint-match` | 数据加密（密钥归属校验） |

## 容器格式

`.enc` 文件是二进制容器（小端字节序）：

```
偏移  长度  字段
0     4     version      (uint32 LE, 当前 = 10000)
4     4     reserved      (uint32 LE, = 0)
8     64    salt_seed     (64 字节盐，渲染为 128 位 hex)
72    4     length        (uint32 LE, 密文长度)
76    N     ciphertext    (iv 12 字节 ‖ 加密数据 ‖ GCM tag 16 字节)
```

盐值存在偏移 8–72，解密时自动读取，因此**无需单独传递盐**。

## 技术细节

如需了解完整的派生流程、字节兼容的关键点、黄金向量验证机制等实现细节，请参考[密钥管理模块需求说明](../spec/key-management)。
