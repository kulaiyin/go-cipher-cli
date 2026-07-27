# 密钥管理模块需求说明

本文档描述 `go-cipher-cli` 密钥管理模块的设计目标：对等实现前端项目 `frontend-cdn-tools`（`libs/common-tools`）的密钥管理逻辑，做到**字节级互通**——Go 加密的数据前端能解，反之亦然。

## 一、模块目标

将前端的密钥派生、密码融合、AES-256-GCM 加解密、二进制容器等能力，用 Go 复刻为命令行工具，并保证与 Web 端互操作的兼容性。

## 二、对等前端功能清单

| 前端函数 | 前端源文件 | Go 实现 | CLI 命令 |
|---|---|---|---|
| `KeyDerivation.argon2` / `hkdf` | `kdf/index.ts` | `internal/kdf.Argon2` / `HKDF` | `keygen` |
| `KeyDerivation.generateSalt` | `kdf/index.ts` | `internal/kdf.GenerateSalt` | `keygen`（自动生成） |
| `KeyDerivation.validatePasswordStrength` | `kdf/index.ts` | `internal/kdf.ValidatePasswordStrength` | （强度反馈） |
| `KeyDerivation.generateStrongPassword` | `kdf/index.ts` | `internal/kdf.GenerateStrongPassword` | （密码生成） |
| `normalizePassword` | `password/fusion.ts` | `internal/fusion.NormalizePassword` | `fuse`（内部） |
| `safety_merge_strings` / `fusePasswords` | `password/fusion.ts` | `internal/fusion.fuseMergeStrings` / `FusePasswords` | `fuse` |
| `computeFinalPassword` | `password/fusion.ts` | `internal/fusion.ComputeFinalPassword` | `fuse` |
| `deriveNewSalt` | `password/fusion.ts` | `internal/fusion.DeriveNewSalt` | （盐派生） |
| `AesGcmTools.generate_aes_gcm_key` | `crypto/aes-gcm.ts` | `internal/aesgcm.GenerateAesGcmKey` | `encrypt`/`decrypt`（内部） |
| `AesGcmTools.encryptWithPassword` / `decryptWithPassword` | `crypto/aes-gcm.ts` | `internal/aesgcm.EncryptWithPassword` / `DecryptWithPassword` | `encrypt` / `decrypt` |
| `CryptoTools.hashText` | `crypto/index.ts` | `internal/crypto.HashText` | `hash` |
| `HmacTools.hashText` | `crypto/index.ts` | `internal/crypto.HMAC` | `hmac` |
| `assembleDownloadData` / `extractDecryptedData` | `data-encryption.ts` | `internal/container.AssembleDownloadData` / `ExtractDecryptedData` | `encrypt`/`decrypt`（容器） |
| `validateHintAndKeysUuidMatch` | `data-encryption.ts` | `internal/container.ValidateHintAndKeysUuidMatch` | `hint-match` |
| `validateKeyRecovery` | `key-recovery.ts` | `internal/kdf.ValidateKeyRecovery` | `recover` |

## 三、加密管线

加密栈是一条链：**argon2id → HMAC-SHA3-512 → HKDF(SHA3-512) → AES-256-GCM**。

### 密钥派生流程（`generate_aes_gcm_key`）

```
输入: salt(128-hex 字符串)、passwords(字符串数组)
1. 过滤空密码
2. salt_text  = SHA256(pw) 逐个计算 → 排序 → 冒号拼接
3. salt_prk   = HMAC-SHA3-512(key=salt, msg=salt_text)        返回 hex 字符串
4. 由 salt_prk 经 HKDF 派生 4 个子密钥（各 64 字节）:
     s1    = HKDF(salt_prk, info="argon2id-salt")
     s2    = HKDF(salt_prk, info="hkdf-safety-key")
     s3    = HKDF(salt_prk, info="aes-256-gcm-dek")
     sdata = HKDF(salt_prk, info="aes-256-gcm-data")
5. 对每个弱密码（强度<8 或非 128-hex）强化:
     argon2id(pw, salt=s1, t=3, m=32768KiB, p=2, dkLen=64) → hex
     再 base64-decode(hex) → hex          [前端 quirk，见第五节]
6. usr_strong = 强化后密码排序 → 冒号拼接
7. prk_dek    = HMAC-SHA3-512(key=s3, msg=usr_strong)        返回 hex 字符串
8. aes_dek    = HKDF(prk_dek, info="aes-256-gcm-final-key", L=32)
返回: { aes_dek(32字节), sdata(64字节) }
```

### AES-256-GCM 加密（`gcmEncryptData`）

```
1. iv       = 随机 12 字节（明文存入输出）
2. data_prk = HMAC-SHA3-512(key=sdata, msg=iv)               返回 hex 字符串
3. iv_used  = HKDF(data_prk, info="aes-gcm-iv", L=12)        实际用于 GCM 的 nonce
4. AES-256-GCM.Seal(nonce=iv_used, plaintext, tagLen=128)
5. 输出 = iv(12) ‖ ciphertext ‖ tag(16)
```

注意：存入文件的是随机 `iv`，但喂给 AES-GCM 的 nonce 是 `iv` 再过一次 HMAC+HKDF 派生出的 `iv_used`。

## 四、二进制容器格式（小端）

```
偏移  长度  字段
0     4     version      (uint32 LE, 加密时 = 10000)
4     4     reserved      (uint32 LE, = 0)
8     64    salt_seed     (64 字节，渲染为 128-hex)
72    4     length        (uint32 LE, 密文长度)
76    N     ciphertext    (iv ‖ ciphertext ‖ tag)
```

## 五、字节兼容的关键陷阱（务必对齐）

| # | 陷阱 | 说明 |
|---|---|---|
| 1 | HKDF-Expand 实为完整 HKDF | 前端 `hkdf_expand` 调用 noble 全量 `hkdf(sha3_512, ikm, salt=空, info, L)`，Go 必须用 `hkdf.New(sha3, ikm, nil, info)`，盐为 nil 触发 Extract+Expand |
| 2 | PRK 以 hex 字符串的 ASCII 字节作 IKM/Key | IKM/Key 一律用 `[]byte(hexString)`，不要 `hex.DecodeString` |
| 3 | argon2 单位为 KiB | `memorySize` 单位是 KiB；强化参数 `t=3, m=32768, p=2, dkLen=64, salt=s1`；前端 noble 的 `m/=1024` 仅在 `NODE_ENV==="test"` 生效，Go 不复制 |
| 4 | `deriveStrongPassword` 的 base64 quirk | 前端把 argon2 的 **hex 摘出字符串误当 base64 解码**（`base64ToBytes(hashHex)`），再 hex 编码进 `processedPasswords`。这是前端真实行为（疑似 bug），Go 必须复刻 |
| 5 | `deriveNewSalt` 的 salt 按 ASCII 字节 | `KeyDerivation.argon2(originalSalt, {salt: originalSalt})` 中 salt 是字符串，按 ASCII 字节传入，不要 hex 解码 |

## 六、黄金向量验证机制

为保证字节级互通，采用**三方验证**：

1. **黄金向量生成**：前端项目 `libs/common-tools/scripts/gen-vectors.mjs` 用 `NODE_ENV=production` 跑出确定输出，固化为 `internal/testvectors/vectors.json`。
2. **真实源码权威测试**：前端 `libs/common-tools/tests/authoritative-*.test.ts` 直接调用真实 `AesGcmTools` / `deriveNewSalt` / `validateHintAndKeysUuidMatch` / `validateKeyRecovery`，断言与 `vectors.json` 一致。
3. **Go 测试**：各 `internal/*` 包的测试加载 `vectors.json` 做黄金向量比对。

三方一致即证明：真实源码 ↔ vectors.json ↔ Go 全链路字节对齐。

### 重新生成黄金向量

```bash
cd /works/gitworks/frontend-cdn-tools/libs/common-tools
NODE_ENV=production node scripts/gen-vectors.mjs > /works/gitworks/go-cipher-cli/internal/testvectors/vectors.json
```

### 运行前端权威测试

```bash
cd /works/gitworks/frontend-cdn-tools/libs/common-tools
NODE_ENV=production npx vitest run \
  tests/authoritative-vector.test.ts \
  tests/authoritative-derivables.test.ts \
  tests/authoritative-web-utils.test.ts \
  --testTimeout=60000
```

## 七、Go 库选型

全部使用标准库 + `golang.org/x/crypto` + `golang.org/x/text`，不引入第三方加密库：

| 用途 | 依赖 |
|---|---|
| Argon2id | `golang.org/x/crypto/argon2` |
| SHA3-512 / SHA3 系列 | `golang.org/x/crypto/sha3` |
| HKDF(SHA3-512) | `golang.org/x/crypto/hkdf` |
| HMAC(SHA3-512/SHA2) | 标准库 `crypto/hmac` |
| SHA-256 / MD5 / SHA1 / SHA2 | 标准库 |
| AES-256-GCM | 标准库 `crypto/aes` + `crypto/cipher` |
| 安全随机数 | 标准库 `crypto/rand` |
| Unicode NFC | `golang.org/x/text/unicode/norm` |
| Base64 / Hex | 标准库 `encoding/*` |
| 小端二进制容器 | 标准库 `encoding/binary` |
| CLI / 配置 / 日志 / 进度 | cobra / viper / zap / survey / mpb |

## 八、CLI 命令

| 命令 | 用途 | 对应前端能力 |
|---|---|---|
| `encrypt [file] -p <pw> [--salt <hex>]` | AES-256-GCM 加密文件，输出前端兼容容器 | `encryptWithPassword` + `assembleDownloadData` |
| `decrypt [file] -p <pw>` | 解密容器（盐从容器读取） | `decryptWithPassword` + `extractDecryptedData` |
| `keygen -p <pw> [--salt <hex>] [--hash-length N]` | argon2id 派生密钥（多密码走 fusion） | `KeyDerivation.argon2` + `computeFinalPassword` |
| `hash [text] --algo <name>` | 哈希文本（MD5/SHA1/SHA2/SHA3） | `CryptoTools.hashText` |
| `hmac [text] --algo <name> --key <k>` | HMAC 计算 | `HmacTools.hashText` |
| `fuse --salt <s> -p <pw>...` | 密码融合 | `computeFinalPassword` |
| `recover [key] --uuid <u>...` | 密钥恢复验证 | `validateKeyRecovery` |
| `hint-match --encrypted <t> --meta <t>` | 提示/UUID 匹配验证 | `validateHintAndKeysUuidMatch` |

## 九、包结构

```
internal/
├── safety/        # HKDF / HMAC / argon2 / 随机数 / 编码（底层原语）
├── kdf/           # KeyDerivation API（argon2 / hkdf / 盐 / 强度 / 恢复）
├── fusion/        # 密码融合（normalize / merge / fuse / deriveNewSalt）
├── aesgcm/        # AES-256-GCM 密钥派生 + 加解密
├── container/     # 二进制容器 + UUID 匹配
├── crypto/        # hash / HMAC / Base64 门面
└── testvectors/   # 黄金向量（embed 的 vectors.json + 加载器）
cmd/
├── encrypt.go / decrypt.go / keygen.go / utils.go
└── cli_e2e_test.go / utils_e2e_test.go   # 隔离进程端到端测试
```

## 十、测试矩阵

| 模块 | 测试内容 | 向量来源 |
|---|---|---|
| `safety` | HKDF-SHA3-512 / HMAC-SHA3-512 / argon2id / SHA256 / 编码 / 随机数 / 高强度判断 | gen-vectors |
| `kdf` | argon2 强化链路 / validatePasswordStrength / generateSalt / generateStrongPassword / validateKeyRecovery | gen-vectors + 前端 kdf.test.ts |
| `fusion` | normalizePassword / safetyMergeStrings / fusePasswords（含中文）/ deriveNewSalt | gen-vectors + 前端 password-fusion.test.ts |
| `aesgcm` | generate_aes_gcm_key 全管线 / 固定 IV 加密 / 往返 / 错误密码失败 / 非法输入 | gen-vectors（权威） |
| `container` | 组装/解析往返 / 短数据 / 错误长度 / salt 提取 / UUID 匹配 | gen-vectors + 内联 |
| `crypto` | MD5/SHA1/SHA2/SHA3 已知向量 / HMAC / Base64 往返 | 前端 crypto.test.ts |
| `cmd` | 各子命令端到端（隔离进程）+ encrypt/decrypt 往返 + 错误密码 | 内联 + 黄金向量 |

## 十一、已知未覆盖项

- **RSA 加解密**（前端 `jsencrypt`）：与密钥管理主线关联弱，jsencrypt 的 padding 方式需单独考证，暂未实现。
- **密钥派生配置文件导出**（前端 `KeyDerivationForm.downloadKeys`）：生成含 `uuid`/`salt`/`hint_ids`/`uuids` 的 `.txt` 配置文件，用于忘记密码时的密钥恢复。目前 Go 只实现了**校验侧**（`recover`/`hint-match`），未实现**生成侧**（`maskKey` 脱敏 + 配置导出）。
