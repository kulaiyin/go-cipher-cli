# 密钥管理

本文介绍 go-cipher-cli 的密码转密钥和 Diceware 助记口令功能，以及它们与 [web 工具](https://tools.wcheer.com/) 的互通关系。

## 核心能力

### 密码转密钥（enhance）

将用户"头脑记忆"级别的密码，通过 Argon2id 慢函数加固 + HKDF-Expand(SHA-256) 域分离，转换成 256 位高熵密钥。**真正用于加密/认证的是这把密钥**，密码本身只是生成原料。

与 web 工具**字节级互通**：相同「密码 + 盐后缀」在 CLI 和 web 端会派生出完全相同的密钥。

### Diceware 助记口令（diceware）

用 EFF 大型词表（7776 词）和密码学安全随机掷骰，生成易记但高熵的口令。

## 密码转密钥管线

```
密码 + 盐后缀
   │
   ▼
1. 固定盐 = "Your_Super_Long_Fixed_Salt_String_Here_2026"
   全盐 = 固定盐 + 用户盐后缀
   │
   ▼
2. Argon2id(64MB/3轮/1路并行, 输出 64 字节)
   → 主密钥 PRK (512 位)
   │
   ▼
3. HKDF-Expand(SHA-256, PRK, domain="default-v1", 输出 32 字节)
   → 子密钥 (256 位)
   │
   ▼
4. 输出 64 位 hex 字符串
```

### 固定盐

第一层固定盐硬编码在代码中（`Your_Super_Long_Fixed_Salt_String_Here_2026`），与 web 端完全一致。它的作用是防止通用彩虹表——即使攻击者提前为所有常见密码构建了彩虹表，也会因为固定盐的存在而失效。

### 盐后缀

用户可选的第二层盐（如站点名、设备名），与固定盐拼接后作为 Argon2id 的盐。不同盐后缀会派生出互不相同的密钥：

```bash
go-cipher-cli enhance -p "MyMaster@2024" --salt-suffix google
# 输出: 3aac7a86fd8c549020841738920154a05bcae6dd116c116a991144df33a440eb

go-cipher-cli enhance -p "MyMaster@2024" --salt-suffix firefox
# 输出: 12a642320091c23fe4d1ba943c86ba9a60ad99f2eba6ce4814636a4cdd664e6d
```

即使谷歌的密钥泄露，火狐的密钥也是安全的。

### HKDF-Expand 域分离

Argon2id 输出的 64 字节主密钥 (PRK) 已经是均匀分布的高熵数据，因此跳过 HKDF-Extract，直接用纯 Expand 做域分离。内部 domain 标签固定为 `default-v1`。

## Diceware 口令生成原理

### EFF 词表

使用 EFF（Electronic Frontier Foundation）发布的大型 Diceware 词表，共 7776 个英文单词，按 5 骰子骰点（11111–66666）的 base-6 编码顺序排列：

- 骰点 `11111` → 下标 0 → `abacus`
- 骰点 `11112` → 下标 1 → `abdomen`
- ...
- 骰点 `66666` → 下标 7775 → `zoom`

### 真随机掷骰

每词掷 5 次骰（1–6），每次骰点来自 Go 标准库 `crypto/rand`（操作系统 CSPRNG）。采用**拒绝采样**消除模偏差：

- 生成随机字节（0–255）
- 只接受 0–251（6 的 42 倍），拒绝 252–255
- `byte % 6 + 1` 得到 1–6

这确保了每个骰点的概率严格为 1/6，无偏向。

### 熵值

| 词数 | 信息熵 | 可能组合数 | 安全等级 |
| --- | --- | --- | --- |
| 4 | 51.7 bit | 3.66 × 10¹² | 弱（不建议） |
| 5 | 64.6 bit | 2.84 × 10¹⁹ | 基础 |
| 6 | 77.5 bit | 2.21 × 10²³ | 良好 |
| 7 | 90.5 bit | 1.72 × 10²⁷ | 强 |
| 8 | 103.4 bit | 1.34 × 10³¹ | 很强 |

建议至少 5 个词。8 个词及以上适合对安全性要求极高的场景。

## 安全说明

### Argon2id 抗暴力破解

64MB 内存 / 3 轮迭代的参数使得每次派生耗时数秒，即便攻击者使用专用硬件也难以在有限时间内暴力破解。这是密码哈希竞赛 (PHC) 的获奖算法。

### 全部本地运算

密码和密钥始终在本地操作系统上运算，不会上传到任何服务器。

### 确定性派生

同一组「密码 + 盐后缀」永远得到相同的密钥。无需保存密钥本身，只需记住密码即可随时还原。无法由密钥反推密码。

## 与 web 工具的功能对照

| 能力 | CLI 命令 | web 工具对应 |
| --- | --- | --- |
| 密码转密钥 | `enhance` | 密钥管理 → 密码转密钥 |
| Diceware 助记口令 | `diceware` | 密钥管理 → Diceware 助记口令生成 |

## 技术细节

### 跨语言一致性保证

密码转密钥的 Go 实现通过了 6 组**黄金向量测试**：
- 3 组不同 domain（age-key-v1 / file-key-v1 / auth-key-v1）
- 3 组不同密码 + 盐后缀组合（弱密码 / 强密码 / 中文密码）

所有向量由 Go 参考实现生成，CLI 和 web 端都必须全部通过才算实现正确。

### 完整测试覆盖

```bash
go test ./internal/... -v
# internal/kdf: TestDeriveSubKeyByDomain_GoldenVectors (6 组向量)
# internal/diceware: 词表完整性、骰点映射、口令生成、随机性、边界处理
```
