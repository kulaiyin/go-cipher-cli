# Key Management Module Specification

This document describes the design goals of the `go-cipher-cli` key management module: to implement the key management logic of the peer frontend project `frontend-cdn-tools` (`libs/common-tools`) with **byte-level interoperability** — data encrypted by Go can be decrypted by the frontend, and vice versa.

## 1. Module Goals

Replicate the frontend's key derivation, password fusion, AES-256-GCM encryption/decryption, and binary container capabilities in Go as a command-line tool, while ensuring interoperability compatibility with the web client.

## 2. Peer Frontend Feature Inventory

| Frontend Function | Frontend Source File | Go Implementation | CLI Command |
|---|---|---|---|
| `KeyDerivation.argon2` / `hkdf` | `kdf/index.ts` | `internal/kdf.Argon2` / `HKDF` | `keygen` |
| `KeyDerivation.generateSalt` | `kdf/index.ts` | `internal/kdf.GenerateSalt` | `keygen` (auto-generated) |
| `KeyDerivation.validatePasswordStrength` | `kdf/index.ts` | `internal/kdf.ValidatePasswordStrength` | (strength feedback) |
| `KeyDerivation.generateStrongPassword` | `kdf/index.ts` | `internal/kdf.GenerateStrongPassword` | (password generation) |
| `normalizePassword` | `password/fusion.ts` | `internal/fusion.NormalizePassword` | `fuse` (internal) |
| `safety_merge_strings` / `fusePasswords` | `password/fusion.ts` | `internal/fusion.fuseMergeStrings` / `FusePasswords` | `fuse` |
| `computeFinalPassword` | `password/fusion.ts` | `internal/fusion.ComputeFinalPassword` | `fuse` |
| `deriveNewSalt` | `password/fusion.ts` | `internal/fusion.DeriveNewSalt` | (salt derivation) |
| `AesGcmTools.generate_aes_gcm_key` | `crypto/aes-gcm.ts` | `internal/aesgcm.GenerateAesGcmKey` | `encrypt`/`decrypt` (internal) |
| `AesGcmTools.encryptWithPassword` / `decryptWithPassword` | `crypto/aes-gcm.ts` | `internal/aesgcm.EncryptWithPassword` / `DecryptWithPassword` | `encrypt` / `decrypt` |
| `CryptoTools.hashText` | `crypto/index.ts` | `internal/crypto.HashText` | `hash` |
| `HmacTools.hashText` | `crypto/index.ts` | `internal/crypto.HMAC` | `hmac` |
| `assembleDownloadData` / `extractDecryptedData` | `data-encryption.ts` | `internal/container.AssembleDownloadData` / `ExtractDecryptedData` | `encrypt`/`decrypt` (container) |
| `validateHintAndKeysUuidMatch` | `data-encryption.ts` | `internal/container.ValidateHintAndKeysUuidMatch` | `hint-match` |
| `validateKeyRecovery` | `key-recovery.ts` | `internal/kdf.ValidateKeyRecovery` | `recover` |
| `KeyDerivationForm.deriveKey` (key-set pipeline #1) | `KeyDerivationForm.vue` | `internal/kdf.DeriveKeySet` | `key-derive` |

## 3. Encryption Pipeline

The encryption stack is a chain: **argon2id → HMAC-SHA3-512 → HKDF(SHA3-512) → AES-256-GCM**.

### Key Derivation Flow (`generate_aes_gcm_key`)

```
Input: salt (128-hex string), passwords (string array)
1. Filter out empty passwords
2. salt_text  = SHA256(pw) computed for each → sorted → joined with colons
3. salt_prk   = HMAC-SHA3-512(key=salt, msg=salt_text)        returns a hex string
4. Derive 4 subkeys from salt_prk via HKDF (64 bytes each):
     s1    = HKDF(salt_prk, info="argon2id-salt")
     s2    = HKDF(salt_prk, info="hkdf-safety-key")
     s3    = HKDF(salt_prk, info="aes-256-gcm-dek")
     sdata = HKDF(salt_prk, info="aes-256-gcm-data")
5. Harden each weak password (strength < 8 or not 128-hex):
     argon2id(pw, salt=s1, t=3, m=32768KiB, p=2, dkLen=64) → hex
     then base64-decode(hex) → hex          [frontend quirk, see section 5]
6. usr_strong = hardened passwords sorted → joined with colons
7. prk_dek    = HMAC-SHA3-512(key=s3, msg=usr_strong)        returns a hex string
8. aes_dek    = HKDF(prk_dek, info="aes-256-gcm-final-key", L=32)
Return: { aes_dek (32 bytes), sdata (64 bytes) }
```

### AES-256-GCM Encryption (`gcmEncryptData`)

```
1. iv       = 12 random bytes (stored in plaintext in the output)
2. data_prk = HMAC-SHA3-512(key=sdata, msg=iv)               returns a hex string
3. iv_used  = HKDF(data_prk, info="aes-gcm-iv", L=12)        nonce actually fed to GCM
4. AES-256-GCM.Seal(nonce=iv_used, plaintext, tagLen=128)
5. Output = iv(12) ‖ ciphertext ‖ tag(16)
```

Note: the random `iv` is what gets stored in the file, but the nonce fed to AES-GCM is `iv_used`, derived by passing `iv` through another HMAC+HKDF.

## 4. Binary Container Format (Little-Endian)

```
Offset  Length  Field
0       4       version      (uint32 LE, = 10000 on encryption)
4       4       reserved      (uint32 LE, = 0)
8       64      salt_seed     (64 bytes, rendered as 128-hex)
72      4       length        (uint32 LE, ciphertext length)
76      N       ciphertext    (iv ‖ ciphertext ‖ tag)
```

## 5. Critical Pitfalls for Byte Compatibility (Must Align)

| # | Pitfall | Description |
|---|---|---|
| 1 | HKDF-Expand is actually full HKDF | The frontend's `hkdf_expand` calls noble's full `hkdf(sha3_512, ikm, salt=empty, info, L)`; Go must use `hkdf.New(sha3, ikm, nil, info)` — a nil salt triggers Extract+Expand |
| 2 | PRK uses the ASCII bytes of the hex string as IKM/Key | IKM/Key always uses `[]byte(hexString)`, never `hex.DecodeString` |
| 3 | argon2 units are KiB | `memorySize` is in KiB; hardening params `t=3, m=32768, p=2, dkLen=64, salt=s1`; the frontend noble's `m/=1024` only takes effect when `NODE_ENV==="test"` — Go does not replicate this |
| 4 | The base64 quirk in `deriveStrongPassword` | The frontend **misinterprets argon2's hex output as base64** (`base64ToBytes(hashHex)`) and re-encodes to hex into `processedPasswords`. This is the actual frontend behavior (likely a bug) — Go must replicate it |
| 5 | `deriveNewSalt`'s salt uses ASCII bytes | In `KeyDerivation.argon2(originalSalt, {salt: originalSalt})`, the salt is a string passed as ASCII bytes — do not hex-decode it |
| 6 | The `[object Object]` coercion in the key-set pipeline | `KeyDerivationForm.vue:697-699` assigns `input_sha3 = CryptoTools.hashText(...)` (a Result **object**) and then builds `combinedPassword = passwordInput + input_sha3`. JS string-coerces the object to `"[object Object]"`, so the SHA3-512 hex is **never** used in `combinedPassword`. Go (`internal/kdf.DeriveKeySet`) must replicate this by using the literal `password + "[object Object]"` — the hash is still computed for parity but its value is discarded |
| 7 | The `array_buffer_to_string` UTF-8 quirk in the key-set pipeline | `KeyDerivationForm.vue:703` passes the 64-byte `salt_password` HKDF output through `AesGcmTools.array_buffer_to_string`, i.e. a WHATWG `TextDecoder` (error mode = replacement). Illegal byte sequences become U+FFFD, so the re-encoded HMAC key (127 bytes) differs from the raw 64 bytes. Go (`internal/kdf.utf8DecodeBytes`) implements the WHATWG UTF-8 decoder state machine to stay byte-compatible; the standard library has no equivalent of the "replacement" error mode |

## 6. Golden Vector Verification Mechanism

To ensure byte-level interoperability, a **three-party verification** approach is adopted:

1. **Golden vector generation**: the frontend project's `libs/common-tools/scripts/gen-vectors.mjs` runs with `NODE_ENV=production` to produce deterministic output, frozen into `internal/testvectors/vectors.json`.
2. **Real source authoritative test**: the frontend's `libs/common-tools/tests/authoritative-*.test.ts` directly invokes the real `AesGcmTools` / `deriveNewSalt` / `validateHintAndKeysUuidMatch` / `validateKeyRecovery`, asserting consistency with `vectors.json`.
3. **Go test**: each `internal/*` package's test loads `vectors.json` for golden vector comparison.

Three-party consistency proves: real source ↔ vectors.json ↔ Go are byte-aligned across the entire chain.

### Regenerating Golden Vectors

```bash
cd /works/gitworks/frontend-cdn-tools/libs/common-tools
NODE_ENV=production node scripts/gen-vectors.mjs > /works/gitworks/go-cipher-cli/internal/testvectors/vectors.json
```

### Running the Frontend Authoritative Tests

```bash
cd /works/gitworks/frontend-cdn-tools/libs/common-tools
NODE_ENV=production npx vitest run \
  tests/authoritative-vector.test.ts \
  tests/authoritative-derivables.test.ts \
  tests/authoritative-web-utils.test.ts \
  --testTimeout=60000
```

## 7. Go Library Selection

Everything uses the standard library + `golang.org/x/crypto` + `golang.org/x/text`; no third-party crypto libraries are introduced:

| Purpose | Dependency |
|---|---|
| Argon2id | `golang.org/x/crypto/argon2` |
| SHA3-512 / SHA3 family | `golang.org/x/crypto/sha3` |
| HKDF(SHA3-512) | `golang.org/x/crypto/hkdf` |
| HMAC(SHA3-512/SHA2) | Standard library `crypto/hmac` |
| SHA-256 / MD5 / SHA1 / SHA2 | Standard library |
| AES-256-GCM | Standard library `crypto/aes` + `crypto/cipher` |
| Secure random numbers | Standard library `crypto/rand` |
| Unicode NFC | `golang.org/x/text/unicode/norm` |
| Base64 / Hex | Standard library `encoding/*` |
| Little-endian binary container | Standard library `encoding/binary` |
| CLI / config / logging / progress | cobra / viper / zap / survey / mpb |

## 8. CLI Commands

| Command | Purpose | Corresponding Frontend Capability |
|---|---|---|
| `encrypt [file] -p <pw> [--salt <hex>]` | AES-256-GCM encrypt a file, output a frontend-compatible container | `encryptWithPassword` + `assembleDownloadData` |
| `decrypt [file] -p <pw>` | Decrypt a container (salt is read from the container) | `decryptWithPassword` + `extractDecryptedData` |
| `keygen -p <pw> [--salt <hex>] [--hash-length N]` | argon2id key derivation (multiple passwords go through fusion) | `KeyDerivation.argon2` + `computeFinalPassword` |
| `hash [text] --algo <name>` | Hash text (MD5/SHA1/SHA2/SHA3) | `CryptoTools.hashText` |
| `hmac [text] --algo <name> --key <k>` | Compute HMAC | `HmacTools.hashText` |
| `fuse --salt <s> -p <pw>...` | Password fusion | `computeFinalPassword` |
| `recover [key] --uuid <u>...` | Key recovery validation | `validateKeyRecovery` |
| `hint-match --encrypted <t> --meta <t>` | Hint/UUID match validation | `validateHintAndKeysUuidMatch` |

## 9. Package Structure

```
internal/
├── safety/        # HKDF / HMAC / argon2 / random / encoding (low-level primitives)
├── kdf/           # KeyDerivation API (argon2 / hkdf / salt / strength / recovery)
├── fusion/        # Password fusion (normalize / merge / fuse / deriveNewSalt)
├── aesgcm/        # AES-256-GCM key derivation + encryption/decryption
├── container/     # Binary container + UUID matching
├── crypto/        # hash / HMAC / Base64 facade
└── testvectors/   # Golden vectors (embedded vectors.json + loader)
cmd/
├── encrypt.go / decrypt.go / keygen.go / utils.go
└── cli_e2e_test.go / utils_e2e_test.go   # Isolated-process end-to-end tests
```

## 10. Test Matrix

| Module | Test Content | Vector Source |
|---|---|---|
| `safety` | HKDF-SHA3-512 / HMAC-SHA3-512 / argon2id / SHA256 / encoding / random / high-strength detection | gen-vectors |
| `kdf` | argon2 hardening chain / validatePasswordStrength / generateSalt / generateStrongPassword / validateKeyRecovery | gen-vectors + frontend kdf.test.ts |
| `fusion` | normalizePassword / safetyMergeStrings / fusePasswords (incl. Chinese) / deriveNewSalt | gen-vectors + frontend password-fusion.test.ts |
| `aesgcm` | generate_aes_gcm_key full pipeline / fixed-IV encryption / round-trip / wrong password failure / invalid input | gen-vectors (authoritative) |
| `container` | assemble/parse round-trip / short data / wrong length / salt extraction / UUID matching | gen-vectors + inline |
| `crypto` | MD5/SHA1/SHA2/SHA3 known vectors / HMAC / Base64 round-trip | frontend crypto.test.ts |
| `cmd` | End-to-end for each subcommand (isolated process) + encrypt/decrypt round-trip + wrong password | inline + golden vectors |

## 11. Known Uncovered Items

- **RSA encryption/decryption** (frontend `jsencrypt`): weakly related to the key management mainline; jsencrypt's padding mode needs separate verification, not yet implemented.
- **Key derivation config file export** (frontend `KeyDerivationForm.downloadKeys`): generates a `.txt` config file containing `uuid`/`salt`/`hint_ids`/`uuids` for key recovery when the password is forgotten. Currently Go only implements the **verification side** (`recover`/`hint-match`), not the **generation side** (`maskKey` masking + config export).
