// Package safety mirrors the crypto-primitive layer of utils/safety-utility.ts:
// HKDF (SHA3-512), HMAC (SHA3-512 / SHA2), argon2id, hashing, encoding helpers and
// secure random. All byte-level behaviour is locked by golden vectors in
// internal/testvectors and the three documented compatibility traps.
//
//   - Trap #1: HKDF-Expand is implemented as a FULL HKDF with an empty salt.
//   - Trap #2: PRK is consumed as the ASCII bytes of its hex string (not decoded).
//   - Trap #3: argon2 memorySize is in KiB; production sizes only (no test downscale).
package safety

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// HKDFExpand mirrors SafetyUtility.hkdf_expand: a full HKDF-SHA3-512 with an empty
// salt, where prk is the ASCII bytes of the (hex) string.
//   - ikm   = bytes(prk)
//   - salt  = empty  -> HKDF-Extract salt is HashLen zero bytes
//   - info  = info
//   - L     = length
func HKDFExpand(prk string, info []byte, length int) []byte {
	ikm := []byte(prk)                         // trap #2: ASCII bytes of the hex string
	r := hkdf.New(sha3.New512, ikm, nil, info) // trap #1: nil salt == full HKDF
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(fmt.Sprintf("safety: hkdf read: %v", err))
	}
	return out
}

// HMACSHA3512 mirrors SafetyUtility.hmac_sha3_512: returns the lowercase hex digest,
// with key/data taken as their raw bytes (the caller passes the ASCII hex string for key).
func HMACSHA3512(data, key []byte) string {
	mac := hmac.New(sha3.New512, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// HMACSHA512 mirrors SafetyUtility.hmac_sha512 (used elsewhere by the frontend).
func HMACSHA512(data, key []byte) string {
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// Argon2id mirrors SafetyUtility.noble_argon2id (production sizes).
// memoryKiB is the memory cost in KiB (matches noble's `m` and argon2's memory unit).
func Argon2id(password, salt []byte, time, memoryKiB, parallelism, keyLen int) ([]byte, error) {
	if time <= 0 {
		return nil, fmt.Errorf("safety: argon2 time must be > 0")
	}
	if memoryKiB <= 0 {
		return nil, fmt.Errorf("safety: argon2 memory must be > 0")
	}
	if parallelism <= 0 {
		return nil, fmt.Errorf("safety: argon2 parallelism must be > 0")
	}
	if keyLen <= 0 {
		return nil, fmt.Errorf("safety: argon2 keyLen must be > 0")
	}
	return argon2.IDKey(
		password, salt,
		uint32(time), uint32(memoryKiB),
		uint8(parallelism), uint32(keyLen),
	), nil
}

// SHA256Hex returns the lowercase hex SHA-256 of s (mirrors CryptoJS.SHA256(s).toString()).
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// --- encoding helpers (mirror SafetyUtility) ---

func BytesToHex(b []byte) string { return hex.EncodeToString(b) }
func HexToBytes(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("16 进制字符串长度必须为偶数")
	}
	return hex.DecodeString(s)
}
func BytesToBase64(b []byte) string          { return base64.StdEncoding.EncodeToString(b) }
func Base64ToBytes(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// GenerateRandomBytes mirrors crypto.getRandomValues.
func GenerateRandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("safety: rand: %v", err))
	}
	return b
}

// IsPasswordHighStrength mirrors SafetyUtility.isPasswordHighStrength:
// length >= 128 and the hex char set reaches at least 15 distinct digits/letters.
func IsPasswordHighStrength(value string) bool {
	if len(value) < 128 {
		return false
	}
	seen := map[rune]struct{}{}
	for _, r := range strings.ToLower(value) {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			seen[r] = struct{}{}
		}
		if len(seen) >= 15 {
			return true
		}
	}
	return false
}
