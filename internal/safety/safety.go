// Package safety implements the crypto-primitive layer:
// HKDF (SHA3-512), HMAC (SHA3-512 / SHA2), argon2id, hashing, encoding helpers and
// secure random. All byte-level behaviour is locked by golden vectors in
// internal/testvectors. Notes on the derivation:
//
//   - HKDF-Expand is implemented as a FULL HKDF with an empty salt.
//   - PRK is consumed as the ASCII bytes of its hex string (not decoded).
//   - argon2 memorySize is in KiB; production sizes only (no test downscale).
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

	"go-cipher-cli/internal/i18n"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// HKDFExpand runs a full HKDF-SHA3-512 with an empty salt, where prk is the
// ASCII bytes of the (hex) string.
//   - ikm   = bytes(prk)
//   - salt  = empty  -> HKDF-Extract salt is HashLen zero bytes
//   - info  = info
//   - L     = length
func HKDFExpand(prk string, info []byte, length int) []byte {
	ikm := []byte(prk)                         // prk is the ASCII bytes of its hex string
	r := hkdf.New(sha3.New512, ikm, nil, info) // nil salt triggers full HKDF (Extract+Expand)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(fmt.Sprintf("safety: hkdf read: %v", err))
	}
	return out
}

// HMACSHA3512 returns the lowercase hex HMAC-SHA3-512 digest, with key/data
// taken as their raw bytes (the caller passes the ASCII hex string for key).
func HMACSHA3512(data, key []byte) string {
	mac := hmac.New(sha3.New512, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// HMACSHA512 returns the lowercase hex HMAC-SHA-512 digest.
func HMACSHA512(data, key []byte) string {
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// HKDFExpandSHA256 implements pure HKDF-Expand (RFC 5869 §2.3) using SHA-256.
//
// This is NOT the full HKDF (Extract+Expand); it directly uses PRK as the HMAC key
// and performs only the Expand step.
//
// For L ≤ 32 (SHA-256 output size), only one HMAC round is needed:
//
//	T(1) = HMAC-SHA-256(PRK, info || 0x01)
//
// prk is raw bytes (the Argon2id master PRK output).
func HKDFExpandSHA256(prk, info []byte, length int) []byte {
	if length <= 0 {
		length = 32
	}
	out := make([]byte, 0, length)
	counter := byte(1)
	prev := []byte{} // T(0) = empty

	for len(out) < length {
		mac := hmac.New(sha256.New, prk)
		mac.Write(prev)            // T(i-1)
		mac.Write(info)            // info
		mac.Write([]byte{counter}) // counter byte
		t := mac.Sum(nil)

		remaining := length - len(out)
		if remaining > len(t) {
			remaining = len(t)
		}
		out = append(out, t[:remaining]...)

		prev = t
		counter++
	}
	return out
}

// Argon2id runs argon2id with production sizes.
// memoryKiB is the memory cost in KiB.
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

// SHA256Hex returns the lowercase hex SHA-256 of s.
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// --- encoding helpers ---

func BytesToHex(b []byte) string { return hex.EncodeToString(b) }
func HexToBytes(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("%s", i18n.T("safety.error.hex_even"))
	}
	return hex.DecodeString(s)
}
func BytesToBase64(b []byte) string          { return base64.StdEncoding.EncodeToString(b) }
func Base64ToBytes(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// GenerateRandomBytes returns n cryptographically secure random bytes from Go's
// CSPRNG (crypto/rand).
func GenerateRandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("safety: rand: %v", err))
	}
	return b
}

// IsPasswordHighStrength reports high strength: length >= 128 and the hex char
// set reaches at least 15 distinct digits/letters.
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
