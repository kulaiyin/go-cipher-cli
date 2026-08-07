// Package kdf exposes the key derivation API surface that the CLI and higher
// layers consume. It wraps internal/safety primitives.
//
// Note on the salt encoding: argon2 returns the salt Base64-encoded and the
// derived key as a hex string.
package kdf

import (
	"encoding/hex"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/safety"
)

// Argon2Config configures an argon2 derivation.
// MemorySize is in KiB.
type Argon2Config struct {
	Salt        []byte
	Iterations  int
	MemorySize  int // KiB
	Parallelism int
	HashLength  int // bytes
}

// KDFResult holds the derivation outcome: Success/Data/Error plus echoed params.
type KDFResult struct {
	Success        bool
	Data           []byte // derived key bytes
	Salt           []byte // salt bytes
	Iterations     int
	HashLength     int
	ProcessingTime int64 // milliseconds
	Error          string
}

const (
	defaultMemoryKiB  = 65536 // 64 MiB
	defaultParallel   = 1
	defaultIterations = 3
)

// Argon2 derives a key with argon2id and returns the result struct.
// password is UTF-8 bytes; callers wipe it after the derivation.
func Argon2(password []byte, cfg Argon2Config) KDFResult {
	start := nowMs()
	time := orDefault(cfg.Iterations, defaultIterations)
	mem := orDefault(cfg.MemorySize, defaultMemoryKiB)
	par := orDefault(cfg.Parallelism, defaultParallel)
	keyLen := cfg.HashLength
	if keyLen <= 0 {
		keyLen = 64
	}
	out, err := safety.Argon2id(password, cfg.Salt, time, mem, par, keyLen)
	if err != nil {
		return KDFResult{Error: errMsg(err, i18n.T("kdf.error.argon2_failed")), ProcessingTime: elapsedMs(start)}
	}
	return KDFResult{
		Success:        true,
		Data:           out,
		Salt:           cfg.Salt,
		Iterations:     time,
		HashLength:     keyLen,
		ProcessingTime: elapsedMs(start),
	}
}

// HKDF runs a full HKDF-SHA3-512 returning the raw bytes.
// salt is consumed as its bytes; info is optional.
func HKDF(password []byte, salt, info []byte, hashLength int) []byte {
	if salt == nil {
		salt = []byte{}
	}
	if info == nil {
		info = []byte{}
	}
	// full HKDF with the given (non-empty) salt.
	return hkdfWithSalt(password, salt, info, hashLength)
}

// GenerateSalt returns random bytes as a hex string.
func GenerateSalt(lengthBytes int) string {
	if lengthBytes <= 0 {
		lengthBytes = 16
	}
	return safety.BytesToHex(safety.GenerateRandomBytes(lengthBytes))
}

// GenerateStrongPassword generates a random password by indexing into the
// charset modulo length. Note: this has modulo bias; do not reuse for new designs.
func GenerateStrongPassword(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>/?"
	if length <= 0 {
		length = 16
	}
	arr := safety.GenerateRandomBytes(length)
	out := make([]byte, length)
	for i, b := range arr {
		out[i] = charset[int(b)%len(charset)]
	}
	return string(out)
}

// PasswordFeedback holds the score and improvement hints for a password.
type PasswordFeedback struct {
	Score    int
	Feedback []string
}

// ValidatePasswordStrength scores a password and returns improvement feedback.
func ValidatePasswordStrength(password string) (score int, feedback []string) {
	// length tiers
	switch {
	case len(password) < 8:
		feedback = append(feedback, i18n.T("kdf.feedback.too_short"))
	case len(password) < 12:
		feedback = append(feedback, i18n.T("kdf.feedback.recommend_longer"))
		score += 1
	case len(password) >= 16:
		score += 2
	default:
		score += 1
	}

	hasLower := false
	hasUpper := false
	hasNumber := false
	hasSpecial := false
	for _, r := range password {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasNumber = true
		case isStrengthSpecial(r):
			hasSpecial = true
		}
	}
	if hasLower {
		score += 1
	} else {
		feedback = append(feedback, i18n.T("kdf.feedback.add_lowercase"))
	}
	if hasUpper {
		score += 1
	} else {
		feedback = append(feedback, i18n.T("kdf.feedback.add_uppercase"))
	}
	if hasNumber {
		score += 1
	} else {
		feedback = append(feedback, i18n.T("kdf.feedback.add_digit"))
	}
	if hasSpecial {
		score += 1
	} else {
		feedback = append(feedback, i18n.T("kdf.feedback.add_special"))
	}

	common := map[string]bool{
		"password": true, "123456": true, "admin": true,
		"qwerty": true, "abc123": true, "password123": true,
	}
	if common[normalizeLowerASCII(password)] {
		feedback = append(feedback, i18n.T("kdf.feedback.avoid_common"))
		if score-2 < 0 {
			score = 0
		} else {
			score -= 2
		}
	}
	return score, feedback
}

func isStrengthSpecial(r rune) bool {
	switch r {
	case '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+',
		'-', '=', '[', ']', '{', '}', ';', '\'', ':', '"', '\\', '|',
		',', '.', '<', '>', '/', '?':
		return true
	}
	return false
}

func normalizeLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// ValidateKeyRecovery builds processedKey = key[0:8] + key[len-8:] (indices clamp to
// [0,len]) and returns whether processedKey is present in uuids.
func ValidateKeyRecovery(generatedKey string, uuids []string) bool {
	keyRunes := []rune(generatedKey)
	n := len(keyRunes)
	// prefix = key[0:min(8,n)]; suffix = key[max(0,n-8):]
	prefixEnd := 8
	if prefixEnd > n {
		prefixEnd = n
	}
	suffixStart := n - 8
	if suffixStart < 0 {
		suffixStart = 0
	}
	processed := string(keyRunes[:prefixEnd]) + string(keyRunes[suffixStart:])
	for _, u := range uuids {
		if u == processed {
			return true
		}
	}
	return false
}

// ValidateKeyRecoveryBytes is the wipeable counterpart of ValidateKeyRecovery:
// it computes the same first-8/last-8 hex fingerprint from raw key bytes so a
// security-sensitive caller never materializes the key's hex string.
// A raw 64-byte key hex-encodes to 128 chars; the first 8 hex chars come from
// the first 4 raw bytes and the last 8 from the last 4 raw bytes.
func ValidateKeyRecoveryBytes(generatedKey []byte, uuids []string) bool {
	if len(generatedKey) == 0 {
		return false
	}
	prefixBytes := 4
	if prefixBytes > len(generatedKey) {
		prefixBytes = len(generatedKey)
	}
	suffixStart := len(generatedKey) - 4
	if suffixStart < 0 {
		suffixStart = 0
	}
	processed := make([]byte, 0, 16)
	processed = appendKeyHex(processed, generatedKey[:prefixBytes])
	processed = appendKeyHex(processed, generatedKey[suffixStart:])
	defer clear(processed)
	for _, u := range uuids {
		if bytesEqualString(processed, u) {
			return true
		}
	}
	return false
}

// appendKeyHex appends the lowercase hex encoding of src to dst.
func appendKeyHex(dst, src []byte) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, hex.EncodedLen(len(src)))...)
	hex.Encode(dst[start:], src)
	return dst
}

// bytesEqualString reports whether b equals the UTF-8 bytes of s without
// allocating either a temporary string or byte slice.
func bytesEqualString(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := range b {
		if b[i] != s[i] {
			return false
		}
	}
	return true
}
