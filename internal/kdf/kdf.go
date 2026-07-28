// Package kdf mirrors kdf/index.ts: the KeyDerivation API surface that the CLI
// and higher layers consume. It wraps internal/safety primitives.
//
// Note on the salt encoding: the frontend's KeyDerivation.argon2 returns the salt
// Base64-encoded and the derived key as a hex string (this is the noble-fallback
// path, which is what we reproduce — no browser/WASM exists in the CLI).
package kdf

import (
	"encoding/base64"
	"encoding/hex"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/safety"
)

// Argon2Config mirrors Argon2Config in types/safety-type.ts.
// MemorySize is in KiB.
type Argon2Config struct {
	Salt        []byte
	Iterations  int
	MemorySize  int // KiB
	Parallelism int
	HashLength  int // bytes
}

// KDFResult mirrors CryptoResult/KDFResult: Success/Data/Error plus echo'd params.
type KDFResult struct {
	Success        bool
	Data           string // hex string of the derived key
	Salt           string // base64 of the salt
	Iterations     int
	HashLength     int
	ProcessingTime int64 // milliseconds
	Error          string
}

const (
	defaultMemoryKiB  = 65536 // 64 MB (matches kdf/index.ts default)
	defaultParallel   = 1
	defaultIterations = 3
)

// Argon2 mirrors KeyDerivation.argon2 (noble fallback path).
func Argon2(password string, cfg Argon2Config) KDFResult {
	start := nowMs()
	time := orDefault(cfg.Iterations, defaultIterations)
	mem := orDefault(cfg.MemorySize, defaultMemoryKiB)
	par := orDefault(cfg.Parallelism, defaultParallel)
	keyLen := cfg.HashLength
	if keyLen <= 0 {
		keyLen = 64
	}
	out, err := safety.Argon2id([]byte(password), cfg.Salt, time, mem, par, keyLen)
	if err != nil {
		return KDFResult{Error: errMsg(err, i18n.T("kdf.error.argon2_failed")), ProcessingTime: elapsedMs(start)}
	}
	return KDFResult{
		Success:        true,
		Data:           hex.EncodeToString(out),
		Salt:           base64.StdEncoding.EncodeToString(cfg.Salt),
		Iterations:     time,
		HashLength:     keyLen,
		ProcessingTime: elapsedMs(start),
	}
}

// HKDF mirrors KeyDerivation.hkdf: full HKDF-SHA3-512 returning the raw bytes.
// salt is consumed as its bytes; info is optional.
func HKDF(password []byte, salt, info []byte, hashLength int) []byte {
	if salt == nil {
		salt = []byte{}
	}
	if info == nil {
		info = []byte{}
	}
	// full HKDF with the given (non-empty) salt — mirrors SafetyUtility.hkdf.
	return hkdfWithSalt(password, salt, info, hashLength)
}

// GenerateSalt mirrors KeyDerivation.generateSalt: random bytes -> hex string.
func GenerateSalt(lengthBytes int) string {
	if lengthBytes <= 0 {
		lengthBytes = 16
	}
	return safety.BytesToHex(safety.GenerateRandomBytes(lengthBytes))
}

// GenerateStrongPassword mirrors KeyDerivation.generateStrongPassword: a CSPRNG
// index into the charset modulo length. Note: this has modulo bias (intentionally
// matches the reference; do not reuse for new designs).
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

// ValidatePasswordStrength mirrors KeyDerivation.validatePasswordStrength.
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

// ValidateKeyRecovery mirrors key-recovery.ts:validateKeyRecovery.
// It builds processedKey = key[0:8] + key[len-8:] (JS substring semantics: indices clamp to
// [0,len]) and returns whether processedKey is present in uuids.
func ValidateKeyRecovery(generatedKey string, uuids []string) bool {
	keyRunes := []rune(generatedKey)
	n := len(keyRunes)
	// prefix = substring(0, min(8, n)); suffix = substring(max(0, n-8))
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
