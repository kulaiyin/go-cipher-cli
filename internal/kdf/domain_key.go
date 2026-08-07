package kdf

import (
	"encoding/hex"
	"fmt"
	"time"

	"go-cipher-cli/internal/safety"
)

// Domain key derivation constants.

const (
	// DeriveHardcodedSalt is the first-layer fixed salt, concatenated with the
	// user-supplied salt suffix to form the full Argon2id salt.
	DeriveHardcodedSalt = "Your_Super_Long_Fixed_Salt_String_Here_2026"

	// DeriveArgon2Memory is 64 MiB.
	DeriveArgon2Memory = 64 * 1024

	// DeriveArgon2Time is 3 iterations.
	DeriveArgon2Time = 3

	// DeriveArgon2Parallelism is 1.
	DeriveArgon2Parallelism = 1

	// DeriveArgon2OutputLen is 64 bytes — Argon2id outputs a 512-bit master PRK.
	DeriveArgon2OutputLen = 64

	// DeriveSubKeyLen is 32 bytes — the final sub-key is 256 bits.
	DeriveSubKeyLen = 32

	// DefaultDomain is the internal fixed domain label.
	DefaultDomain = "default-v1"
)

// DeriveSubKeyResult holds the derived sub-key and metadata.
type DeriveSubKeyResult struct {
	Success        bool
	SubKeyHex      string // 64-char hex of the 32-byte sub-key
	ProcessingTime int64  // milliseconds
	Error          string
}

// DeriveSubKeyByDomain derives a domain-separated sub-key.
//
// Algorithm:
//  1. fullSalt = DeriveHardcodedSalt + optionalSaltSuffix
//  2. masterPRK = Argon2id(password, fullSalt, 64MiB/3iter/1par, output=64 bytes)
//  3. subKey = HKDF-Expand(SHA-256, masterPRK, domainInfo, output=32 bytes)
//  4. Return hex(subKey)
func DeriveSubKeyByDomain(userPassword []byte, optionalSaltSuffix, domainInfo string) (string, error) {
	fullSalt := DeriveHardcodedSalt + optionalSaltSuffix

	// Phase 1: Argon2id slow function
	masterPRK, err := safety.Argon2id(
		userPassword,
		[]byte(fullSalt),
		DeriveArgon2Time,
		DeriveArgon2Memory,
		DeriveArgon2Parallelism,
		DeriveArgon2OutputLen,
	)
	if err != nil {
		return "", fmt.Errorf("argon2id: %w", err)
	}

	// Phase 2: HKDF-Expand(SHA-256) domain separation (pure Expand, no Extract)
	subKey := safety.HKDFExpandSHA256(masterPRK, []byte(domainInfo), DeriveSubKeyLen)

	return hex.EncodeToString(subKey), nil
}

// DeriveSubKey is the convenience wrapper using DefaultDomain.
func DeriveSubKey(userPassword []byte, optionalSaltSuffix string) DeriveSubKeyResult {
	start := time.Now()
	subKeyHex, err := DeriveSubKeyByDomain(userPassword, optionalSaltSuffix, DefaultDomain)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return DeriveSubKeyResult{
			Success:        false,
			Error:          err.Error(),
			ProcessingTime: elapsed,
		}
	}
	return DeriveSubKeyResult{
		Success:        true,
		SubKeyHex:      subKeyHex,
		ProcessingTime: elapsed,
	}
}
