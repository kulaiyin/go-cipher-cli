package kdf

import (
	"encoding/hex"
	"fmt"
	"time"

	"go-cipher-cli/internal/safety"
)

// Domain key derivation constants — MUST match the frontend's
// DomainKeyDerivation in kdf/index.ts byte-for-byte.

const (
	// DeriveHardcodedSalt is the first-layer fixed salt, same as
	// DERIVE_HARDCODED_SALT in the frontend. It is concatenated with the
	// user-supplied salt suffix to form the full Argon2id salt.
	DeriveHardcodedSalt = "Your_Super_Long_Fixed_Salt_String_Here_2026"

	// DeriveArgon2Memory is 64 MiB (matches DERIVE_ARGON2_MEMORY = 64*1024 KiB).
	DeriveArgon2Memory = 64 * 1024

	// DeriveArgon2Time is 3 iterations (matches DERIVE_ARGON2_TIME).
	DeriveArgon2Time = 3

	// DeriveArgon2Parallelism is 1 (matches DERIVE_ARGON2_PARALLELISM).
	DeriveArgon2Parallelism = 1

	// DeriveArgon2OutputLen is 64 bytes — Argon2id outputs a 512-bit master PRK
	// (matches DERIVE_ARGON2_OUTPUT_LEN).
	DeriveArgon2OutputLen = 64

	// DeriveSubKeyLen is 32 bytes — the final sub-key is 256 bits.
	DeriveSubKeyLen = 32

	// DefaultDomain is the internal fixed domain label (matches DEFAULT_DOMAIN).
	DefaultDomain = "default-v1"
)

// DeriveSubKeyResult mirrors the frontend DeriveSubKeyResult.
type DeriveSubKeyResult struct {
	Success        bool
	SubKeyHex      string // 64-char hex of the 32-byte sub-key
	ProcessingTime int64  // milliseconds
	Error          string
}

// DeriveSubKeyByDomain mirrors DomainKeyDerivation.deriveSubKeyByDomain.
//
// Algorithm (identical to frontend):
//  1. fullSalt = DeriveHardcodedSalt + optionalSaltSuffix
//  2. masterPRK = Argon2id(password, fullSalt, 64MiB/3iter/1par, output=64 bytes)
//  3. subKey = HKDF-Expand(SHA-256, masterPRK, domainInfo, output=32 bytes)
//  4. Return hex(subKey)
func DeriveSubKeyByDomain(userPassword, optionalSaltSuffix, domainInfo string) (string, error) {
	fullSalt := DeriveHardcodedSalt + optionalSaltSuffix

	// Phase 1: Argon2id slow function
	masterPRK, err := safety.Argon2id(
		[]byte(userPassword),
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

// DeriveSubKey is the convenience wrapper that uses DefaultDomain,
// matching DomainKeyDerivation.derive() in the frontend.
func DeriveSubKey(userPassword, optionalSaltSuffix string) DeriveSubKeyResult {
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
