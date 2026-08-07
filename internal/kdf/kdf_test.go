package kdf

import (
	"encoding/hex"
	"strings"
	"testing"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/testvectors"
)

func TestMain(m *testing.M) {
	i18n.MustInit("en")
	m.Run()
}

// Tests for the kdf package.

func TestValidatePasswordStrength_GoldenVectors(t *testing.T) {
	v := testvectors.MustLoad()
	for _, c := range v.ValidatePasswordStrength {
		score, feedback := ValidatePasswordStrength(c.In)
		if score != c.Score {
			t.Errorf("ValidatePasswordStrength(%q) score = %d, want %d", c.In, score, c.Score)
		}
		if !sameStringSet(feedback, c.Feedback) {
			t.Errorf("ValidatePasswordStrength(%q) feedback = %v, want %v", c.In, feedback, c.Feedback)
		}
	}
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	return true
}

func TestGenerateStrongPassword(t *testing.T) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>/?"
	pw := GenerateStrongPassword(20)
	if len(pw) != 20 {
		t.Errorf("length = %d, want 20", len(pw))
	}
	for _, r := range pw {
		if !strings.ContainsRune(charset, r) {
			t.Errorf("unexpected rune %q in generated password", r)
		}
	}
	// two draws should differ
	if GenerateStrongPassword(20) == pw {
		t.Error("two draws identical (very unlikely)")
	}
}

func TestGenerateSalt(t *testing.T) {
	s := GenerateSalt(16) // 16 bytes -> 32 hex chars
	if len(s) != 32 {
		t.Errorf("len = %d, want 32", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		t.Errorf("not valid hex: %v", err)
	}
}

func TestArgon2_ReturnsHexAndBase64Salt(t *testing.T) {
	// Verifies the argon2 path: data is hex string, salt is base64.
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	pw := "test-password"
	saltHex := "00112233445566778899aabbccddeeff"
	salt, _ := hex.DecodeString(saltHex)
	res := Argon2([]byte(pw), Argon2Config{
		Salt:        salt,
		Iterations:  3,
		MemorySize:  8 * 1024,
		Parallelism: 2,
		HashLength:  32,
	})
	if !res.Success || res.Data == "" {
		t.Fatalf("argon2 failed: %+v", res)
	}
	// data must be hex
	if _, err := hex.DecodeString(res.Data); err != nil {
		t.Errorf("data not hex: %v", err)
	}
	if res.Iterations != 3 || res.HashLength != 32 {
		t.Errorf("got iters=%d hashLen=%d", res.Iterations, res.HashLength)
	}
}

func TestArgon2_StrongPasswordDerivation_MatchesGolden(t *testing.T) {
	// Validates the raw argon2id primitive (the value returned as .data) using the
	// strengthening config t=3,m=32*1024,p=2, dkLen=64, salt=s1. NOTE:
	// deriveStrongPassword applies an additional base64-decode step on top of this
	// hex before it reaches processedPasswords — that step is exercised in
	// internal/aesgcm. Here we check only the raw argon2 hex.
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	v := testvectors.MustLoad()
	g := v.GenerateAesGcmKey
	s1, err := hex.DecodeString(g.S1)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Passwords) != len(g.Argon2RawHex) {
		t.Fatal("vector mismatch")
	}
	for i, pw := range g.Passwords {
		wantHex := g.Argon2RawHex[i]
		res := Argon2([]byte(pw), Argon2Config{
			Salt: s1, Iterations: 3, MemorySize: 32 * 1024, Parallelism: 2, HashLength: 64,
		})
		if !res.Success {
			t.Fatalf("argon2 failed for pw %d: %+v", i, res)
		}
		if res.Data != wantHex {
			t.Errorf("strong-pw[%d] = %s, want %s", i, res.Data, wantHex)
		}
	}
}
