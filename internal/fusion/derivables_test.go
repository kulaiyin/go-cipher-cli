package fusion

import (
	"testing"

	"go-cipher-cli/internal/testvectors"
)

// Tests for DeriveNewSalt.
// It uses argon2id with salt-as-string (ASCII bytes) for BOTH password and salt,
// t=3, m=65536, p=4, dkLen=8, and returns the hex digest. On error it returns the
// original salt unchanged.

func TestDeriveNewSalt_MatchesGolden(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	v := testvectors.MustLoad()
	got, err := DeriveNewSalt(v.Argon2id64mb.SaltHex)
	if err != nil {
		t.Fatalf("DeriveNewSalt error: %v", err)
	}
	if got != v.Argon2id64mb.OutHex {
		t.Errorf("DeriveNewSalt(%q) = %s, want %s", v.Argon2id64mb.SaltHex, got, v.Argon2id64mb.OutHex)
	}
}

func TestDeriveNewSalt_Deterministic(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	a, _ := DeriveNewSalt("deadbeef")
	b, _ := DeriveNewSalt("deadbeef")
	if a != b {
		t.Errorf("DeriveNewSalt not deterministic: %s != %s", a, b)
	}
}
