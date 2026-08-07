package kdf

import (
	"encoding/hex"
	"testing"

	"go-cipher-cli/internal/testvectors"
)

// Tests for ValidateKeyRecovery: processedKey = key[0:8] + key[len-8:];
// returns whether processedKey is in uuids.

func TestValidateKeyRecovery_GoldenVectors(t *testing.T) {
	v := testvectors.MustLoad()
	for _, c := range v.ValidateKeyRecovery {
		got := ValidateKeyRecovery(c.Key, c.Uuids)
		if got != c.Out {
			t.Errorf("ValidateKeyRecovery(%q, %v) = %v, want %v", c.Key, c.Uuids, got, c.Out)
		}
	}
}

func TestValidateKeyRecoveryBytes_ParityWithString(t *testing.T) {
	// golden vectors' keys are arbitrary strings (not hex), while the bytes
	// variant is only defined for raw key bytes. Use a fixed 128-hex key and
	// compare both variants across uuids lists.
	keyHex := "0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef" +
		"0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef"
	raw, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	uuidSets := [][]string{
		{keyHex[:8] + keyHex[len(keyHex)-8:]},
		{keyHex[:8] + "ffffffff"},
		{"nope1234567890ab"},
		{},
		{keyHex[:8] + keyHex[len(keyHex)-8:], "zzz"},
	}
	for _, uuids := range uuidSets {
		want := ValidateKeyRecovery(keyHex, uuids)
		got := ValidateKeyRecoveryBytes(raw, uuids)
		if got != want {
			t.Errorf("ValidateKeyRecoveryBytes(%q, %v) = %v, want %v", keyHex, uuids, got, want)
		}
	}
}
