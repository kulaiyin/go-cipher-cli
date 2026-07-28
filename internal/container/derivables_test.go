package container

import (
	"testing"

	"go-cipher-cli/internal/testvectors"
)

// Tests for ValidateHintAndKeysUuidMatch: encrypted without uuid -> true; meta without
// uuid -> false; else compare captures (case-sensitive).

func TestValidateHintAndKeysUuidMatch_GoldenVectors(t *testing.T) {
	v := testvectors.MustLoad()
	for _, c := range v.ValidateHintAndKeysUuidMatch {
		got := ValidateHintAndKeysUuidMatch(c.Encrypted, c.Meta)
		if got != c.Out {
			t.Errorf("ValidateHintAndKeysUuidMatch(%q, %q) = %v, want %v", c.Encrypted, c.Meta, got, c.Out)
		}
	}
}
