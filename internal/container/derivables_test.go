package container

import (
	"testing"

	"go-cipher-cli/internal/testvectors"
)

// TDD: ValidateHintAndKeysUuidMatch mirrors data-encryption.ts:validateHintAndKeysUuidMatch.
// Regex /KEYUUID: ([a-f0-9*]+)/i; encrypted without uuid -> true; meta without uuid -> false;
// else compare captures (case-sensitive).

func TestValidateHintAndKeysUuidMatch_GoldenVectors(t *testing.T) {
	v := testvectors.MustLoad()
	for _, c := range v.ValidateHintAndKeysUuidMatch {
		got := ValidateHintAndKeysUuidMatch(c.Encrypted, c.Meta)
		if got != c.Out {
			t.Errorf("ValidateHintAndKeysUuidMatch(%q, %q) = %v, want %v", c.Encrypted, c.Meta, got, c.Out)
		}
	}
}
