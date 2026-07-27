package kdf

import (
	"testing"

	"go-cipher-cli/internal/testvectors"
)

// TDD: ValidateKeyRecovery mirrors key-recovery.ts:validateKeyRecovery.
// processedKey = key[0:8] + key[len-8:]; returns whether processedKey is in uuids.

func TestValidateKeyRecovery_GoldenVectors(t *testing.T) {
	v := testvectors.MustLoad()
	for _, c := range v.ValidateKeyRecovery {
		got := ValidateKeyRecovery(c.Key, c.Uuids)
		if got != c.Out {
			t.Errorf("ValidateKeyRecovery(%q, %v) = %v, want %v", c.Key, c.Uuids, got, c.Out)
		}
	}
}
