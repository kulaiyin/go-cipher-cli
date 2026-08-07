package cmd

import (
	"encoding/hex"
	"strings"
	"testing"

	"go-cipher-cli/internal/kdf"
)

// Tests for the bytes-typed recovery config rendering
// (key_derive_pipe_config.go). The bytes variant must produce exactly the same
// text as the legacy string variant, given the same underlying key material.

func TestFormatFrontendRecoveryConfigBytes_Parity(t *testing.T) {
	rawS1, _ := hex.DecodeString(kdWantS1)
	rawS2, _ := hex.DecodeString(strings.Repeat("ab", 64))
	rawS3, _ := hex.DecodeString(strings.Repeat("cd", 64))
	rawUUID, _ := hex.DecodeString(kdWantUUID)

	strRes := kdf.KeySetResult{
		Success:  true,
		Keys:     []string{kdWantS1, hex.EncodeToString(rawS2), hex.EncodeToString(rawS3)},
		UUID:     kdWantUUID,
		SaltSeed: kdSalt,
		Strength: kdf.StrengthBasic,
	}
	bytesRes := kdf.KeySetBytesResult{
		Success:  true,
		RawKeys:  [][]byte{rawS1, rawS2, rawS3},
		RawUUID:  rawUUID,
		SaltSeed: kdSalt,
		Strength: kdf.StrengthBasic,
	}

	hintIDs := []string{"q1", "q2", "q3"}
	want := formatFrontendRecoveryConfig(buildRecoveryConfig(strRes, "myhint", hintIDs), strRes.Keys)
	got := formatFrontendRecoveryConfigBytes(buildPipeRecoveryConfig(bytesRes, "myhint", hintIDs), bytesRes.RawKeys, bytesRes.RawUUID)
	defer clear(got)
	if string(got) != want {
		t.Fatalf("config parity mismatch:\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestFormatFrontendRecoveryConfigBytes_NoFullKeys(t *testing.T) {
	// The rendered config must never contain a full 128-hex key or the full
	// 32-hex UUID (only their masked forms).
	rawS1, _ := hex.DecodeString(kdWantS1)
	rawUUID, _ := hex.DecodeString(kdWantUUID)
	bytesRes := kdf.KeySetBytesResult{
		Success:  true,
		RawKeys:  [][]byte{rawS1},
		RawUUID:  rawUUID,
		SaltSeed: kdSalt,
		Strength: kdf.StrengthBasic,
	}
	out := formatFrontendRecoveryConfigBytes(buildPipeRecoveryConfig(bytesRes, "myhint", nil), bytesRes.RawKeys, bytesRes.RawUUID)
	defer clear(out)
	if strings.Contains(string(out), kdWantS1) {
		t.Errorf("config leaks a full S1 key")
	}
	if strings.Contains(string(out), kdWantUUID) {
		t.Errorf("config leaks the full UUID")
	}
}

func TestBuildPipeRecoveryConfig_NoFullUUID(t *testing.T) {
	// buildPipeRecoveryConfig must not materialize the full UUID hex string in
	// the recoveryConfig struct (the masked form is rendered from raw bytes).
	rawS1, _ := hex.DecodeString(kdWantS1)
	rawUUID, _ := hex.DecodeString(kdWantUUID)
	r := kdf.KeySetBytesResult{
		RawKeys:  [][]byte{rawS1},
		RawUUID:  rawUUID,
		SaltSeed: kdSalt,
		Strength: kdf.StrengthBasic,
	}
	if cfg := buildPipeRecoveryConfig(r, "myhint", nil); cfg.UUID != "" {
		t.Errorf("buildPipeRecoveryConfig materialized the full UUID: %q", cfg.UUID)
	}
}
