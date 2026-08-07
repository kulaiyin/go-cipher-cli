package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

// End-to-end tests for the argon2id CLI command.
//
// The derivation is deterministic (same password + salt + params → same key),
// so tests assert against a golden vector computed with the reference
// x/crypto/argon2 implementation (2 rounds / 8 MiB / 1 parallelism / 32 bytes).

const (
	a2TestPassword = "TestPass!2026"
	a2TestSaltHex  = "00112233445566778899aabbccddeeff"
	// Golden vector from the reference argon2.IDKey implementation.
	a2WantKeyHex = "2afa7f5bf041cb89dd3386b80ec27f51036fa97e86822f2e08a3f4be8ff58a70"
)

func TestArgon2idCmd_Text_MaskedGoldenVector(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	// Fixed password + salt via --secrets-stdin (stdin line 2 supplies the
	// salt; --salt is mutually exclusive with --secrets-stdin).
	stdin := a2TestPassword + "\n" + a2TestSaltHex + "\n"
	out, code := runCLIWithInput(t, stdin, nil, "argon2id", "--secrets-stdin",
		"--iterations", "2", "--memory", "8", "--key-length", "32")
	if code != 0 {
		t.Fatalf("argon2id failed: %s", out)
	}

	// Text mode masks the derived key (first 8 / last 8 chars + asterisks) so
	// the plaintext never reaches a terminal; the full value is covered by the
	// --json golden test below.
	if !strings.Contains(out, "Key (hex):    "+displayMaskKey(a2WantKeyHex)) {
		t.Errorf("expected masked key hex, output:\n%s", out)
	}
	if !strings.Contains(out, "Key (base64): "+displayMaskKey("Kvp/W/BBy4ndM4a4DsJ/UQNvqX6Ggi8uCKP0vo/1inA=")) {
		t.Errorf("expected masked key base64, output:\n%s", out)
	}
	if !strings.Contains(out, "use --json") {
		t.Errorf("expected mask hint pointing to --json, output:\n%s", out)
	}
	if !strings.Contains(out, "Salt (hex):    "+a2TestSaltHex) {
		t.Errorf("expected salt hex echo, output:\n%s", out)
	}
	if !strings.Contains(out, "Salt (base64): ABEiM0RVZneImaq7zN3u/w==") {
		t.Errorf("expected salt base64 echo, output:\n%s", out)
	}
	if !strings.Contains(out, "Algorithm: Argon2id (8 MB / 2 rounds / 1 parallelism)") {
		t.Errorf("expected algorithm line, output:\n%s", out)
	}
	if !strings.Contains(out, "Key length:   256 bits") {
		t.Errorf("expected 256-bit key length, output:\n%s", out)
	}
	if !strings.Contains(out, "Processing time:") {
		t.Errorf("expected processing time line, output:\n%s", out)
	}
}

func TestArgon2idCmd_JSON_GoldenVector(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	stdin := a2TestPassword + "\n" + a2TestSaltHex + "\n"
	out, code := runCLIWithInput(t, stdin, nil, "argon2id", "--secrets-stdin", "--json",
		"--iterations", "2", "--memory", "8", "--key-length", "32")
	if code != 0 {
		t.Fatalf("argon2id --json failed: %s", out)
	}

	var got struct {
		Success        bool   `json:"success"`
		Algorithm      string `json:"algorithm"`
		Salt           string `json:"salt"`
		SaltHex        string `json:"salt_hex"`
		KeyHex         string `json:"key_hex"`
		KeyBase64      string `json:"key_base64"`
		Iterations     int    `json:"iterations"`
		MemoryMiB      int    `json:"memory_mib"`
		Parallelism    int    `json:"parallelism"`
		KeyLength      int    `json:"key_length"`
		ProcessingTime int64  `json:"processing_time_ms"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}

	if !got.Success {
		t.Errorf("expected success=true, output:\n%s", out)
	}
	if got.Algorithm != "argon2id" {
		t.Errorf("algorithm: got %q want argon2id", got.Algorithm)
	}
	if got.Salt != "ABEiM0RVZneImaq7zN3u/w==" {
		t.Errorf("salt: got %q", got.Salt)
	}
	if got.SaltHex != a2TestSaltHex {
		t.Errorf("salt_hex: got %q want %q", got.SaltHex, a2TestSaltHex)
	}
	if got.KeyHex != a2WantKeyHex {
		t.Errorf("key_hex: got %q want %q", got.KeyHex, a2WantKeyHex)
	}
	if got.KeyBase64 != "Kvp/W/BBy4ndM4a4DsJ/UQNvqX6Ggi8uCKP0vo/1inA=" {
		t.Errorf("key_base64: got %q", got.KeyBase64)
	}
	if got.Iterations != 2 || got.MemoryMiB != 8 || got.Parallelism != 1 || got.KeyLength != 32 {
		t.Errorf("params mismatch: %+v", got)
	}
	if got.ProcessingTime <= 0 {
		t.Errorf("expected positive processing_time_ms, got %d", got.ProcessingTime)
	}
}

func TestArgon2idCmd_RandomSalt_DifferentKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	// Same password, only password on stdin (no salt line) → each run draws a
	// fresh random salt → different key.
	stdin := a2TestPassword + "\n"
	out1, code1 := runCLIWithInput(t, stdin, nil, "argon2id", "--secrets-stdin", "--json", "--memory", "8", "--key-length", "32")
	out2, code2 := runCLIWithInput(t, stdin, nil, "argon2id", "--secrets-stdin", "--json", "--memory", "8", "--key-length", "32")
	if code1 != 0 || code2 != 0 {
		t.Fatalf("argon2id failed: out1=%d out2=%d", code1, code2)
	}
	key1 := jsonKeyHex(t, out1)
	key2 := jsonKeyHex(t, out2)
	if key1 == key2 {
		t.Fatal("two runs without a salt produced the same key — random salt broken")
	}
}

func TestArgon2idCmd_Deterministic(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	// Same inputs → identical key across runs.
	stdin := a2TestPassword + "\n" + a2TestSaltHex + "\n"
	out1, _ := runCLIWithInput(t, stdin, nil, "argon2id", "--secrets-stdin", "--json", "--memory", "8", "--key-length", "32")
	out2, _ := runCLIWithInput(t, stdin, nil, "argon2id", "--secrets-stdin", "--json", "--memory", "8", "--key-length", "32")
	if jsonKeyHex(t, out1) != jsonKeyHex(t, out2) {
		t.Fatal("argon2id not deterministic with fixed salt")
	}
}

func TestArgon2idCmd_StdinPipedWithoutFlag(t *testing.T) {
	// stdin is piped (runCLIWithInput wires a non-nil reader → exec treats
	// stdin as a pipe, not a TTY) but no --secrets-stdin → must refuse rather
	// than silently derive from an empty password.
	out, code := runCLIWithInput(t, a2TestPassword+"\n", nil, "argon2id")
	if code == 0 {
		t.Errorf("expected argon2id to fail with piped stdin and no --secrets-stdin, output:\n%s", out)
	}
}

func TestArgon2idCmd_InvalidSaltFails(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	// Salt via --salt flag (only allowed when stdin is NOT --secrets-stdin);
	// runCLI leaves stdin nil, which exec treats as a non-TTY pipe, so the
	// command refuses to read a password. Invalid salt is therefore never
	// reached from the TTY path, so exercise it through --secrets-stdin by
	// putting the bad salt on stdin line 2.
	stdin := a2TestPassword + "\n" + "not-hex!" + "\n"
	out, code := runCLIWithInput(t, stdin, nil, "argon2id", "--secrets-stdin")
	if code == 0 {
		t.Errorf("expected argon2id to fail with invalid salt, output:\n%s", out)
	}
}

func TestArgon2idCmd_InvalidParamsFail(t *testing.T) {
	// Non-positive params must be rejected before any derivation work runs.
	// stdin supplies the password via --secrets-stdin, but the parameter
	// check fails first so the password is never read.
	stdin := a2TestPassword + "\n"
	for _, badArgs := range [][]string{
		{"--iterations", "0"},
		{"--memory", "0"},
		{"--parallelism", "0"},
		{"--key-length", "0"},
	} {
		// runCLIWithInput takes a flat variadic; prepend the command name
		// explicitly because Go does not allow mixing a fixed arg with a
		// slice spread.
		full := append([]string{"argon2id", "--secrets-stdin"}, badArgs...)
		if out, code := runCLIWithInput(t, stdin, nil, full...); code == 0 {
			t.Errorf("expected failure for %v, output:\n%s", badArgs, out)
		}
	}
}

// jsonKeyHex extracts the key_hex field from an argon2id --json output.
func jsonKeyHex(t *testing.T, out string) string {
	t.Helper()
	var got struct {
		KeyHex string `json:"key_hex"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	return got.KeyHex
}
