package cmd

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-end tests for the key-derive CLI command.
//
// These run the compiled binary as a subprocess (see runCLI / TestMain in
// cli_e2e_test.go) and assert end-to-end behaviour:
//   - generate produces a key set matching the golden vector (byte-level interop)
//   - generate writes a valid recovery config in frontend text+base64 format
//   - restore with the correct inputs verifies successfully
//   - restore with wrong inputs fails
//
// All tests use the basic strength tier (~1.5s per derivation) and are skipped
// under -short.

const (
	// Fixed inputs matching internal/testvectors/keyderive-vectors.json.
	kdInput    = "ThisIsAFixedProbeInputForGoldenVector2026"
	kdPassword = "ProbePassword!2026"
	kdSalt     = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	// Expected outputs from the golden vector (frontend-derived).
	kdWantUUID = "50daa113b96fa309f362e48c533206e1"
	kdWantS1   = "ec9b6b4c1aa5d79a8d264fbeec4deaa2fad98dbffff8200ccf3598bea0c03b998f38cb2af69c27e55f43be83871e9283a3880f54f3e3d1bbed2194f06840e127"
)

// extractField pulls the value after "Name: " from a key-derive output line,
// e.g. "S1: ec9b..." -> "ec9b...". Returns "" if not found.
func extractField(out, prefix string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, prefix); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// extractUUID pulls the UUID value from key-derive output.
func extractUUID(t *testing.T, out string) string {
	t.Helper()
	v := extractField(out, "UUID:")
	if v == "" {
		t.Fatalf("no UUID line in output:\n%s", out)
	}
	return v
}

// extractKey pulls an S1/S2/S3 value from key-derive output.
func extractKey(t *testing.T, out, name string) string {
	t.Helper()
	v := extractField(out, name+":")
	if v == "" {
		t.Fatalf("no %s line in output:\n%s", name, out)
	}
	return v
}

// extractDataB64 pulls the base64 DATA line from a frontend-format config block.
func extractDataB64(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "DATA: ") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "DATA: "))
		}
	}
	t.Fatalf("no DATA line in output:\n%s", out)
	return ""
}

func TestKeyDeriveCmd_Generate_GoldenVector(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	out, code := runCLI(t, "key-derive", "--mode", "generate",
		"-i", kdInput, "-p", kdPassword,
		"--strength", "basic", "--salt", kdSalt)
	if code != 0 {
		t.Fatalf("key-derive generate failed: %s", out)
	}

	if got := extractUUID(t, out); got != kdWantUUID {
		t.Errorf("UUID mismatch\n got: %s\nwant: %s", got, kdWantUUID)
	}
	if got := extractKey(t, out, "S1"); got != kdWantS1 {
		t.Errorf("S1 mismatch\n got: %s\nwant: %s", got, kdWantS1)
	}
	// S2/S3 must be present and distinct from S1.
	s2 := extractKey(t, out, "S2")
	s3 := extractKey(t, out, "S3")
	if s2 == kdWantS1 || s3 == kdWantS1 || s2 == s3 {
		t.Errorf("keys should be distinct: S1/S2/S3 not all different")
	}
	// The salt must appear in the DATA field of the frontend-format config.
	dataB64 := extractDataB64(t, out)
	decoded, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		t.Fatalf("DATA is not valid base64: %v", err)
	}
	var dataObj struct {
		Salt string `json:"salt"`
	}
	if err := json.Unmarshal(decoded, &dataObj); err != nil {
		t.Fatalf("DATA is not valid JSON: %v", err)
	}
	if dataObj.Salt != kdSalt {
		t.Errorf("salt in DATA = %q, want %q", dataObj.Salt, kdSalt)
	}
}

func TestKeyDeriveCmd_Generate_WritesConfigFile(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "recovery.txt")

	out, code := runCLI(t, "key-derive", "--mode", "generate",
		"-i", kdInput, "-p", kdPassword,
		"--strength", "basic", "--salt", kdSalt,
		"--output", cfgPath)
	if code != 0 {
		t.Fatalf("generate failed: %s", out)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config file not written: %v", err)
	}
	cfg, err := parseFrontendRecoveryConfig(string(data))
	if err != nil {
		t.Fatalf("config not valid frontend format: %v", err)
	}
	if cfg.Version != "1.0.0" {
		t.Errorf("version = %q, want 1.0.0", cfg.Version)
	}
	if cfg.Salt != kdSalt {
		t.Errorf("salt = %q, want %q", cfg.Salt, kdSalt)
	}
	wantMaskedUUID := kdWantUUID[:8] + strings.Repeat("*", len(kdWantUUID)-16) + kdWantUUID[len(kdWantUUID)-8:]
	if cfg.UUID != wantMaskedUUID {
		t.Errorf("uuid = %q\n want %q", cfg.UUID, wantMaskedUUID)
	}
	if len(cfg.UUIDs) != 4 {
		t.Errorf("uuids len = %d, want 4", len(cfg.UUIDs))
	}
	// uuids[0] must equal S1[:8] + S1[len-8:] (fingerprint form, no asterisks).
	wantFingerprint := kdWantS1[:8] + kdWantS1[len(kdWantS1)-8:]
	if cfg.UUIDs[0] != wantFingerprint {
		t.Errorf("uuids[0] = %q, want %q", cfg.UUIDs[0], wantFingerprint)
	}
}

func TestKeyDeriveCmd_Restore_Match(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	// First generate a config to restore from.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "recovery.txt")
	_, code := runCLI(t, "key-derive", "--mode", "generate",
		"-i", kdInput, "-p", kdPassword,
		"--strength", "basic", "--salt", kdSalt,
		"--output", cfgPath)
	if code != 0 {
		t.Fatalf("setup generate failed")
	}

	out, code := runCLI(t, "key-derive", "--mode", "restore",
		"-i", kdInput, "-p", kdPassword,
		"--config", cfgPath)
	if code != 0 {
		t.Fatalf("restore failed: %s", out)
	}
	// restore with correct inputs must re-derive the same UUID and report success.
	if got := extractUUID(t, out); got != kdWantUUID {
		t.Errorf("UUID mismatch\n got: %s\nwant: %s", got, kdWantUUID)
	}
	if !strings.Contains(out, "restore success") && !strings.Contains(out, "successful") {
		t.Errorf("expected restore success message, output:\n%s", out)
	}
}

func TestKeyDeriveCmd_Restore_NoMatch(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "recovery.txt")
	_, code := runCLI(t, "key-derive", "--mode", "generate",
		"-i", kdInput, "-p", kdPassword,
		"--strength", "basic", "--salt", kdSalt,
		"--output", cfgPath)
	if code != 0 {
		t.Fatalf("setup generate failed")
	}

	// restore with WRONG input -> must report failure (but still exit 0; the
	// command completed, the verification result is just negative).
	out, code := runCLI(t, "key-derive", "--mode", "restore",
		"-i", "WrongInputTextHere1234567890", "-p", kdPassword,
		"--config", cfgPath)
	if code != 0 {
		t.Fatalf("restore should still exit 0 on verification failure: %s", out)
	}
	if !strings.Contains(out, "restore failed") && !strings.Contains(out, "failed") {
		t.Errorf("expected restore failed message, output:\n%s", out)
	}
}

func TestKeyDeriveCmd_DefaultModeIsGenerate(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	// No --mode flag: defaults to generate, produces a key set.
	out, code := runCLI(t, "key-derive",
		"-i", kdInput, "-p", kdPassword,
		"--strength", "basic", "--salt", kdSalt)
	if code != 0 {
		t.Fatalf("default mode failed: %s", out)
	}
	if got := extractUUID(t, out); got != kdWantUUID {
		t.Errorf("default mode should generate, UUID mismatch\n got: %s\nwant: %s", got, kdWantUUID)
	}
}

func TestKeyDeriveCmd_MissingPasswordFails(t *testing.T) {
	// Non-interactive (no TTY) + no password -> must fail fast, exit non-zero.
	out, code := runCLI(t, "key-derive", "--mode", "generate",
		"-i", kdInput, "--strength", "basic", "--salt", kdSalt)
	if code == 0 {
		t.Fatalf("expected non-zero exit without password, output:\n%s", out)
	}
}

func TestKeyDeriveCmd_InvalidModeFails(t *testing.T) {
	out, code := runCLI(t, "key-derive", "--mode", "bogus",
		"-i", kdInput, "-p", kdPassword, "--strength", "basic")
	if code == 0 {
		t.Fatalf("expected non-zero exit for invalid mode, output:\n%s", out)
	}
}

// TestKeyDeriveCmd_Restore_LegacyJSON verifies that the restore command can
// still read the old raw JSON format for backward compatibility.
func TestKeyDeriveCmd_Restore_LegacyJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "recovery.json")

	s1fp := kdWantS1[:8] + kdWantS1[len(kdWantS1)-8:]
	legacy := recoveryConfig{
		Version:  "1.0.0",
		Strength: "basic",
		Salt:     kdSalt,
		UUID:     kdWantUUID,
		Hint:     "test-hint",
		HintIDs:  []string{},
		UUIDs:    []string{s1fp},
	}
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	out, code := runCLI(t, "key-derive", "--mode", "restore",
		"-i", kdInput, "-p", kdPassword,
		"--config", cfgPath)
	if code != 0 {
		t.Fatalf("restore from legacy JSON failed: %s", out)
	}
	if got := extractUUID(t, out); got != kdWantUUID {
		t.Errorf("UUID mismatch\n got: %s\nwant: %s", got, kdWantUUID)
	}
	if !strings.Contains(out, "restore success") && !strings.Contains(out, "successful") {
		t.Errorf("expected restore success message, output:\n%s", out)
	}
}
