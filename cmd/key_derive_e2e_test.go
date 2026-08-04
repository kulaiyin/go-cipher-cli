package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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

	// restore with WRONG input -> must report failure AND exit non-zero, so
	// scripts and CI can reliably detect a mismatch (not just rely on the
	// output text). The failure message goes to stderr with a non-zero exit
	// code. No re-derived details (UUID/keys/config) may leak to stdout.
	out, code := runCLI(t, "key-derive", "--mode", "restore",
		"-i", "WrongInputTextHere1234567890", "-p", kdPassword,
		"--config", cfgPath)
	if code == 0 {
		t.Fatalf("restore should exit non-zero on verification failure, got 0: %s", out)
	}
	if !strings.Contains(out, "restore failed") && !strings.Contains(out, "failed") {
		t.Errorf("expected restore failed message, output:\n%s", out)
	}
	// The error message itself mentions "UUID" but never as a "UUID: " detail
	// line; require that no derived-key details were printed.
	if strings.Contains(out, "UUID: ") {
		t.Errorf("failed restore must not print derived key details, output:\n%s", out)
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

// --- --use-config-file flow (path-printing + confirmation) ---
//
// No editor is launched (cross-platform): the command prints the config file
// path, the user edits it in their own editor, then confirms. Tests simulate
// the user by pre-writing the config file and answering the confirmation.

// validConfigYAML returns a config matching the golden vector (basic tier).
func validConfigYAML() string {
	return fmt.Sprintf("input: %q\nhint: \"\"\nstrength: \"basic\"\n", kdInput)
}

// findGeneratedConfig returns the single generated config under
// <tmp>/mntemp/default (empty string if none/unexpected count).
func findGeneratedConfig(t *testing.T, tmp string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(tmp, "mntemp", "default", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 generated config under mntemp/default, got %v", matches)
	}
	return matches[0]
}

// TestKeyDeriveConfigFile_AutoPath verifies the no-flag path: a template is
// generated under mntemp/default, its path is printed for the user to edit,
// and a closed stdin aborts cleanly instead of hanging.
func TestKeyDeriveConfigFile_AutoPath(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	dir := t.TempDir()
	out, code := runCLIWithInput(t, "", []string{"TMPDIR=" + dir},
		"key-derive", "--use-config-file")
	if code != 1 {
		t.Fatalf("expected abort on closed stdin, got code=%d:\n%s", code, out)
	}
	cfgPath := findGeneratedConfig(t, dir)
	if !strings.Contains(out, cfgPath) {
		t.Errorf("output does not print the config path %q:\n%s", cfgPath, out)
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "input:") {
		t.Errorf("generated template missing input field:\n%s", raw)
	}
}

// TestKeyDeriveConfigFile_GenerateFromExistingConfig drives the happy path:
// the user already edited a config file (pre-written here), confirms, and the
// derivation matches the golden vector.
func TestKeyDeriveConfigFile_GenerateFromExistingConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "my-config.yaml")
	if err := os.WriteFile(cfgPath, []byte(validConfigYAML()), 0o600); err != nil {
		t.Fatal(err)
	}

	out, code := runCLIWithInput(t, "Y\n", nil,
		"key-derive", "--use-config-file", "--config-file", cfgPath, "-p", kdPassword, "--salt", kdSalt)
	if code != 0 {
		t.Fatalf("config-file generate failed (%d):\n%s", code, out)
	}
	if got := extractUUID(t, out); got != kdWantUUID {
		t.Errorf("UUID = %q, want %q", got, kdWantUUID)
	}
	if got := extractKey(t, out, "S1"); got != kdWantS1 {
		t.Errorf("S1 = %q, want %q", got, kdWantS1)
	}
	// The recovery config must be saved next to the config file and the user
	// warned it is volatile (temp dir, lost on reboot).
	rcPath := filepath.Join(dir, "my-config.txt")
	rcRaw, err := os.ReadFile(rcPath)
	if err != nil {
		t.Fatalf("recovery config not auto-saved: %v", err)
	}
	if !strings.Contains(string(rcRaw), "DATA:") {
		t.Errorf("recovery config file missing DATA payload:\n%s", rcRaw)
	}
	if !strings.Contains(out, "temporary directory") {
		t.Errorf("expected volatile warning for the recovery config, got:\n%s", out)
	}
}

// TestKeyDeriveConfigFile_InvalidConfigLoop verifies the loop when validation
// fails: the error and the path hint are shown again, and the flow aborts
// cleanly when stdin closes (the user never fixes the file).
func TestKeyDeriveConfigFile_InvalidConfigLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(cfgPath, []byte("input: \"\"\nhint: \"\"\nstrength: \"basic\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, code := runCLIWithInput(t, "Y\nY\n", nil,
		"key-derive", "--use-config-file", "--config-file", cfgPath, "-p", kdPassword, "--salt", kdSalt)
	if code != 1 {
		t.Fatalf("expected abort after repeated invalid config, got code=%d:\n%s", code, out)
	}
	if !strings.Contains(out, "input must not be empty") {
		t.Errorf("expected empty-input error, got:\n%s", out)
	}
	if strings.Count(out, cfgPath) < 2 {
		t.Errorf("expected the config path to be re-printed after failure:\n%s", out)
	}
}

// TestKeyDeriveConfigFile_CustomMissingPath generates a template at the
// requested path when the file does not exist yet.
func TestKeyDeriveConfigFile_CustomMissingPath(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "nested", "custom.yaml") // parent missing

	out, code := runCLIWithInput(t, "Y\nY\n", nil,
		"key-derive", "--use-config-file", "--config-file", cfgPath, "-p", kdPassword, "--salt", kdSalt)
	if code != 1 {
		t.Fatalf("expected abort (template input empty), got code=%d:\n%s", code, out)
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config not generated at requested path: %v", err)
	}
	if !strings.Contains(string(raw), "input:") {
		t.Errorf("generated template at custom path missing input field:\n%s", raw)
	}
	if !strings.Contains(out, cfgPath) {
		t.Errorf("output does not print the config path %q:\n%s", cfgPath, out)
	}
}

// TestKeyDeriveConfigFile_RestoreRejected ensures --use-config-file only
// applies to generate mode; restore keeps its existing behaviour.
func TestKeyDeriveConfigFile_RestoreRejected(t *testing.T) {
	out, code := runCLI(t, "key-derive", "--use-config-file", "--mode", "restore")
	if code != 1 {
		t.Fatalf("restore with --use-config-file should fail, got code=%d:\n%s", code, out)
	}
	if !strings.Contains(out, "generate") {
		t.Errorf("expected error mentioning generate mode, got:\n%s", out)
	}
}

func TestKeyDeriveCmd_InvalidStrengthFails(t *testing.T) {
	out, code := runCLI(t, "key-derive", "--mode", "generate",
		"-i", kdInput, "-p", kdPassword, "--strength", "bogus")
	if code == 0 {
		t.Fatalf("expected non-zero exit for invalid strength, output:\n%s", out)
	}
	if !strings.Contains(out, "bogus") {
		t.Errorf("expected error to mention the invalid strength value, got:\n%s", out)
	}
}

func TestKeyDeriveCmd_WeakPasswordFails(t *testing.T) {
	out, code := runCLI(t, "key-derive", "--mode", "generate",
		"-i", kdInput, "-p", "weakpass", "--strength", "basic")
	if code == 0 {
		t.Fatalf("expected non-zero exit for weak password, output:\n%s", out)
	}
}

func TestKeyDeriveCmd_ShortInputFails(t *testing.T) {
	out, code := runCLI(t, "key-derive", "--mode", "generate",
		"-i", "short", "-p", kdPassword, "--strength", "basic")
	if code == 0 {
		t.Fatalf("expected non-zero exit for short input, output:\n%s", out)
	}
}

func TestKeyDeriveCmd_Restore_WrongPassword(t *testing.T) {
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

	out, code := runCLI(t, "key-derive", "--mode", "restore",
		"-i", kdInput, "-p", "WrongP@ss1",
		"--config", cfgPath)
	if code == 0 {
		t.Fatalf("restore should exit non-zero on wrong password, got 0: %s", out)
	}
	if strings.Contains(out, "UUID: ") {
		t.Errorf("failed restore must not print derived key details, output:\n%s", out)
	}
}

func TestKeyDeriveCmd_Restore_MissingConfigFails(t *testing.T) {
	out, code := runCLI(t, "key-derive", "--mode", "restore",
		"-i", kdInput, "-p", kdPassword)
	if code == 0 {
		t.Fatalf("expected non-zero exit without --config, output:\n%s", out)
	}
}

func TestKeyDeriveCmd_Restore_NonexistentConfigFails(t *testing.T) {
	out, code := runCLI(t, "key-derive", "--mode", "restore",
		"-i", kdInput, "-p", kdPassword,
		"--config", filepath.Join(t.TempDir(), "nope.txt"))
	if code == 0 {
		t.Fatalf("expected non-zero exit for missing config file, output:\n%s", out)
	}
}

func TestKeyDeriveCmd_Restore_TamperedConfig(t *testing.T) {
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

	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	text := string(raw)
	dataB64 := ""
	for _, line := range strings.Split(text, "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "DATA: ") {
			dataB64 = strings.TrimSpace(strings.TrimPrefix(trimmed, "DATA: "))
			break
		}
	}
	if dataB64 == "" {
		t.Fatal("no DATA line in config")
	}
	decoded, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		t.Fatal(err)
	}
	var dataObj map[string]interface{}
	if err := json.Unmarshal(decoded, &dataObj); err != nil {
		t.Fatal(err)
	}
	salt, ok := dataObj["salt"].(string)
	if !ok || salt == "" {
		t.Fatal("no salt in DATA payload")
	}
	dataObj["salt"] = strings.Repeat("f", len(salt))
	mutated, err := json.Marshal(dataObj)
	if err != nil {
		t.Fatal(err)
	}
	newB64 := base64.StdEncoding.EncodeToString(mutated)
	tampered := strings.Replace(text, "DATA: "+dataB64, "DATA: "+newB64, 1)
	if tampered == text {
		t.Fatal("tamper substitution produced identical content")
	}
	if err := os.WriteFile(cfgPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	out, code := runCLI(t, "key-derive", "--mode", "restore",
		"-i", kdInput, "-p", kdPassword,
		"--config", cfgPath)
	if code == 0 {
		t.Fatalf("restore should fail on tampered config, got 0: %s", out)
	}
}

func TestKeyDeriveCmd_Generate_CustomHint(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "recovery.txt")
	_, code := runCLI(t, "key-derive", "--mode", "generate",
		"-i", kdInput, "-p", kdPassword,
		"--strength", "basic", "--salt", kdSalt,
		"--hint", "my-custom-hint",
		"--output", cfgPath)
	if code != 0 {
		t.Fatalf("generate failed: %s", t.Name())
	}

	cfg, err := parseFrontendRecoveryConfig(string(readFile(t, cfgPath)))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if cfg.Hint != "my-custom-hint" {
		t.Errorf("config hint = %q, want my-custom-hint", cfg.Hint)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
