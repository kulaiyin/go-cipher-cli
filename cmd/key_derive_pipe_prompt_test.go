package cmd

import (
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/kdf"
)

// Tests for the interactive (TTY) core of key-derive-pipe. The prompt
// collection itself needs a terminal (huh/bubbletea) and is not automated;
// these tests drive the derive+emit/verify functions with a fully-collected
// state so the wipeable-byte flow is exercised without a TTY.

func TestRunKeyDerivePipeInteractiveGenerate_ConfigFile(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	dir := t.TempDir()
	outPath := filepath.Join(dir, "recovery.txt")
	state := &keyDerivePipeInteractiveState{
		Mode:     "generate",
		Input:    kdInput,
		Salt:     kdSalt,
		Hint:     "myhint",
		Strength: kdf.StrengthBasic,
		Output:   outPath,
		Password: []byte(kdPassword),
	}
	defer clear(state.Password)

	if err := runKeyDerivePipeInteractiveGenerate(state); err != nil {
		t.Fatalf("generate: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	if strings.Contains(string(data), kdWantS1) {
		t.Error("config leaks a full S1 key")
	}
	cfg, err := loadRecoveryConfig(outPath)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if cfg.Salt != kdSalt {
		t.Errorf("salt = %q, want %q", cfg.Salt, kdSalt)
	}
	fp := kdWantS1[:8] + kdWantS1[len(kdWantS1)-8:]
	found := false
	for _, u := range cfg.UUIDs {
		if u == fp {
			found = true
		}
	}
	if !found {
		t.Error("uuids missing the S1 fingerprint")
	}
}

func TestRunKeyDerivePipeInteractiveRestore(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	cfg := &recoveryConfig{
		Salt:  kdSalt,
		UUIDs: []string{kdWantS1[:8] + kdWantS1[len(kdWantS1)-8:]},
	}
	good := &keyDerivePipeInteractiveState{
		Mode:     "restore",
		Input:    kdInput,
		Salt:     kdSalt,
		Strength: kdf.StrengthBasic,
		UUIDs:    cfg.UUIDs,
		Password: []byte(kdPassword),
	}
	defer clear(good.Password)
	out, err := captureStdout(t, func() error { return runKeyDerivePipeInteractiveRestore(good) })
	if err != nil {
		t.Fatalf("restore should succeed: %v", err)
	}
	// The rebuilt config's masked key rows carry the S1 fingerprint in the
	// clear; the UUID fingerprint lives only inside the base64 DATA block.
	if !strings.Contains(out, kdWantS1[:8]) {
		t.Errorf("restore did not emit the rebuilt recovery config (missing S1 fingerprint):\n%s", out)
	}
	if !strings.Contains(out, i18n.T("key_derive.output.restore_success")) {
		t.Errorf("restore success message missing:\n%s", out)
	}

	bad := &keyDerivePipeInteractiveState{
		Mode:     "restore",
		Input:    kdInput,
		Salt:     kdSalt,
		Strength: kdf.StrengthBasic,
		UUIDs:    cfg.UUIDs,
		Password: []byte("WrongP@ss1"),
	}
	defer clear(bad.Password)
	if err := runKeyDerivePipeInteractiveRestore(bad); err == nil {
		t.Fatal("restore should fail with the wrong password")
	}
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what
// was written to it.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	runErr := fn()
	w.Close()
	data, _ := io.ReadAll(r)
	return string(data), runErr
}

func TestWriteKeySetBytesFile(t *testing.T) {
	rawS1, _ := hex.DecodeString(kdWantS1)
	rawS2, _ := hex.DecodeString(strings.Repeat("ab", 64))
	rawS3, _ := hex.DecodeString(strings.Repeat("cd", 64))
	rawUUID, _ := hex.DecodeString(kdWantUUID)
	r := kdf.KeySetBytesResult{
		RawKeys: [][]byte{rawS1, rawS2, rawS3},
		RawUUID: rawUUID,
	}
	path := filepath.Join(t.TempDir(), "keys.txt")
	if err := writeKeySetBytesFile(path, r); err != nil {
		t.Fatalf("write keys file: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	if !strings.Contains(string(data), kdWantS1) {
		t.Errorf("keys file missing S1:\n%s", data)
	}
	if !strings.Contains(string(data), kdWantUUID) {
		t.Errorf("keys file missing UUID:\n%s", data)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("permissions = %o, want 600", fi.Mode().Perm())
	}
}
