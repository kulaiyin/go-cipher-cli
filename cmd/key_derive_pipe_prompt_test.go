package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	if err := runKeyDerivePipeInteractiveRestore(good); err != nil {
		t.Fatalf("restore should succeed: %v", err)
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
