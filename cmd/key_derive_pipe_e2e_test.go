package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/buger/jsonparser"

	"go-cipher-cli/internal/util"
)

// End-to-end tests for the `key-derive-pipe` subcommand: run the compiled
// binary as a subprocess (runCLIWithInputBuf), feed JSON on stdin, assert on
// the JSON output. Reuses golden-vector constants from key_derive_e2e_test.go.

// pipeJSON builds the stdin JSON payload for a generate run.
func pipeJSON(t *testing.T, salt string) string {
	t.Helper()
	return `{"mode":"generate","input":"` + kdInput + `","password":"` + kdPassword + `","salt":"` + salt + `","strength":"basic"}`
}

// TestKeyDerivePipeCmd_GoldenVector: S1/UUID match the golden vector.
func TestKeyDerivePipeCmd_GoldenVector(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	buf, code := runCLIWithInputBuf(t, pipeJSON(t, kdSalt), nil, "key-derive-pipe")
	defer util.WipeBytes(buf.Bytes())
	if code != 0 {
		t.Fatalf("key-derive-pipe failed: %s", buf.String())
	}
	out := buf.Bytes()
	uuid, _, _, _ := jsonparser.Get(out, "uuid")
	if string(uuid) != kdWantUUID {
		t.Errorf("uuid = %q, want %q", uuid, kdWantUUID)
	}
	s1, _, _, _ := jsonparser.Get(out, "keys", "[0]")
	if string(s1) != kdWantS1 {
		t.Errorf("S1 = %q, want %q", s1, kdWantS1)
	}
	if bytes.Contains(out, []byte(kdPassword)) {
		t.Errorf("stdout leaks the password:\n%s", out)
	}
}

// TestKeyDerivePipeCmd_RandomSaltDifferentKeys: no salt -> two runs differ.
func TestKeyDerivePipeCmd_RandomSaltDifferentKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	payload := `{"mode":"generate","input":"` + kdInput + `","password":"` + kdPassword + `","strength":"basic"}`
	buf1, code1 := runCLIWithInputBuf(t, payload, nil, "key-derive-pipe")
	defer util.WipeBytes(buf1.Bytes())
	buf2, code2 := runCLIWithInputBuf(t, payload, nil, "key-derive-pipe")
	defer util.WipeBytes(buf2.Bytes())
	if code1 != 0 || code2 != 0 {
		t.Fatalf("failed: code1=%d code2=%d", code1, code2)
	}
	k1, _, _, _ := jsonparser.Get(buf1.Bytes(), "keys", "[0]")
	k2, _, _, _ := jsonparser.Get(buf2.Bytes(), "keys", "[0]")
	if bytes.Equal(k1, k2) {
		t.Fatal("two runs without a salt produced the same key — random salt broken")
	}
}

// TestKeyDerivePipeCmd_Deterministic: same payload -> same keys.
func TestKeyDerivePipeCmd_Deterministic(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	buf1, code1 := runCLIWithInputBuf(t, pipeJSON(t, kdSalt), nil, "key-derive-pipe")
	defer util.WipeBytes(buf1.Bytes())
	buf2, code2 := runCLIWithInputBuf(t, pipeJSON(t, kdSalt), nil, "key-derive-pipe")
	defer util.WipeBytes(buf2.Bytes())
	if code1 != 0 || code2 != 0 {
		t.Fatalf("failed: code1=%d code2=%d", code1, code2)
	}
	k1, _, _, _ := jsonparser.Get(buf1.Bytes(), "keys", "[0]")
	k2, _, _, _ := jsonparser.Get(buf2.Bytes(), "keys", "[0]")
	if !bytes.Equal(k1, k2) {
		t.Fatalf("same inputs produced different keys:\n %s\n %s", k1, k2)
	}
}

// TestKeyDerivePipeCmd_InvalidParams: bad inputs -> non-zero exit.
func TestKeyDerivePipeCmd_InvalidParams(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{"bad mode", `{"mode":"bogus","input":"` + kdInput + `","password":"` + kdPassword + `","strength":"basic"}`},
		{"short input", `{"mode":"generate","input":"short","password":"` + kdPassword + `","strength":"basic"}`},
		{"weak password", `{"mode":"generate","input":"` + kdInput + `","password":"weakpass","strength":"basic"}`},
		{"invalid salt hex", `{"mode":"generate","input":"` + kdInput + `","password":"` + kdPassword + `","salt":"nothex","strength":"basic"}`},
		{"invalid strength", `{"mode":"generate","input":"` + kdInput + `","password":"` + kdPassword + `","strength":"bogus"}`},
		{"empty payload", ``},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			buf, code := runCLIWithInputBuf(t, c.payload, nil, "key-derive-pipe")
			util.WipeBytes(buf.Bytes())
			if code == 0 {
				t.Fatalf("expected non-zero exit for %s", c.name)
			}
		})
	}
}

// TestKeyDerivePipeCmd_RestoreSuccess: generate a config, then re-derive via
// mode=restore; keys match the generate run.
func TestKeyDerivePipeCmd_RestoreSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	dir := t.TempDir()
	cfgPath := dir + "/recovery.txt"

	// 1. Generate a recovery config via the legacy command (it writes the
	//    frontend text+base64 format with the salt).
	_, code := runCLI(t, "key-derive", "--mode", "generate",
		"-i", kdInput, "-p", kdPassword,
		"--strength", "basic", "--salt", kdSalt,
		"--output", cfgPath)
	if code != 0 {
		t.Fatalf("setup generate failed")
	}

	// 2. Re-derive via the pipe command in restore mode.
	genBuf, code := runCLIWithInputBuf(t, pipeJSON(t, kdSalt), nil, "key-derive-pipe")
	defer util.WipeBytes(genBuf.Bytes())
	if code != 0 {
		t.Fatalf("generate via pipe failed: %s", genBuf.String())
	}
	restorePayload := `{"mode":"restore","input":"` + kdInput + `","password":"` + kdPassword + `","config":"` + cfgPath + `"}`
	restBuf, code := runCLIWithInputBuf(t, restorePayload, nil, "key-derive-pipe")
	defer util.WipeBytes(restBuf.Bytes())
	if code != 0 {
		t.Fatalf("restore via pipe failed: %s", restBuf.String())
	}
	genS1, _, _, _ := jsonparser.Get(genBuf.Bytes(), "keys", "[0]")
	restS1, _, _, _ := jsonparser.Get(restBuf.Bytes(), "keys", "[0]")
	if !bytes.Equal(genS1, restS1) {
		t.Fatalf("restore key mismatch:\n generate:  %s\n restore:   %s", genS1, restS1)
	}
}

// TestKeyDerivePipeCmd_NoStdinFails: empty stdin -> clear failure, no hang.
func TestKeyDerivePipeCmd_NoStdinFails(t *testing.T) {
	// Empty stdin -> resolveKeyDerivePipeParams gets an empty payload -> no
	// input/password -> validation rejects it.
	buf, code := runCLIWithInputBuf(t, "", nil, "key-derive-pipe")
	defer util.WipeBytes(buf.Bytes())
	if code == 0 {
		t.Fatalf("expected non-zero exit for empty stdin")
	}
	out := buf.String()
	// The error must mention input or password (the required fields), not crash.
	if !strings.Contains(out, "input") && !strings.Contains(out, "password") {
		t.Errorf("expected error to mention required field, got:\n%s", out)
	}
}
