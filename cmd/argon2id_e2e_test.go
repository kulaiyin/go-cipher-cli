package cmd

import (
	"bytes"
	"os"
	"testing"

	"github.com/buger/jsonparser"

	"go-cipher-cli/internal/util"
)

// End-to-end tests for the argon2id CLI command.
//
// The command reads the password either interactively from a terminal or from
// a piped JSON object when stdin is piped/redirected, so these tests exercise
// the paths that are reachable without a TTY: JSON input derivation, invalid
// parameters rejected up front, and the fallback when the JSON lacks a
// password (which requires a controlling terminal and therefore fails here).

func TestArgon2idCmd_JSON_GoldenVector(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	// Fixed password + salt via a piped JSON object; the derivation is
	// deterministic, so the result matches the reference argon2.IDKey golden
	// vector.
	stdin := `{"password":"TestPass!2026","salt":"00112233445566778899aabbccddeeff"}`
	buf, code := runCLIWithInputBuf(t, stdin, nil, "argon2id",
		"--iterations", "2", "--memory", "8", "--key-length", "32")
	defer util.WipeBytes(buf.Bytes())
	if code != 0 {
		t.Fatalf("argon2id failed: %s", buf.String())
	}
	out := buf.Bytes()
	salt, _, _, _ := jsonparser.Get(out, "salt")
	key, _, _, _ := jsonparser.Get(out, "key")
	wantKeyHex := []byte("2afa7f5bf041cb89dd3386b80ec27f51036fa97e86822f2e08a3f4be8ff58a70")
	if !bytes.Equal(key, wantKeyHex) {
		t.Errorf("key = %q, want %q (output: %s)", key, wantKeyHex, out)
	}
	if !bytes.Equal(salt, []byte("00112233445566778899aabbccddeeff")) {
		t.Errorf("salt = %q, want 00112233445566778899aabbccddeeff", salt)
	}
	if bytes.Contains(out, []byte("TestPass!2026")) {
		t.Errorf("stdout leaks the password:\n%s", out)
	}
}

func TestArgon2idCmd_JSON_RandomSaltDifferentKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	// Password only, no salt in the JSON: each run draws a fresh random salt so
	// the derived keys must differ.
	stdin := `{"password":"TestPass!2026"}`
	buf1, code1 := runCLIWithInputBuf(t, stdin, nil, "argon2id", "--memory", "8", "--key-length", "32")
	defer util.WipeBytes(buf1.Bytes())
	buf2, code2 := runCLIWithInputBuf(t, stdin, nil, "argon2id", "--memory", "8", "--key-length", "32")
	defer util.WipeBytes(buf2.Bytes())
	if code1 != 0 || code2 != 0 {
		t.Fatalf("argon2id failed: out1=%d out2=%d", code1, code2)
	}
	key1, _, _, _ := jsonparser.Get(buf1.Bytes(), "key")
	key2, _, _, _ := jsonparser.Get(buf2.Bytes(), "key")
	if bytes.Equal(key1, key2) {
		t.Fatal("two runs without a salt produced the same key — random salt broken")
	}
}

func TestArgon2idCmd_JSON_MissingPasswordNeedsTTY(t *testing.T) {
	// A piped JSON without a password falls back to the controlling terminal.
	// This can only be observed when no /dev/tty exists (e.g. CI): on a real
	// terminal the fallback would block waiting for keyboard input, so skip.
	if f, err := os.Open("/dev/tty"); err == nil {
		f.Close()
		t.Skip("test requires a run without a controlling terminal")
	}
	stdin := `{"salt":"00112233445566778899aabbccddeeff"}`
	buf, code := runCLIWithInputBuf(t, stdin, nil, "argon2id")
	defer util.WipeBytes(buf.Bytes())
	if code == 0 {
		t.Errorf("expected argon2id to fail when piped JSON has no password, output:\n%s", buf.String())
	}
}

func TestArgon2idCmd_InvalidParamsFail(t *testing.T) {
	// Non-positive params are rejected before the input path, so no password
	// is needed.
	for _, badArgs := range [][]string{
		{"--iterations", "0"},
		{"--memory", "0"},
		{"--parallelism", "0"},
		{"--key-length", "0"},
	} {
		full := append([]string{"argon2id"}, badArgs...)
		buf, code := runCLIWithInputBuf(t, "", nil, full...)
		util.WipeBytes(buf.Bytes())
		if code == 0 {
			t.Errorf("expected failure for %v, output:\n%s", badArgs, buf.String())
		}
	}
}
