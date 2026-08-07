package cmd

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"go-cipher-cli/internal/util"
)

// End-to-end tests for the argon2id CLI command.
//
// The command reads the password either interactively from a terminal or via
// --pipe from stdin, so these tests exercise the paths that are reachable
// without a TTY: --pipe derivation, invalid parameters rejected up front, and
// piped stdin without --pipe refused.

func TestArgon2idCmd_Pipe_GoldenVector(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	// Fixed password + salt via --pipe; the derivation is deterministic, so
	// the result matches the reference argon2.IDKey golden vector.
	stdin := "TestPass!2026\n00112233445566778899aabbccddeeff\n"
	buf, code := runCLIWithInputBuf(t, stdin, nil, "argon2id", "--pipe",
		"--iterations", "2", "--memory", "8", "--key-length", "32")
	defer util.WipeBytes(buf.Bytes())
	if code != 0 {
		t.Fatalf("argon2id --pipe failed: %s", buf.String())
	}
	out := buf.String()
	wantHex := "2afa7f5bf041cb89dd3386b80ec27f51036fa97e86822f2e08a3f4be8ff58a70"
	if !strings.Contains(out, "Key (hex):    "+wantHex) {
		t.Errorf("expected full key hex, output:\n%s", out)
	}
	if strings.Contains(out, "TestPass!2026") {
		t.Errorf("stdout leaks the password:\n%s", out)
	}
}

func TestArgon2idCmd_PipeOut_PrintsHexOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	// --pipe-out prints only the derived key as hex, with no label lines, so the
	// stdout is directly consumable by another program.
	stdin := "TestPass!2026\n00112233445566778899aabbccddeeff\n"
	buf, code := runCLIWithInputBuf(t, stdin, nil, "argon2id", "--pipe", "--pipe-out",
		"--iterations", "2", "--memory", "8", "--key-length", "32")
	defer util.WipeBytes(buf.Bytes())
	if code != 0 {
		t.Fatalf("argon2id --pipe --pipe-out failed: %s", buf.Bytes())
	}
	// stdout is two lines: salt hex then key hex.
	wantSaltHex := []byte("00112233445566778899aabbccddeeff")
	wantKeyHex := []byte("2afa7f5bf041cb89dd3386b80ec27f51036fa97e86822f2e08a3f4be8ff58a70")
	out := bytes.Split(buf.Bytes(), []byte("\n"))
	t.Logf("pipe-out output: %q", buf.Bytes())
	if len(out) != 3 || !bytes.Equal(out[0], wantSaltHex) || !bytes.Equal(out[1], wantKeyHex) {
		t.Errorf("stdout = %q, want salt %q then key %q", buf.Bytes(), wantSaltHex, wantKeyHex)
	}
}

func TestArgon2idCmd_Pipe_RandomSaltDifferentKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	// Password only, no salt line: each run draws a fresh random salt so the
	// derived keys must differ.
	extractHex := func(out string) string {
		const prefix = "Key (hex):    "
		i := strings.Index(out, prefix)
		if i < 0 {
			t.Fatalf("no key line in output:\n%s", out)
		}
		line := out[i+len(prefix):]
		line = line[:strings.IndexByte(line, '\n')]
		return line
	}
	stdin := "TestPass!2026\n"
	buf1, code1 := runCLIWithInputBuf(t, stdin, nil, "argon2id", "--pipe", "--memory", "8", "--key-length", "32")
	defer util.WipeBytes(buf1.Bytes())
	buf2, code2 := runCLIWithInputBuf(t, stdin, nil, "argon2id", "--pipe", "--memory", "8", "--key-length", "32")
	defer util.WipeBytes(buf2.Bytes())
	out1, out2 := buf1.String(), buf2.String()
	if code1 != 0 || code2 != 0 {
		t.Fatalf("argon2id failed: out1=%d out2=%d", code1, code2)
	}
	k1, _ := hex.DecodeString(extractHex(out1))
	k2, _ := hex.DecodeString(extractHex(out2))
	if string(k1) == string(k2) {
		t.Fatal("two runs without a salt produced the same key — random salt broken")
	}
}

func TestArgon2idCmd_StdinPipedRefused(t *testing.T) {
	// runCLIWithInputBuf wires a non-nil stdin reader, which exec treats as a
	// pipe rather than a TTY, so argon2id must refuse instead of silently
	// deriving from an empty password.
	buf, code := runCLIWithInputBuf(t, "whatever\n", nil, "argon2id")
	defer util.WipeBytes(buf.Bytes())
	if code == 0 {
		t.Errorf("expected argon2id to fail with piped stdin, output:\n%s", buf.String())
	}
}

func TestArgon2idCmd_InvalidParamsFail(t *testing.T) {
	// Non-positive params are rejected before the terminal check, so no
	// interactive password prompt is needed.
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
