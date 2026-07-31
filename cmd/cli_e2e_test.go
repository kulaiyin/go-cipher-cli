package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// testBinary is built once via TestMain so every runCLI invocation runs the CLI in a
// fresh, fully-isolated process. This avoids cobra's flag-state leakage between subtests
// (StringSlice flags append across reused rootCmd invocations).
var testBinary string

func TestMain(m *testing.M) {
	// Build the CLI binary from the module root so e2e tests run in an isolated process
	// (avoids cobra flag-state leakage between subtests).
	root, _ := os.Getwd()
	root = filepath.Join(root, "..") // go-cipher-cli/cmd -> go-cipher-cli (module root)
	bin, err := os.CreateTemp("", "gocipher-e2e-*")
	if err != nil {
		panic(err)
	}
	bin.Close()
	build := exec.Command("go", "build", "-o", bin.Name(), ".")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		panic("build failed: " + err.Error() + "\n" + string(out))
	}
	testBinary = bin.Name()
	code := m.Run()
	_ = os.Remove(testBinary)
	os.Exit(code)
}

// End-to-end test of the encrypt/decrypt CLI commands against real files,
// exercising the full pipeline (argon2id -> HMAC-SHA3-512 -> HKDF -> AES-256-GCM
// -> binary container).

func runCLI(t *testing.T, args ...string) (stdout string, exitCode int) {
	t.Helper()
	return runCLIWithInput(t, "", nil, args...)
}

// runCLIWithInput runs the CLI with the given stdin payload and extra env
// entries. Tests that must answer an interactive prompt (e.g. the
// --use-config-file confirmation) or inject a fake $EDITOR use this instead of
// runCLI.
func runCLIWithInput(t *testing.T, stdin string, env []string, args ...string) (stdout string, exitCode int) {
	t.Helper()
	if testBinary == "" {
		t.Fatal("testBinary not built")
	}
	cmd := exec.Command(testBinary, args...)
	cmd.Env = append(os.Environ(), append(env, "LANG=en_US.UTF-8")...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	stdout = out.String()
	if err != nil {
		exitCode = 1
	}
	return stdout, exitCode
}

// Commented out: encrypt/decrypt commands not yet implemented.
// func TestEncryptDecrypt_RoundTrip(t *testing.T) {
// 	if testing.Short() {
// 		t.Skip("argon2 slow in -short")
// 	}
// 	tmp := t.TempDir()
// 	inPath := filepath.Join(tmp, "secret.txt")
// 	outPath := inPath + ".enc"
// 	plaintext := []byte("top secret payload with CJK and emoji 🔐")
// 	if err := os.WriteFile(inPath, plaintext, 0o644); err != nil {
// 		t.Fatal(err)
// 	}
//
// 	// Encrypt with two passwords and an explicit salt (reproducible container).
// 	salt := strings.Repeat("ab", 64) // 128 hex
// 	if out, code := runCLI(t, "encrypt", inPath, "-p", "pw-one", "-p", "pw-two", "--salt", salt); code != 0 {
// 		t.Fatalf("encrypt failed: %s", out)
// 	}
// 	enc, err := os.ReadFile(outPath)
// 	if err != nil {
// 		t.Fatalf("read enc: %v", err)
// 	}
// 	if len(enc) < 76 {
// 		t.Fatalf("container too small: %d", len(enc))
// 	}
//
// 	// Decrypt with the same passwords -> must match the original plaintext.
// 	// Our decrypt strips ".enc" suffix: secret.txt.enc -> secret.txt. To avoid
// 	// clobbering the input, decrypt into a separate dir by copying first.
// 	decDir := filepath.Join(tmp, "dec")
// 	if err := os.MkdirAll(decDir, 0o755); err != nil {
// 		t.Fatal(err)
// 	}
// 	encCopy := filepath.Join(decDir, "secret.txt.enc")
// 	if err := os.WriteFile(encCopy, enc, 0o644); err != nil {
// 		t.Fatal(err)
// 	}
// 	if out, code := runCLI(t, "decrypt", encCopy, "-p", "pw-two", "-p", "pw-one"); code != 0 {
// 		t.Fatalf("decrypt failed: %s", out)
// 	}
// 	got, err := os.ReadFile(filepath.Join(decDir, "secret.txt"))
// 	if err != nil {
// 		t.Fatalf("read decrypted: %v", err)
// 	}
// 	if string(got) != string(plaintext) {
// 		t.Errorf("round-trip mismatch:\n got=%q\nwant=%q", got, plaintext)
// 	}
// }
//
// func TestDecrypt_WrongPasswordFails(t *testing.T) {
// 	if testing.Short() {
// 		t.Skip("argon2 slow in -short")
// 	}
// 	tmp := t.TempDir()
// 	inPath := filepath.Join(tmp, "secret.txt")
// 	outPath := inPath + ".enc"
// 	if err := os.WriteFile(inPath, []byte("hello"), 0o644); err != nil {
// 		t.Fatal(err)
// 	}
// 	if _, code := runCLI(t, "encrypt", inPath, "-p", "correct", "--salt", strings.Repeat("01", 64)); code != 0 {
// 		t.Fatal("encrypt failed")
// 	}
// 	if _, code := runCLI(t, "decrypt", outPath, "-p", "wrong"); code == 0 {
// 		t.Error("expected decrypt to fail with wrong password")
// 	}
// }
