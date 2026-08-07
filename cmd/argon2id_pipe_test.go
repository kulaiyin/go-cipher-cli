// Package cmd_test: independent os/exec tests for the argon2id command.
//
// These tests exercise the pipe-only interface: sensitive input (password +
// salt) arrives over stdin via --secrets-stdin and the derived key leaves via
// stdout as --json. Unlike the in-package e2e tests they build their own
// binary and use raw exec.Command directly (no runCLI wrapper, no shared
// TestMain), so stdout, stderr and the real exit code are captured separately.
package cmd_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	pipePassword = "TestPass!2026"
	pipeSaltHex  = "00112233445566778899aabbccddeeff"
	pipeWantKey  = "2afa7f5bf041cb89dd3386b80ec27f51036fa97e86822f2e08a3f4be8ff58a70"
)

var (
	pipeBinOnce sync.Once
	pipeBinPath string
	pipeBinErr  error
)

// pipeCLIBinary builds the CLI once into a temp dir, fully independent of the
// package-level TestMain binary.
func pipeCLIBinary() (string, error) {
	pipeBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "gocipher-pipe-bin-*")
		if err != nil {
			pipeBinErr = err
			return
		}
		pipeBinPath = filepath.Join(dir, "go-cipher-cli")
		root, err := os.Getwd()
		if err != nil {
			pipeBinErr = err
			return
		}
		cmd := exec.Command("go", "build", "-o", pipeBinPath, ".")
		cmd.Dir = filepath.Join(root, "..")
		if out, err := cmd.CombinedOutput(); err != nil {
			pipeBinErr = fmt.Errorf("build go-cipher-cli: %v\n%s", err, out)
		}
	})
	return pipeBinPath, pipeBinErr
}

type pipeResult struct {
	stdout string
	stderr string
	code   int
}

// runArgon2Pipe runs `argon2id <args>` with the given stdin via os/exec and
// returns stdout, stderr and the real exit code separately.
func runArgon2Pipe(t *testing.T, stdin string, args ...string) pipeResult {
	t.Helper()
	bin, err := pipeCLIBinary()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, append([]string{"argon2id"}, args...)...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err = cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else {
			code = -1
		}
	}
	return pipeResult{stdout: out.String(), stderr: errOut.String(), code: code}
}

func pipeJSONKey(t *testing.T, out string) string {
	t.Helper()
	var got struct {
		Success bool   `json:"success"`
		SaltHex string `json:"salt_hex"`
		KeyHex  string `json:"key_hex"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out)
	}
	if !got.Success {
		t.Fatalf("expected success=true:\n%s", out)
	}
	return got.KeyHex
}

func TestArgon2idPipe_GoldenVector(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	stdin := pipePassword + "\n" + pipeSaltHex + "\n"
	r := runArgon2Pipe(t, stdin, "--secrets-stdin", "--json",
		"--iterations", "2", "--memory", "8", "--key-length", "32")
	if r.code != 0 {
		t.Fatalf("argon2id exited %d:\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	if got := pipeJSONKey(t, r.stdout); got != pipeWantKey {
		t.Errorf("key_hex: got %q want %q", got, pipeWantKey)
	}
	if strings.Contains(r.stdout, pipePassword) {
		t.Errorf("stdout leaks the password:\n%s", r.stdout)
	}
	if r.stderr != "" {
		t.Errorf("expected empty stderr on piped --json run, got:\n%s", r.stderr)
	}
}

func TestArgon2idPipe_SingleLineEOF(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	// Password line only, no salt line: EOF is tolerated and a random salt is
	// drawn, so the run must still succeed and emit valid JSON.
	r := runArgon2Pipe(t, pipePassword+"\n", "--secrets-stdin", "--json",
		"--iterations", "2", "--memory", "8", "--key-length", "32")
	if r.code != 0 {
		t.Fatalf("argon2id exited %d:\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	pipeJSONKey(t, r.stdout)
}

func TestArgon2idPipe_SecretsStdinExclusive(t *testing.T) {
	// --secrets-stdin mixed with --salt must fail: the salt source stays
	// unambiguous (stdin line 2 vs. the flag).
	for _, args := range [][]string{
		{"--secrets-stdin", "--salt", pipeSaltHex},
	} {
		r := runArgon2Pipe(t, pipePassword+"\n"+pipeSaltHex+"\n", args...)
		if r.code == 0 {
			t.Errorf("--secrets-stdin mixed with %v must fail, got exit 0", args)
		}
		if r.stdout != "" {
			t.Errorf("--secrets-stdin conflict must not write to stdout, got:\n%s", r.stdout)
		}
		if strings.Contains(r.stdout, pipePassword) || strings.Contains(r.stderr, pipePassword) {
			t.Errorf("password leaked for %v:\nstdout: %s\nstderr: %s", args, r.stdout, r.stderr)
		}
	}
}

func TestArgon2idPipe_PasswordNotInArgv(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("cmdline inspection needs /proc")
	}
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	bin, err := pipeCLIBinary()
	if err != nil {
		t.Fatal(err)
	}
	// Slow config so the process stays alive long enough to read /proc.
	cmd := exec.Command(bin, "argon2id", "--secrets-stdin", "--json",
		"--iterations", "4", "--memory", "128")
	cmd.Stdin = strings.NewReader(pipePassword + "\n" + pipeSaltHex + "\n")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	deadline := time.Now().Add(2 * time.Second)
	var leaked bool
	var cmdline string
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			break
		}
		cmdline = string(raw)
		for _, field := range strings.Split(cmdline, "\x00") {
			if strings.Contains(field, pipePassword) {
				leaked = true
			}
		}
		if cmdline != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = cmd.Wait()
	if leaked {
		t.Fatalf("password present in process argv: %q", cmdline)
	}
	if cmdline != "" && !strings.Contains(cmdline, "--secrets-stdin") {
		t.Fatalf("unexpected argv: %q", cmdline)
	}
}
