package cmd

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"go-cipher-cli/internal/util"
	"go-cipher-cli/internal/validation"
)

// Tests for the key-derive-pipe input layer (key_derive_pipe.go). They drive the
// non-TTY path via withStdinPipe (its closed write end makes term.IsTerminal
// report false), and reuse the golden-vector constants from
// key_derive_e2e_test.go.

// withStdinPipe replaces os.Stdin with a pipe fed from payload, runs fn, then
// restores stdin. The write end is closed so the read end hits EOF and reads as
// a non-TTY.
func withStdinPipe(t *testing.T, payload string, fn func() error) error {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	// Write the payload and close the write end so the read end hits EOF.
	go func() {
		_, _ = w.Write([]byte(payload))
		_ = w.Close()
	}()

	origStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = origStdin }()
	return fn()
}

// TestRunKeyDerivePipe_GoldenVector: raw bytes hex-encode to the golden vector.
func TestRunKeyDerivePipe_GoldenVector(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	payload := `{"mode":"generate","input":"` + kdInput + `","password":"` + kdPassword + `","salt":"` + kdSalt + `","strength":"basic"}`

	var gotUUID, gotS1 string
	err := withStdinPipe(t, payload, func() error {
		r, err := runKeyDerivePipe()
		if err != nil {
			return err
		}
		defer wipeKeySetBytesResult(r)
		gotUUID = hex.EncodeToString(r.RawUUID)
		gotS1 = hex.EncodeToString(r.RawKeys[0])
		return nil
	})
	if err != nil {
		t.Fatalf("runKeyDerivePipe failed: %v", err)
	}
	if gotUUID != kdWantUUID {
		t.Errorf("UUID = %q, want %q", gotUUID, kdWantUUID)
	}
	if gotS1 != kdWantS1 {
		t.Errorf("S1 = %q, want %q", gotS1, kdWantS1)
	}
}

// TestRunKeyDerivePipe_RandomSaltDifferentKeys: no salt -> two runs differ.
func TestRunKeyDerivePipe_RandomSaltDifferentKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	payload := `{"mode":"generate","input":"` + kdInput + `","password":"` + kdPassword + `","strength":"basic"}`

	var s1First string
	err := withStdinPipe(t, payload, func() error {
		r, err := runKeyDerivePipe()
		if err != nil {
			return err
		}
		defer wipeKeySetBytesResult(r)
		s1First = hex.EncodeToString(r.RawKeys[0])
		return nil
	})
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	err = withStdinPipe(t, payload, func() error {
		r, err := runKeyDerivePipe()
		if err != nil {
			return err
		}
		defer wipeKeySetBytesResult(r)
		if hex.EncodeToString(r.RawKeys[0]) == s1First {
			t.Fatal("two runs without a salt produced the same key — random salt broken")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
}

// TestRunKeyDerivePipe_InvalidParams: bad inputs rejected before derivation.
func TestRunKeyDerivePipe_InvalidParams(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{
			name:    "bad mode",
			payload: `{"mode":"bogus","input":"` + kdInput + `","password":"` + kdPassword + `","strength":"basic"}`,
		},
		{
			name:    "short input",
			payload: `{"mode":"generate","input":"short","password":"` + kdPassword + `","strength":"basic"}`,
		},
		{
			name:    "weak password",
			payload: `{"mode":"generate","input":"` + kdInput + `","password":"weakpass","strength":"basic"}`,
		},
		{
			name:    "invalid salt hex",
			payload: `{"mode":"generate","input":"` + kdInput + `","password":"` + kdPassword + `","salt":"nothex","strength":"basic"}`,
		},
		{
			name:    "invalid strength",
			payload: `{"mode":"generate","input":"` + kdInput + `","password":"` + kdPassword + `","strength":"bogus"}`,
		},
		{
			name:    "restore without config",
			payload: `{"mode":"restore","input":"` + kdInput + `","password":"` + kdPassword + `"}`,
		},
		{
			name:    "generate with config",
			payload: `{"mode":"generate","input":"` + kdInput + `","password":"` + kdPassword + `","config":"/tmp/x.txt","strength":"basic"}`,
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			err := withStdinPipe(t, c.payload, func() error {
				_, err := runKeyDerivePipe()
				return err
			})
			if err == nil {
				t.Fatalf("expected error for %s", c.name)
			}
		})
	}
}

// TestRunKeyDerivePipe_Deterministic: same payload -> same keys.
func TestRunKeyDerivePipe_Deterministic(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	payload := `{"mode":"generate","input":"` + kdInput + `","password":"` + kdPassword + `","salt":"` + kdSalt + `","strength":"basic"}`

	var first string
	err := withStdinPipe(t, payload, func() error {
		r, err := runKeyDerivePipe()
		if err != nil {
			return err
		}
		defer wipeKeySetBytesResult(r)
		first = hex.EncodeToString(r.RawKeys[0])
		return nil
	})
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	err = withStdinPipe(t, payload, func() error {
		r, err := runKeyDerivePipe()
		if err != nil {
			return err
		}
		defer wipeKeySetBytesResult(r)
		got := hex.EncodeToString(r.RawKeys[0])
		if got != first {
			t.Fatalf("same inputs produced different keys:\n %s\n %s", first, got)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
}

// TestResolveKeyDerivePipePassword_JSONAsBytes: password pulled as []byte.
func TestResolveKeyDerivePipePassword_JSONAsBytes(t *testing.T) {
	pw, err := resolveKeyDerivePipePassword([]byte(`{"password":"` + kdPassword + `"}`))
	if err != nil {
		t.Fatalf("password field present but failed: %v", err)
	}
	defer util.WipeBytes(pw)
	if string(pw) != kdPassword {
		t.Errorf("password bytes = %q, want %q", string(pw), kdPassword)
	}
}

// TestResolveKeyDerivePipePassword_Missing: absent password resolves to nil so
// the caller can fall back to the interactive TTY flow.
func TestResolveKeyDerivePipePassword_Missing(t *testing.T) {
	pw, err := resolveKeyDerivePipePassword([]byte(`{"mode":"generate","input":"` + kdInput + `"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pw != nil {
		t.Errorf("expected nil password, got %q", pw)
	}
}

// TestResolveKeyDerivePipeParams_JSONPrecedence: each JSON field parsed.
func TestResolveKeyDerivePipeParams_JSONPrecedence(t *testing.T) {
	payload := `{"mode":"restore","input":"` + kdInput + `","salt":"` + kdSalt + `","hint":"myhint","strength":"advanced","config":"/tmp/c.txt","password":"` + kdPassword + `"}`
	err := withStdinPipe(t, payload, func() error {
		p, _, err := resolveKeyDerivePipeParams()
		if err != nil {
			return err
		}
		if p.Mode != "restore" {
			t.Errorf("mode = %q, want restore", p.Mode)
		}
		if p.Input != kdInput {
			t.Errorf("input = %q", p.Input)
		}
		if p.Salt != kdSalt {
			t.Errorf("salt = %q", p.Salt)
		}
		if p.Hint != "myhint" {
			t.Errorf("hint = %q", p.Hint)
		}
		if p.Strength != "advanced" {
			t.Errorf("strength = %q", p.Strength)
		}
		if p.Config != "/tmp/c.txt" {
			t.Errorf("config = %q", p.Config)
		}
		if string(p.Password) != kdPassword {
			t.Errorf("password = %q", string(p.Password))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("resolveKeyDerivePipeParams: %v", err)
	}
}

// TestValidatePasswordBytes: byte-based rules accept/reject as expected.
func TestValidatePasswordBytes(t *testing.T) {
	cases := []struct {
		name    string
		pw      string
		wantErr bool
	}{
		{name: "letter+digit+special", pw: "ProbePassword!2026", wantErr: false},
		{name: "too short", pw: "Ab1!", wantErr: true},
		{name: "no digit", pw: "Password!!!!", wantErr: true},
		{name: "no letter", pw: "12345678!", wantErr: true},
		{name: "no special", pw: "Password2026", wantErr: true},
		{name: "high strength 128-hex", pw: kdSalt, wantErr: false}, // 128 hex chars
		{name: "trimmed spaces ok", pw: "  ProbePassword!2026  ", wantErr: false},
		{name: "empty", pw: "", wantErr: true},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			err := validatePasswordBytes([]byte(c.pw))
			if c.wantErr && err == nil {
				t.Fatalf("expected error for %q", c.pw)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", c.pw, err)
			}
		})
	}
}

// TestValidatePasswordBytes_ParityWithString: byte version agrees with the
// string version (faithful, leak-free replacement).
func TestValidatePasswordBytes_ParityWithString(t *testing.T) {
	cases := []string{
		"ProbePassword!2026",
		"weakpass",
		"Ab1!",
		"Password2026", // no special
		kdSalt,         // 128 hex high-strength
		"abcdefgh",     // no digit/special
		"abcdefg1",     // no special
	}
	for _, c := range cases {
		c := c
		t.Run(c, func(t *testing.T) {
			errBytes := validatePasswordBytes([]byte(c))
			errString := validation.ValidateKeyDerivePassword(c)
			if (errBytes == nil) != (errString == nil) {
				t.Errorf("parity mismatch for %q: bytes_err=%v string_err=%v", c, errBytes, errString)
			}
		})
	}
}

// wipeKeySetBytesResult is defined in key_derive_pipe.go; reused by tests below.

// TestRunKeyDerivePipe_KeysIntactAtReturn: raw keys are intact at return, not
// pre-wiped by an over-eager defer (guards against zeroing the return value).
func TestRunKeyDerivePipe_KeysIntactAtReturn(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	payload := `{"mode":"generate","input":"` + kdInput + `","password":"` + kdPassword + `","salt":"` + kdSalt + `","strength":"basic"}`

	err := withStdinPipe(t, payload, func() error {
		r, err := runKeyDerivePipe()
		if err != nil {
			return err
		}
		defer wipeKeySetBytesResult(r)
		if !r.Success {
			return fmt.Errorf("derive failed: %s", r.Error)
		}
		// Each raw key must be non-zero (a 64-byte key is effectively never all
		// zero) and must hex-encode to the golden-vector S1.
		for i, k := range r.RawKeys {
			if len(k) != 64 {
				return fmt.Errorf("raw key %d length = %d, want 64", i, len(k))
			}
			if isAllZero(k) {
				return fmt.Errorf("raw key %d is all zero — was it pre-wiped?", i)
			}
		}
		if len(r.RawUUID) != 16 {
			return fmt.Errorf("raw UUID length = %d, want 16", len(r.RawUUID))
		}
		if isAllZero(r.RawUUID) {
			return fmt.Errorf("raw UUID is all zero — was it pre-wiped?")
		}
		if hex.EncodeToString(r.RawKeys[0]) != kdWantS1 {
			return fmt.Errorf("S1 = %q, want %q", hex.EncodeToString(r.RawKeys[0]), kdWantS1)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
