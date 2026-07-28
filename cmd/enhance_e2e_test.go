package cmd

import (
	"strings"
	"testing"
)

// End-to-end tests for the enhance CLI command (password-to-key).
//
// enhance output is deterministic (same password + salt suffix → same key), so
// these tests assert against golden vectors captured from the reference
// implementation, proving end-to-end byte-level compatibility with the web tool.
// Vectors come from internal/testvectors/domain-key-vectors.json.

// extractKeyHex pulls the hex key value out of the "Key (hex):" line.
func extractKeyHex(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Key (hex):") {
			// "Key (hex):    <64 hex chars>"
			return strings.TrimSpace(strings.TrimPrefix(line, "Key (hex):"))
		}
	}
	t.Fatalf("no Key (hex) line in output:\n%s", out)
	return ""
}

func TestEnhanceCmd_DefaultDomain_GoldenVector(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	// Golden vector: password=weakpass, no suffix, default-v1 domain.
	const wantHex = "6b5e4099abfaa82d246ee9207665740cb813be93488b14b2ff4f7e8abc139e06"

	out, code := runCLI(t, "enhance", "-p", "weakpass")
	if code != 0 {
		t.Fatalf("enhance failed: %s", out)
	}
	got := extractKeyHex(t, out)
	if got != wantHex {
		t.Fatalf("enhance(weakpass) key mismatch:\n got: %s\nwant: %s", got, wantHex)
	}

	// Default domain must be reported.
	if !strings.Contains(out, "Domain:   default-v1") {
		t.Errorf("expected default domain, output:\n%s", out)
	}
	// 256-bit key → 64 hex chars.
	if len(got) != 64 {
		t.Errorf("expected 64-char hex key, got %d", len(got))
	}
	// No salt suffix line when -s is omitted.
	if strings.Contains(out, "Salt suffix:") {
		t.Errorf("Salt suffix line should be absent when -s omitted, output:\n%s", out)
	}
}

func TestEnhanceCmd_WithSaltSuffix_GoldenVector(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	// Golden vector: password=Str0ng!Pass#2, suffix=mysalt, default-v1.
	const wantHex = "a0e1dd425ae257de12d40f66e51ffe82578621a9c860c662264ef381ccf6463b"

	out, code := runCLI(t, "enhance", "-p", "Str0ng!Pass#2", "-s", "mysalt")
	if code != 0 {
		t.Fatalf("enhance failed: %s", out)
	}
	got := extractKeyHex(t, out)
	if got != wantHex {
		t.Fatalf("enhance key mismatch:\n got: %s\nwant: %s", got, wantHex)
	}
	if !strings.Contains(out, "Salt suffix: mysalt") {
		t.Errorf("expected salt suffix label, output:\n%s", out)
	}
}

func TestEnhanceCmd_CustomDomain_GoldenVector(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	// Golden vector: same inputs, different domain → different key (domain separation).
	const (
		pw          = "19980824@MyFirstPet@602"
		suffix      = "CustomSuffix123"
		ageWantHex  = "7cfd77bccffead2465662a54037d1be25025ec426ed3901329fa7898e19919ea"
		authWantHex = "2bae2db5f8cb9ddbb997b29598ba6e6bfa65390f689ca1c27388efee31717c81"
	)

	outAge, code := runCLI(t, "enhance", "-p", pw, "-s", suffix, "--domain", "age-key-v1")
	if code != 0 {
		t.Fatalf("enhance failed: %s", outAge)
	}
	if got := extractKeyHex(t, outAge); got != ageWantHex {
		t.Fatalf("age-key-v1 mismatch:\n got: %s\nwant: %s", got, ageWantHex)
	}

	outAuth, code := runCLI(t, "enhance", "-p", pw, "-s", suffix, "--domain", "auth-key-v1")
	if code != 0 {
		t.Fatalf("enhance failed: %s", outAuth)
	}
	if got := extractKeyHex(t, outAuth); got != authWantHex {
		t.Fatalf("auth-key-v1 mismatch:\n got: %s\nwant: %s", got, authWantHex)
	}

	// Different domains over the same inputs must produce different keys.
	if extractKeyHex(t, outAge) == extractKeyHex(t, outAuth) {
		t.Fatal("different domains produced the same key — domain separation broken")
	}
}

func TestEnhanceCmd_Deterministic(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	// Same inputs → identical key across runs.
	out1, _ := runCLI(t, "enhance", "-p", "testpass123", "-s", "suffix")
	out2, _ := runCLI(t, "enhance", "-p", "testpass123", "-s", "suffix")
	k1 := extractKeyHex(t, out1)
	k2 := extractKeyHex(t, out2)
	if k1 != k2 {
		t.Fatalf("enhance not deterministic:\n run1: %s\n run2: %s", k1, k2)
	}
}

func TestEnhanceCmd_DifferentSuffixDifferentKey(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	// Same password, different suffix → different key.
	out1, _ := runCLI(t, "enhance", "-p", "samepw", "-s", "google")
	out2, _ := runCLI(t, "enhance", "-p", "samepw", "-s", "firefox")
	k1 := extractKeyHex(t, out1)
	k2 := extractKeyHex(t, out2)
	if k1 == k2 {
		t.Fatalf("different suffixes produced the same key — suffix isolation broken")
	}
}

func TestEnhanceCmd_MissingPasswordFails(t *testing.T) {
	// -p is required; omitting it must exit non-zero.
	out, code := runCLI(t, "enhance")
	if code == 0 {
		t.Errorf("expected enhance to fail without -p, output:\n%s", out)
	}
}
