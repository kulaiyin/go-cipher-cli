package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-end tests for the secret-seal command, exercising the full encryption
// pipeline (age, AES-256-GCM, Shamir sharing, K1 derivation via argon2id, and
// fallback muscle-password recovery). All tests use real argon2id at production
// sizes (64 MiB / 3 passes), so they are skipped under -short.

const (
	ssTestK1         = "stormknickersreorderramrodoblongcaptivateunbeaten"
	ssTestMusclePw   = "i-remember-this-forever"
	ssTestSecretP    = "my-ultimate-secret-123"
	ssTestSecretP_CN = "\u6211\u7684\u7ec8\u6781\u5bc6\u7801-\u673a\u5bc6-123"
)

// ssSealArgs builds the base seal arguments.
func ssSealArgs(extra ...string) []string {
	base := []string{
		"secret-seal", "--mode", "encrypt",
		"--password", ssTestSecretP,
		"--muscle-password", ssTestMusclePw,
		"--k1", ssTestK1,
	}
	return append(base, extra...)
}

// ssUnsealArgs builds the base primary unseal arguments.
func ssUnsealArgs(extra ...string) []string {
	base := []string{
		"secret-seal", "--mode", "decrypt",
		"--k1", ssTestK1,
	}
	return append(base, extra...)
}

// --- Round-trip tests ---

func TestSecretSeal_RoundTrip_Primary(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	tmp := t.TempDir()
	vaultDir := filepath.Join(tmp, "vault")

	out, code := runCLI(t, ssSealArgs("--output", vaultDir)...)
	if code != 0 {
		t.Fatalf("seal failed: %s", out)
	}
	if !strings.Contains(out, "\u5c01\u5370") && !strings.Contains(out, "sealed") {
		t.Fatalf("expected success marker in output: %s", out)
	}
	verifyVaultFiles(t, vaultDir)

	out, code = runCLI(t, ssUnsealArgs("--input", vaultDir)...)
	if code != 0 {
		t.Fatalf("unseal failed: %s", out)
	}
	if !strings.Contains(out, ssTestSecretP) {
		t.Errorf("unseal output missing secret P\ngot: %s", out)
	}
}

func TestSecretSeal_RoundTrip_Fallback(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	tmp := t.TempDir()
	vaultDir := filepath.Join(tmp, "vault")

	out, code := runCLI(t, ssSealArgs("--output", vaultDir)...)
	if code != 0 {
		t.Fatalf("seal failed: %s", out)
	}

	out, code = runCLI(t,
		"secret-seal", "--mode", "decrypt",
		"--fallback",
		"--muscle-password", ssTestMusclePw,
		"--input", vaultDir)
	if code != 0 {
		t.Fatalf("fallback unseal failed: %s", out)
	}
	if !strings.Contains(out, ssTestSecretP) {
		t.Errorf("fallback unseal missing secret P\ngot: %s", out)
	}
}

func TestSecretSeal_RoundTrip_CJK(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	tmp := t.TempDir()
	vaultDir := filepath.Join(tmp, "vault")

	// Seal with CJK secret.
	out, code := runCLI(t, "secret-seal", "--mode", "encrypt",
		"--password", ssTestSecretP_CN,
		"--muscle-password", ssTestMusclePw,
		"--k1", ssTestK1,
		"--output", vaultDir)
	if code != 0 {
		t.Fatalf("seal CJK failed: %s", out)
	}

	out, code = runCLI(t, ssUnsealArgs("--input", vaultDir)...)
	if code != 0 {
		t.Fatalf("unseal CJK failed: %s", out)
	}
	if !strings.Contains(out, ssTestSecretP_CN) {
		t.Errorf("unseal CJK missing secret P\ngot: %s", out)
	}
}

// --- Error cases ---

func TestSecretSeal_WrongK1_Fails(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	tmp := t.TempDir()
	vaultDir := filepath.Join(tmp, "vault")

	out, code := runCLI(t, ssSealArgs("--output", vaultDir)...)
	if code != 0 {
		t.Fatalf("seal failed: %s", out)
	}

	out, code = runCLI(t, "secret-seal", "--mode", "decrypt",
		"--k1", "wrong-diceware-phrase-here-now",
		"--input", vaultDir)
	if code == 0 {
		t.Fatalf("expected unseal with wrong K1 to fail, got: %s", out)
	}
}

func TestSecretSeal_WrongMusclePassword_Fails(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	tmp := t.TempDir()
	vaultDir := filepath.Join(tmp, "vault")

	out, code := runCLI(t, ssSealArgs("--output", vaultDir)...)
	if code != 0 {
		t.Fatalf("seal failed: %s", out)
	}

	out, code = runCLI(t, "secret-seal", "--mode", "decrypt",
		"--fallback",
		"--muscle-password", "wrong-muscle-pw",
		"--input", vaultDir)
	if code == 0 {
		t.Fatalf("expected fallback unseal with wrong muscle pw to fail, got: %s", out)
	}
}

// --- Shamir resilience ---

func TestSecretSeal_ShamirThreeOfFive(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	tmp := t.TempDir()
	vaultDir := filepath.Join(tmp, "vault")

	out, code := runCLI(t, ssSealArgs("--output", vaultDir)...)
	if code != 0 {
		t.Fatalf("seal failed: %s", out)
	}

	// Delete 2 shares — should still recover with remaining 3.
	sharesDir := filepath.Join(vaultDir, "shares")
	os.Remove(filepath.Join(sharesDir, "share-1.dat"))
	os.Remove(filepath.Join(sharesDir, "share-2.dat"))

	out, code = runCLI(t, ssUnsealArgs("--input", vaultDir)...)
	if code != 0 {
		t.Fatalf("unseal with 3/5 shares failed: %s", out)
	}
	if !strings.Contains(out, ssTestSecretP) {
		t.Errorf("unseal missing secret P after share deletion\ngot: %s", out)
	}
}

func TestSecretSeal_ShamirInsufficientShares_Fails(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	tmp := t.TempDir()
	vaultDir := filepath.Join(tmp, "vault")

	out, code := runCLI(t, ssSealArgs("--output", vaultDir)...)
	if code != 0 {
		t.Fatalf("seal failed: %s", out)
	}

	// Delete 3 shares — only 2 left, below threshold.
	sharesDir := filepath.Join(vaultDir, "shares")
	os.Remove(filepath.Join(sharesDir, "share-1.dat"))
	os.Remove(filepath.Join(sharesDir, "share-2.dat"))
	os.Remove(filepath.Join(sharesDir, "share-3.dat"))

	out, code = runCLI(t, ssUnsealArgs("--input", vaultDir)...)
	if code == 0 {
		t.Fatalf("expected unseal with 2/5 shares to fail, got: %s", out)
	}
}

// --- Missing/bad arguments (non-interactive) ---

func TestSecretSeal_MissingMode_Fails(t *testing.T) {
	out, code := runCLI(t, "secret-seal", "--k1", ssTestK1)
	if code == 0 {
		t.Fatalf("expected missing --mode to fail, got: %s", out)
	}
}

func TestSecretSeal_InvalidMode_Fails(t *testing.T) {
	out, code := runCLI(t, "secret-seal", "--mode", "bogus",
		"--k1", ssTestK1)
	if code == 0 {
		t.Fatalf("expected invalid --mode to fail, got: %s", out)
	}
}

func TestSecretSeal_SealMissingPassword_Fails(t *testing.T) {
	out, code := runCLI(t, "secret-seal", "--mode", "encrypt",
		"--muscle-password", ssTestMusclePw,
		"--k1", ssTestK1)
	if code == 0 {
		t.Fatalf("expected seal without --password to fail, got: %s", out)
	}
}

func TestSecretSeal_SealMissingMusclePw_Fails(t *testing.T) {
	out, code := runCLI(t, "secret-seal", "--mode", "encrypt",
		"--password", ssTestSecretP,
		"--k1", ssTestK1)
	if code == 0 {
		t.Fatalf("expected seal without --muscle-password to fail, got: %s", out)
	}
}

func TestSecretSeal_UnsealMissingInput_Fails(t *testing.T) {
	out, code := runCLI(t, "secret-seal", "--mode", "decrypt",
		"--k1", ssTestK1)
	if code == 0 {
		t.Fatalf("expected unseal without --input to fail, got: %s", out)
	}
}

func TestSecretSeal_UnsealMissingK1_Fails(t *testing.T) {
	out, code := runCLI(t, "secret-seal", "--mode", "decrypt",
		"--input", "/nonexistent")
	if code == 0 {
		t.Fatalf("expected unseal without --k1 to fail, got: %s", out)
	}
}

func TestSecretSeal_FallbackMissingMusclePw_Fails(t *testing.T) {
	out, code := runCLI(t, "secret-seal", "--mode", "decrypt",
		"--fallback",
		"--input", "/nonexistent")
	if code == 0 {
		t.Fatalf("expected fallback unseal without --muscle-password to fail, got: %s", out)
	}
}

// --- Tamper resistance ---

func TestSecretSeal_TamperedEncryptD_Fails(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	tmp := t.TempDir()
	vaultDir := filepath.Join(tmp, "vault")

	out, code := runCLI(t, ssSealArgs("--output", vaultDir)...)
	if code != 0 {
		t.Fatalf("seal failed: %s", out)
	}

	// Overwrite encrypt-d.dat with garbage.
	os.WriteFile(filepath.Join(vaultDir, "encrypt-d.dat"), []byte("tampered!"), 0600)

	out, code = runCLI(t, ssUnsealArgs("--input", vaultDir)...)
	if code == 0 {
		t.Fatalf("expected unseal with tampered encrypt-d.dat to fail, got: %s", out)
	}
}

func TestSecretSeal_TamperedEncryptK_Fails_Fallback(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	tmp := t.TempDir()
	vaultDir := filepath.Join(tmp, "vault")

	out, code := runCLI(t, ssSealArgs("--output", vaultDir)...)
	if code != 0 {
		t.Fatalf("seal failed: %s", out)
	}

	// Overwrite encrypt-k.dat — breaks the fallback path.
	os.WriteFile(filepath.Join(vaultDir, "encrypt-k.dat"), []byte("tampered!"), 0600)

	out, code = runCLI(t, "secret-seal", "--mode", "decrypt",
		"--fallback",
		"--muscle-password", ssTestMusclePw,
		"--input", vaultDir)
	if code == 0 {
		t.Fatalf("expected fallback unseal with tampered encrypt-k.dat to fail, got: %s", out)
	}
}

func TestSecretSeal_TamperedShare_Fails(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	tmp := t.TempDir()
	vaultDir := filepath.Join(tmp, "vault")

	out, code := runCLI(t, ssSealArgs("--output", vaultDir)...)
	if code != 0 {
		t.Fatalf("seal failed: %s", out)
	}

	// Tamper with share-3.dat — but shares 1,2,4,5 are still good, so
	// reconstruction should still succeed (3-of-5, tampered share skipped).
	os.WriteFile(filepath.Join(vaultDir, "shares", "share-3.dat"), []byte("tampered!"), 0600)

	out, code = runCLI(t, ssUnsealArgs("--input", vaultDir)...)
	if code != 0 {
		t.Fatalf("unseal with 1/5 tampered share should still work (4 good shares): %s", out)
	}
	if !strings.Contains(out, ssTestSecretP) {
		t.Errorf("unseal missing secret P after single share tamper\ngot: %s", out)
	}
}

func TestSecretSeal_TamperedThreeShares_Fails(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	tmp := t.TempDir()
	vaultDir := filepath.Join(tmp, "vault")

	out, code := runCLI(t, ssSealArgs("--output", vaultDir)...)
	if code != 0 {
		t.Fatalf("seal failed: %s", out)
	}

	// Tamper 3 shares — only 2 good left, below threshold.
	sharesDir := filepath.Join(vaultDir, "shares")
	os.WriteFile(filepath.Join(sharesDir, "share-1.dat"), []byte("tampered!"), 0600)
	os.WriteFile(filepath.Join(sharesDir, "share-2.dat"), []byte("tampered!"), 0600)
	os.WriteFile(filepath.Join(sharesDir, "share-3.dat"), []byte("tampered!"), 0600)

	out, code = runCLI(t, ssUnsealArgs("--input", vaultDir)...)
	if code == 0 {
		t.Fatalf("expected unseal with only 2/5 good shares to fail, got: %s", out)
	}
}

// --- Helpers ---

func verifyVaultFiles(t *testing.T, vaultDir string) {
	t.Helper()

	// Check encrypt-d.dat exists and is non-empty.
	ed := filepath.Join(vaultDir, "encrypt-d.dat")
	if info, err := os.Stat(ed); err != nil || info.Size() == 0 {
		t.Errorf("encrypt-d.dat missing or empty: err=%v, size=%d", err, info.Size())
	}

	// Check encrypt-k.dat exists and is non-empty.
	ek := filepath.Join(vaultDir, "encrypt-k.dat")
	if info, err := os.Stat(ek); err != nil || info.Size() == 0 {
		t.Errorf("encrypt-k.dat missing or empty: err=%v, size=%d", err, info.Size())
	}

	// Check all 5 share files exist and are non-empty.
	sharesDir := filepath.Join(vaultDir, "shares")
	for i := 1; i <= 5; i++ {
		sf := filepath.Join(sharesDir, "share-"+string(rune('0'+i))+".dat")
		if info, err := os.Stat(sf); err != nil || info.Size() == 0 {
			t.Errorf("share-%d.dat missing or empty: err=%v, size=%d", i, err, info.Size())
		}
	}
}
