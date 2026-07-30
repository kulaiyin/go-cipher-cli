package cmd

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-end tests for the `data-cipher` command, exercising the full pipeline
// (zip bundle -> AES-GCM -> dual HMAC integrity -> tamper trap).
//
// These use real argon2id at production sizes (32MiB assemble key, plus the AES
// pipeline's argon2 strengthening), so they are skipped under -short.

// Strong keys (128-hex each, same set used by the assemblePackageKey golden vector).
var dcKeys = []string{
	"bf804aed3db8eb96c3d7b23eef691732e8f12fdaef7ea3cae1e698e4fdd9ffba0c0b8a1bcc46517e52378f52423024abab606023df7d000d87e063c98be3ec25",
	"9c739f0e46366a83a9d835c0501c1117486cda418e48c7fda36dd186dc0c4564efca3ce8b9dc64fa1f1e4a752398daf9bb2d51f4f592efe0008c82543661d2ae",
	"5bf83dd741d8a7206df9deefcb1dbec97a4c7172536222b615ee58c473dd750ac740fcf77cd34a29800e33ded1ebcb9a2a4e988278c0d241b3c273274fa1f3eb",
}
var dcPassword1 = "P@ssw0rd-Strong-1!"

func dcArgs(file string, extra ...string) []string {
	args := []string{"data-cipher"}
	if file != "" {
		args = append(args, file)
	}
	args = append(args, "-p", dcKeys[0], "-p", dcKeys[1], "-p", dcKeys[2], "-p", dcPassword1)
	return append(args, extra...)
}

func TestDataCipher_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	tmp := t.TempDir()
	in := filepath.Join(tmp, "secret.txt")
	plain := []byte("top secret payload with CJK \u4e2d\u6587 and emoji \U0001F510")
	if err := os.WriteFile(in, plain, 0o644); err != nil {
		t.Fatal(err)
	}
	encZip := filepath.Join(tmp, "out.zip")
	if out, code := runCLI(t, dcArgs(in, "--mode", "encrypt", "-o", encZip, "--hint", "my hint")...); code != 0 {
		t.Fatalf("encrypt failed: %s", out)
	}
	// The produced file must be a web-style zip.
	zipBytes, err := os.ReadFile(encZip)
	if err != nil {
		t.Fatal(err)
	}
	if !(len(zipBytes) > 4 && zipBytes[0] == 'P' && zipBytes[1] == 'K') {
		t.Fatalf("output is not a zip: %x...", zipBytes[:8])
	}
	dec := filepath.Join(tmp, "restored.txt")
	if out, code := runCLI(t, dcArgs(encZip, "--mode", "decrypt", "-o", dec)...); code != 0 {
		t.Fatalf("decrypt failed: %s", out)
	}
	got, err := os.ReadFile(dec)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(got) != string(plain) {
		t.Errorf("round-trip mismatch:\n got=%q\nwant=%q", got, plain)
	}
}

func TestDataCipher_WrongPasswordFails(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	tmp := t.TempDir()
	in := filepath.Join(tmp, "secret.txt")
	if err := os.WriteFile(in, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	encZip := filepath.Join(tmp, "out.zip")
	if out, code := runCLI(t, dcArgs(in, "--mode", "encrypt", "-o", encZip)...); code != 0 {
		t.Fatalf("encrypt failed: %s", out)
	}
	// Decrypt with a wrong password1 that still passes the composite check
	// (letter + digit + special, >=8) so we exercise the GCM auth-failure path,
	// not the pre-decrypt validateKeys gate.
	if out, code := runCLI(t, "data-cipher", encZip, "--mode", "decrypt",
		"-p", dcKeys[0], "-p", dcKeys[1], "-p", dcKeys[2], "-p", "WRONG-password-9!"); code == 0 {
		t.Fatalf("decrypt with wrong password unexpectedly succeeded: %s", out)
	}
}

func TestDataCipher_TamperedMetaDetected(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	tmp := t.TempDir()
	in := filepath.Join(tmp, "secret.txt")
	if err := os.WriteFile(in, []byte("tamper-target"), 0o644); err != nil {
		t.Fatal(err)
	}
	encZip := filepath.Join(tmp, "out.zip")
	if out, code := runCLI(t, dcArgs(in, "--mode", "encrypt", "-o", encZip)...); code != 0 {
		t.Fatalf("encrypt failed: %s", out)
	}
	// Re-zip with a tampered sha256 in meta-data.json -> integrity check fails.
	if err := rebuildZipWithTamperedSha(encZip, "deadbeef"); err != nil {
		t.Fatal(err)
	}
	if out, code := runCLI(t, dcArgs(encZip, "--mode", "decrypt")...); code == 0 {
		t.Fatalf("decrypt of tampered file unexpectedly succeeded: %s", out)
	} else if !strings.Contains(out, "integrity") {
		t.Fatalf("expected integrity error, got: %s", out)
	}
}

func TestDataCipher_NotAZip(t *testing.T) {
	tmp := t.TempDir()
	fake := filepath.Join(tmp, "fake.zip")
	if err := os.WriteFile(fake, []byte("not a zip at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := runCLI(t, dcArgs(fake, "--mode", "decrypt")...); code == 0 {
		t.Fatalf("expected failure on non-zip, got: %s", out)
	}
}

// TestDataCipher_MissingModeNonInteractiveFails verifies that when --mode is
// omitted in a non-interactive (piped stdin) context, the command does NOT
// silently default to encrypt; it requires an explicit mode (the user must
// choose encrypt vs decrypt — there is no default).
func TestDataCipher_MissingModeNonInteractiveFails(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "secret.txt")
	if err := os.WriteFile(in, []byte("default-mode data"), 0o644); err != nil {
		t.Fatal(err)
	}
	// dcArgs does NOT include --mode; stdin is a pipe (non-TTY) under `go test`.
	out, code := runCLI(t, dcArgs(in, "-o", filepath.Join(tmp, "out.zip"))...)
	if code == 0 {
		t.Fatalf("missing --mode should require explicit selection, got success: %s", out)
	}
}

// TestDataCipher_InvalidModeFails verifies an explicit invalid --mode value is
// rejected (the interactive/default path only applies to an empty value).
func TestDataCipher_InvalidModeFails(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "secret.txt")
	if err := os.WriteFile(in, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := runCLI(t, dcArgs(in, "--mode", "bogus")...); code == 0 {
		t.Fatalf("expected invalid-mode failure, got: %s", out)
	}
}

// TestDataCipher_NoArgNonInteractiveFails verifies that running with no
// positional argument in a non-interactive (piped stdin) context reports
// input_required rather than entering an unusable interactive prompt. In a real
// TTY the command would instead prompt for the file path.
func TestDataCipher_NoArgNonInteractiveFails(t *testing.T) {
	if out, code := runCLI(t, "data-cipher", "-p", dcKeys[0]); code == 0 {
		t.Fatalf("expected input-required failure, got: %s", out)
	}
}

func TestDataCipher_TooFewPasswordsFails(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "secret.txt")
	if err := os.WriteFile(in, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := runCLI(t, "data-cipher", in, "--mode", "encrypt",
		"-p", dcKeys[0], "-p", dcKeys[1], "-p", dcKeys[2]); code == 0 {
		t.Fatalf("expected too-few-passwords failure, got: %s", out)
	}
}

// TestDataCipher_TextInputRoundTrip verifies encrypting text via --text and
// --input-type text, then decrypting the produced zip back to the original text.
func TestDataCipher_TextInputRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	tmp := t.TempDir()
	plain := "text-mode secret with CJK \u4e2d\u6587 and emoji \U0001F510"
	encZip := filepath.Join(tmp, "text-out.zip")
	// Encrypt text content directly (no input file).
	if out, code := runCLI(t, dcArgs("", "--mode", "encrypt",
		"--input-type", "text", "--text", plain, "-o", encZip)...); code != 0 {
		t.Fatalf("encrypt text failed: %s", out)
	}
	dec := filepath.Join(tmp, "restored.txt")
	if out, code := runCLI(t, dcArgs(encZip, "--mode", "decrypt", "-o", dec)...); code != 0 {
		t.Fatalf("decrypt failed: %s", out)
	}
	got, err := os.ReadFile(dec)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(got) != plain {
		t.Errorf("text round-trip mismatch:\n got=%q\nwant=%q", got, plain)
	}
}

// TestDataCipher_TextInputNonInteractiveMissingText verifies that
// --input-type text without --text (and non-interactive) fails rather than
// prompting.
func TestDataCipher_TextInputNonInteractiveMissingText(t *testing.T) {
	if out, code := runCLI(t, dcArgs("", "--mode", "encrypt", "--input-type", "text")...); code == 0 {
		t.Fatalf("expected text-required failure, got: %s", out)
	}
}

// TestDataCipher_DecryptRejectsTextInputType verifies decrypt only allows file.
func TestDataCipher_DecryptRejectsTextInputType(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "secret.txt")
	if err := os.WriteFile(in, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := runCLI(t, dcArgs(in, "--mode", "decrypt", "--input-type", "text")...); code == 0 {
		t.Fatalf("expected decrypt-file-only failure, got: %s", out)
	}
}

// TestDataCipher_InvalidInputTypeFails verifies an invalid --input-type value.
func TestDataCipher_InvalidInputTypeFails(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "secret.txt")
	if err := os.WriteFile(in, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := runCLI(t, dcArgs(in, "--mode", "encrypt", "--input-type", "bogus")...); code == 0 {
		t.Fatalf("expected invalid-input-type failure, got: %s", out)
	}
}

// TestDataCipher_WeakKeyRejected verifies that a non-high-strength key (mirrors
// the web tool's validateKey: DataEncryptionForm.vue:744-746) is refused before
// encryption, even when supplied via -p (non-interactive). This locks the
// validation so the CLI never produces a file the web tool would refuse.
func TestDataCipher_WeakKeyRejected(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "secret.txt")
	if err := os.WriteFile(in, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	// key1 is far too short / not 128-hex -> must be rejected.
	weakKey := "tooweak"
	args := []string{"data-cipher", in, "--mode", "encrypt",
		"-p", weakKey, "-p", dcKeys[1], "-p", dcKeys[2], "-p", dcPassword1}
	if out, code := runCLI(t, args...); code == 0 {
		t.Fatalf("expected weak-key rejection, got success: %s", out)
	}
}

// TestDataCipher_WeakPassword1Rejected verifies that a password1 failing the
// composite rule (DataEncryptionForm.vue:756-758: not high strength AND not
// letter+digit+special with len>=8) is refused.
func TestDataCipher_WeakPassword1Rejected(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "secret.txt")
	if err := os.WriteFile(in, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	// "abcdefg" is >=7 chars but <8 AND lacks digit/special -> rejected.
	args := []string{"data-cipher", in, "--mode", "encrypt",
		"-p", dcKeys[0], "-p", dcKeys[1], "-p", dcKeys[2], "-p", "abcdefg"}
	if out, code := runCLI(t, args...); code == 0 {
		t.Fatalf("expected weak-password1 rejection, got success: %s", out)
	}
}

// rebuildZipWithTamperedSha rewrites the bundle's meta-data.json with a changed
// sha256, leaving the .bin untouched, so the SHA-256 integrity check must fail.
func rebuildZipWithTamperedSha(zipPath, fakeSha string) error {
	data, err := os.ReadFile(zipPath)
	if err != nil {
		return err
	}
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	var bin, meta []byte
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		if f.Name == "encrypted-data.bin" {
			bin = b
		}
		if f.Name == "meta-data.json" {
			meta = b
		}
	}
	// Replace the sha256 value inside meta-data.json.
	metaStr := string(meta)
	idx := strings.Index(metaStr, "\"sha256\":")
	if idx < 0 {
		return errTamper
	}
	// crude value replacement between the first quotes after the key.
	start := idx + len("\"sha256\":")
	q1 := strings.Index(metaStr[start:], "\"") + start
	q2 := strings.Index(metaStr[q1+1:], "\"") + q1 + 1
	newMeta := metaStr[:q1+1] + fakeSha + metaStr[q2:]
	return writeBundle(zipPath, bin, []byte(newMeta))
}

var errTamper = &tamperErr{}

type tamperErr struct{}

func (*tamperErr) Error() string { return "tamper rebuild failed" }

func writeBundle(path string, bin, meta []byte) error {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range []struct {
		name string
		data []byte
	}{
		{"encrypted-data.bin", bin},
		{"meta-data.json", meta},
	} {
		fw, err := w.Create(e.name)
		if err != nil {
			return err
		}
		if _, err := fw.Write(e.data); err != nil {
			return err
		}
	}
	if err := w.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}
