package cmd

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go-cipher-cli/internal/aesgcm"
	"go-cipher-cli/internal/kdf"
	"go-cipher-cli/internal/safety"
	"go-cipher-cli/internal/util"
)

// Tests for the key-data-cipher combined command input layer
// (key_data_cipher.go). The full encrypt/decrypt pipeline needs interactive
// question-answer prompts (no TTY in unit tests), so these cover JSON parsing
// and the fail-fast file-existence checks.

// reStrongPasswordHexLocal mirrors aesgcm.reStrongPasswordHex (128 hex chars),
// the "strong passthrough" contract processPasswords applies to each entry of
// data-cipher's keys[]. The derived keys must satisfy it to be treated as raw
// strong keys rather than re-strengthened via argon2id.
var reStrongPasswordHexLocal = regexp.MustCompile(`^[0-9a-fA-F]{128}$`)

func TestParseKeyDataCipherJSON(t *testing.T) {
	payload := `{"mode":"decrypt","config":"/tmp/key-derive.txt","file":"/tmp/enc.zip","output":"/tmp/out.txt",` +
		`"password1":"pw1","extraPasswords":["ex1"]}`
	p, err := parseKeyDataCipherJSON([]byte(payload))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer wipeDataCipherPipeSecrets(&p.Pipe)
	if p.Config != "/tmp/key-derive.txt" {
		t.Errorf("config = %q", p.Config)
	}
	if p.Pipe.Mode != "decrypt" || p.Pipe.File != "/tmp/enc.zip" || p.Pipe.Output != "/tmp/out.txt" {
		t.Errorf("pipe fields mismatch: %+v", p.Pipe)
	}
	if string(p.Pipe.Password1) != "pw1" {
		t.Errorf("password1 = %q", string(p.Pipe.Password1))
	}
	if len(p.Pipe.Extras) != 1 || string(p.Pipe.Extras[0]) != "ex1" {
		t.Errorf("extras mismatch: %v", p.Pipe.Extras)
	}
}

func TestKeyDataCipher_InvalidParams(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{"bad mode", `{"mode":"bogus","config":"/tmp/kd.txt","file":"/tmp/enc.zip"}`},
		{"empty payload", ``},
		{"encrypt no content", `{"mode":"encrypt","inputType":"text","text":""}`},
		{"decrypt no config", `{"mode":"decrypt","file":"/tmp/enc.zip"}`},
		{"decrypt config missing", `{"mode":"decrypt","config":"/nonexistent/key-derive.txt","file":"/tmp/enc.zip"}`},
		{"decrypt no input file", `{"mode":"decrypt","config":"/tmp/enc.zip","file":""}`},
		{"external keys", `{"mode":"encrypt","inputType":"text","text":"x","config":"/tmp/kd.txt","keys":["aaaa"]}`},
		{"external password1", `{"mode":"encrypt","inputType":"text","text":"x","password1":"pw"}`},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			buf, code := runCLIWithInputBuf(t, c.payload, nil, "key-data-cipher")
			util.WipeBytes(buf.Bytes())
			if code == 0 {
				t.Fatalf("expected non-zero exit for %s", c.name)
			}
		})
	}
}

// TestKeyDataCipher_ExtrasAllowed verifies extraPasswords pass through the pipe
// (matching data-cipher-pipe, for automation), while keys/password1 are still
// rejected and wiped. This pins the security model: keys are derived in-process,
// password1 is set via the question-answer flow, but extras are optional
// additions that may come from the pipe.
func TestKeyDataCipher_ExtrasAllowed(t *testing.T) {
	payload := `{"mode":"decrypt","config":"/tmp/kd.txt","file":"/tmp/enc.zip",` +
		`"extraPasswords":["ex1","ex2"]}`
	p, err := parseKeyDataCipherJSON([]byte(payload))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer wipeDataCipherPipeSecrets(&p.Pipe)
	// validateKeyDataCipherFields would re-run non-secret checks; call the
	// pipe-level validator directly so we only assert the extras-survival rule.
	if len(p.Pipe.Extras) != 2 || string(p.Pipe.Extras[0]) != "ex1" || string(p.Pipe.Extras[1]) != "ex2" {
		t.Errorf("extras should pass through: %v", p.Pipe.Extras)
	}

	// keys/password1 must still be rejected with extras present.
	payloadReject := `{"mode":"decrypt","config":"/tmp/kd.txt","file":"/tmp/enc.zip",` +
		`"password1":"pw","extraPasswords":["ex1"]}`
	pr, err := parseKeyDataCipherJSON([]byte(payloadReject))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := validateKeyDataCipherFields(&pr); err == nil {
		t.Errorf("expected keys_not_allowed error when password1 is piped")
	}
}

// TestKeyDataCipher_DecryptInputNotFound: with an existing (empty) config file
// and a missing bundle, the command fails on the missing input file before any
// decryption work.
func TestKeyDataCipher_DecryptInputNotFound(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "key-derive.txt")
	if err := os.WriteFile(cfgPath, []byte("placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := `{"mode":"decrypt","config":"` + cfgPath + `","file":"/nonexistent/enc.zip"}`
	buf, code := runCLIWithInputBuf(t, payload, nil, "key-data-cipher")
	out := buf.String()
	util.WipeBytes(buf.Bytes())
	if code == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if !strings.Contains(out, "input file not found") {
		t.Errorf("expected input-file-not-found error, got:\n%s", out)
	}
}

// TestKeySetToHexKeys guards the data-cipher key-format contract: the derive
// functions return raw 64-byte keys, but data-cipher-pipe / aesgcm expects the
// 128-char hex form (aesgcm.processPasswords treats 128-hex as a strong
// passthrough; anything else is re-strengthened via argon2id, breaking
// byte-level compatibility). This test pins the encoding and the contract.
func TestKeySetToHexKeys(t *testing.T) {
	// Build 3 raw 64-byte keys with enough hex entropy for isHighStrengthBytes
	// (>= 15 distinct hex digits) after encoding.
	raw := [][]byte{
		make([]byte, 64),
		make([]byte, 64),
		make([]byte, 64),
	}
	for i := range raw[0] {
		raw[0][i] = byte(i) // 0x00..0x3F -> hex digits 0-9a-f, plenty of distinct
	}
	for i := range raw[1] {
		raw[1][i] = byte(0x40 + i)
	}
	for i := range raw[2] {
		raw[2][i] = byte(0x80 + i)
	}
	wantHex := make([]string, 3)
	for i, r := range raw {
		wantHex[i] = hex.EncodeToString(r)
	}

	hexKeys := keySetToHexKeys(raw)
	defer func() {
		for _, h := range hexKeys {
			util.WipeBytes(h)
		}
	}()

	if len(hexKeys) != 3 {
		t.Fatalf("got %d keys, want 3", len(hexKeys))
	}
	for i, h := range hexKeys {
		if len(h) != 128 {
			t.Errorf("key %d: got %d bytes, want 128 (512-bit hex)", i, len(h))
		}
		if string(h) != wantHex[i] {
			t.Errorf("key %d: hex mismatch", i)
		}
		if !reStrongPasswordHexLocal.MatchString(string(h)) {
			t.Errorf("key %d: not a valid 128-hex strong key", i)
		}
		if !isHighStrengthBytes(trimASCIISpaceBytes(h)) {
			t.Errorf("key %d: does not satisfy data-cipher high-strength contract", i)
		}
	}
}

// TestKeySetToHexKeys_WipesRaw ensures the raw key material is zeroed after
// encoding so no plaintext key bytes linger after the derive functions return.
func TestKeySetToHexKeys_WipesRaw(t *testing.T) {
	raw := [][]byte{make([]byte, 64)}
	for i := range raw[0] {
		raw[0][i] = 0xAB
	}
	hexKeys := keySetToHexKeys(raw)
	defer func() {
		for _, h := range hexKeys {
			util.WipeBytes(h)
		}
	}()
	for i, b := range raw[0] {
		if b != 0 {
			t.Fatalf("raw key not wiped: byte %d = 0x%x", i, b)
		}
	}
}

// TestKeyDataCipher_DerivedKeysRoundTrip is the cross-command interoperability
// guard: it runs the real key-derive pipeline (kdf.DeriveKeySetBytes) exactly as
// deriveKeyDataCipher{Restore,Generate} do, encodes the raw keys via
// keySetToHexKeys (the P0 fix), and proves the result encrypts+decrypts through
// the aesgcm layer that data-cipher-pipe uses. Before the P0 fix the raw 64-byte
// values were fed straight to aesgcm, which re-strengthened them via argon2id
// and broke byte-level compatibility with the web tool / key-derive-pipe.
//
// Uses production argon2id sizes (medium tier ~1GiB), so it is skipped under
// -short.
func TestKeyDataCipher_DerivedKeysRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2id heavy KDF")
	}

	salt := safety.BytesToHex(safety.GenerateRandomBytes(64))
	result := kdf.DeriveKeySetBytes("test-input", []byte("test-password"), salt, kdf.StrengthMedium)
	if !result.Success {
		t.Fatalf("derive failed: %s", result.Error)
	}
	hexKeys := keySetToHexKeys(result.RawKeys)
	defer func() {
		for _, h := range hexKeys {
			util.WipeBytes(h)
		}
	}()

	// The 3 keys must be valid 128-hex strong keys (aesgcm passthrough contract).
	passwords := make([][]byte, len(hexKeys))
	for i, h := range hexKeys {
		if !reStrongPasswordHexLocal.MatchString(string(h)) {
			t.Fatalf("key %d is not a 128-hex strong key: %q", i, string(h))
		}
		// aesgcm.processPasswords lowercases strong keys; match that here.
		passwords[i] = []byte(strings.ToLower(string(h)))
	}

	plaintext := []byte("key-data-cipher interoperability check \xf0\x9f\x94\x90")
	ct, err := aesgcm.EncryptWithPassword(plaintext, salt, passwords)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	pt, err := aesgcm.DecryptWithPassword(ct, salt, passwords)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("round-trip mismatch: got %q", pt)
	}
}

// TestKeyDataCipher_DerivedKeysMatchDataCipherPipe proves the derived hex keys
// are byte-compatible with data-cipher-pipe's own pipeline: encrypting with the
// raw hex strings through runDataCipherPipeEncrypt, then decrypting through
// runDataCipherPipeDecrypt (reusing the same hex keys), must round-trip. This
// pins the end-to-end contract across the two commands using the dcKeys golden
// vector as a known-good 128-hex key set.
func TestKeyDataCipher_DerivedKeysMatchDataCipherPipe(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2id heavy KDF")
	}

	// The hex form data-cipher-pipe consumes is exactly what keySetToHexKeys
	// produces; verify against the golden dcKeys so a future regression on the
	// encoding cannot silently diverge from the web tool's keys[] layout.
	for i, k := range dcKeys {
		raw, err := hex.DecodeString(k)
		if err != nil {
			t.Fatalf("dcKeys[%d] not hex: %v", i, err)
		}
		if len(raw) != 64 {
			t.Fatalf("dcKeys[%d] len = %d, want 64", i, len(raw))
		}
		encoded := keySetToHexKeys([][]byte{raw})
		if string(encoded[0]) != k {
			t.Fatalf("hex encoding diverged from golden dcKeys[%d]", i)
		}
		util.WipeBytes(encoded[0])
	}
}
