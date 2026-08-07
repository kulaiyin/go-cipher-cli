package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-cipher-cli/internal/util"
)

// Unit tests for the data-cipher-pipe input layer (data_cipher_pipe.go) plus an
// end-to-end round trip reusing the dcKeys/dcPassword1 constants.

func TestParseDataCipherPipeJSON(t *testing.T) {
	payload := `{"mode":"encrypt","inputType":"text","text":"hello world","salt":"s","hint":"h","output":"o",` +
		`"keys":["k1","k2","k3"],"password1":"pw1","extraPasswords":["ex1","ex2"]}`
	p, err := parseDataCipherPipeJSON([]byte(payload))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer wipeDataCipherPipeSecrets(&p)
	if p.Mode != "encrypt" || p.InputType != "text" || p.Text != "hello world" {
		t.Errorf("scalars mismatch: %+v", p)
	}
	if p.Salt != "s" || p.Hint != "h" || p.Output != "o" {
		t.Errorf("metadata mismatch: %+v", p)
	}
	if len(p.Keys) != 3 || string(p.Keys[0]) != "k1" || string(p.Keys[2]) != "k3" {
		t.Errorf("keys mismatch: %v", p.Keys)
	}
	if string(p.Password1) != "pw1" {
		t.Errorf("password1 mismatch: %q", p.Password1)
	}
	if len(p.Extras) != 2 || string(p.Extras[0]) != "ex1" || string(p.Extras[1]) != "ex2" {
		t.Errorf("extras mismatch: %v", p.Extras)
	}
}

func TestBuildDataCipherPipePasswordList(t *testing.T) {
	p := &dataCipherPipeParams{
		Keys:      [][]byte{[]byte("k1"), []byte("k2"), []byte("k3")},
		Password1: []byte("pw1"),
	}
	list := buildDataCipherPipePasswordList(p)
	if len(list) != 4 {
		t.Fatalf("without extra: len=%d, want 4", len(list))
	}
	for i, want := range []string{"k1", "k2", "k3", "pw1"} {
		if string(list[i]) != want {
			t.Errorf("entry %d = %q, want %q", i, list[i], want)
		}
	}

	p.Extras = [][]byte{[]byte("ex")}
	list2 := buildDataCipherPipePasswordList(p)
	if len(list2) != 5 || string(list2[4]) != "ex" {
		t.Fatalf("with extra: len=%d want=5 (last=%q)", len(list2), list2[len(list2)-1])
	}

	p.Extras = [][]byte{[]byte("ex1"), []byte("ex2")}
	list3 := buildDataCipherPipePasswordList(p)
	if len(list3) != 6 || string(list3[4]) != "ex1" || string(list3[5]) != "ex2" {
		t.Fatalf("two extras: len=%d, got %v", len(list3), list3)
	}
}

func TestValidateDataCipherPipeSecrets(t *testing.T) {
	good := &dataCipherPipeParams{
		Keys:      [][]byte{[]byte(dcKeys[0]), []byte(dcKeys[1]), []byte(dcKeys[2])},
		Password1: []byte(dcPassword1),
	}
	if err := validateDataCipherPipeSecrets(good); err != nil {
		t.Fatalf("good secrets rejected: %v", err)
	}

	weak := &dataCipherPipeParams{
		Keys:      [][]byte{[]byte("tooweak"), []byte(dcKeys[1]), []byte(dcKeys[2])},
		Password1: []byte(dcPassword1),
	}
	if err := validateDataCipherPipeSecrets(weak); err == nil {
		t.Fatal("weak key accepted")
	}

	shortPW := &dataCipherPipeParams{
		Keys:      [][]byte{[]byte(dcKeys[0]), []byte(dcKeys[1]), []byte(dcKeys[2])},
		Password1: []byte("Ab1!"),
	}
	if err := validateDataCipherPipeSecrets(shortPW); err == nil {
		t.Fatal("weak password1 accepted")
	}
}

// TestDataCipherPipe_KeysPipeRequired: the 3 strong keys can only come from the
// pipe; a JSON payload without all 3 fails fast with no interactive fallback.
func TestDataCipherPipe_KeysPipeRequired(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{
			name:    "no keys",
			payload: `{"mode":"encrypt","inputType":"text","text":"hello","password1":"` + dcPassword1 + `"}`,
		},
		{
			name:    "only two keys",
			payload: `{"mode":"encrypt","inputType":"text","text":"hello","keys":["` + dcKeys[0] + `","` + dcKeys[1] + `"],"password1":"` + dcPassword1 + `"}`,
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			buf, code := runCLIWithInputBuf(t, c.payload, nil, "data-cipher-pipe")
			out := buf.String()
			util.WipeBytes(buf.Bytes())
			if code == 0 {
				t.Fatalf("expected non-zero exit for %s", c.name)
			}
			if !strings.Contains(out, "pipe") {
				t.Errorf("expected error to mention the pipe, got:\n%s", out)
			}
		})
	}
}

// TestDataCipherPipe_RoundTrip encrypts text via piped JSON, then decrypts the
// produced bundle, asserting the plaintext round-trips. Uses real argon2id, so
// it is skipped under -short.
func TestDataCipherPipe_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	tmp := t.TempDir()
	encPath := filepath.Join(tmp, "enc.zip")
	decPath := filepath.Join(tmp, "dec.txt")
	plain := "pipe secret payload with CJK \u4e2d\u6587 and emoji \U0001F510"
	salt := kdSalt

	encPayload := `{"mode":"encrypt","inputType":"text","text":"` + plain + `","salt":"` + salt + `",` +
		`"keys":["` + dcKeys[0] + `","` + dcKeys[1] + `","` + dcKeys[2] + `"],"password1":"` + dcPassword1 + `","output":"` + encPath + `"}`
	buf, code := runCLIWithInputBuf(t, encPayload, nil, "data-cipher-pipe")
	defer util.WipeBytes(buf.Bytes())
	if code != 0 {
		t.Fatalf("encrypt failed: %s", buf.String())
	}

	decPayload := `{"mode":"decrypt","file":"` + encPath + `",` +
		`"keys":["` + dcKeys[0] + `","` + dcKeys[1] + `","` + dcKeys[2] + `"],"password1":"` + dcPassword1 + `","output":"` + decPath + `"}`
	buf2, code2 := runCLIWithInputBuf(t, decPayload, nil, "data-cipher-pipe")
	defer util.WipeBytes(buf2.Bytes())
	if code2 != 0 {
		t.Fatalf("decrypt failed: %s", buf2.String())
	}

	got, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(plain)) {
		t.Fatalf("round-trip mismatch:\n got %q\nwant %q", got, plain)
	}
}

// TestDataCipherPipe_RoundTripWithExtra verifies that an optional extra password
// used during encrypt must be repeated on decrypt (it participates in the key
// derivation), and that omitting it fails.
func TestDataCipherPipe_RoundTripWithExtra(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	tmp := t.TempDir()
	encPath := filepath.Join(tmp, "enc.zip")
	decPath := filepath.Join(tmp, "dec.txt")
	plain := "extra-password round trip"
	keys := `"keys":["` + dcKeys[0] + `","` + dcKeys[1] + `","` + dcKeys[2] + `"],"password1":"` + dcPassword1 + `"`

	encPayload := `{"mode":"encrypt","inputType":"text","text":"` + plain + `","salt":"` + kdSalt + `",` +
		keys + `,"extraPasswords":["extra-secret","second-extra"],"output":"` + encPath + `"}`
	buf, code := runCLIWithInputBuf(t, encPayload, nil, "data-cipher-pipe")
	defer util.WipeBytes(buf.Bytes())
	if code != 0 {
		t.Fatalf("encrypt failed: %s", buf.String())
	}

	// Decrypt WITH both extra passwords -> success.
	decOK := `{"mode":"decrypt","file":"` + encPath + `",` + keys + `,"extraPasswords":["extra-secret","second-extra"],"output":"` + decPath + `"}`
	buf2, code2 := runCLIWithInputBuf(t, decOK, nil, "data-cipher-pipe")
	defer util.WipeBytes(buf2.Bytes())
	if code2 != 0 {
		t.Fatalf("decrypt with extra failed: %s", buf2.String())
	}
	got, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(plain)) {
		t.Fatalf("mismatch:\n got %q\nwant %q", got, plain)
	}

	// Decrypt WITHOUT the extra passwords -> must fail (keys differ).
	decNoExtra := `{"mode":"decrypt","file":"` + encPath + `",` + keys + `,"output":"` + decPath + `"}`
	buf3, code3 := runCLIWithInputBuf(t, decNoExtra, nil, "data-cipher-pipe")
	defer util.WipeBytes(buf3.Bytes())
	if code3 == 0 {
		t.Fatalf("decrypt without the extra passwords should fail")
	}
}
