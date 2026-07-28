package safety

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"go-cipher-cli/internal/testvectors"
)

// Tests for the safety package (the crypto primitive layer).

func TestHKDFExpand_GoldenVectors(t *testing.T) {
	// Verifies full HKDF with empty salt, where prk is the hex-string ASCII bytes.
	v := testvectors.MustLoad()
	for _, c := range v.HKDFExpand {
		want, err := hex.DecodeString(c.Out)
		if err != nil {
			t.Fatalf("bad want hex: %v", err)
		}
		got := HKDFExpand(c.PRK, []byte(c.Info), c.Length)
		if !bytes.Equal(got, want) {
			t.Errorf("HKDFExpand(prk=%q, info=%q, L=%d):\n got=%x\nwant=%x", c.PRK, c.Info, c.Length, got, want)
		}
	}
}

func TestHMACSHA3512_GoldenVectors(t *testing.T) {
	v := testvectors.MustLoad()
	for _, c := range v.HMACSHA3512 {
		got := HMACSHA3512([]byte(c.Data), []byte(c.Key))
		if got != c.Out {
			t.Errorf("HMACSHA3512(data=%q,key=%q) = %s, want %s", c.Data, c.Key, got, c.Out)
		}
	}
}

func TestArgon2id_GoldenVectors(t *testing.T) {
	// Verifies production-size argon2id output (memory in KiB).
	if testing.Short() {
		t.Skip("argon2 golden vectors are slow; skip in -short")
	}
	v := testvectors.MustLoad()
	for _, c := range v.Argon2id {
		salt, err := hex.DecodeString(c.SaltHex)
		if err != nil {
			t.Fatalf("bad salt hex: %v", err)
		}
		got, err := Argon2id([]byte(c.Password), salt, c.Iterations, c.MemorySize, c.Parallelism, c.HashLength)
		if err != nil {
			t.Fatalf("Argon2id error: %v", err)
		}
		if hex.EncodeToString(got) != c.OutHex {
			t.Errorf("Argon2id(%q) = %x, want %s", c.Password, got, c.OutHex)
		}
	}
}

func TestSHA256_GoldenVectors(t *testing.T) {
	v := testvectors.MustLoad()
	for _, c := range v.SHA256 {
		got := SHA256Hex(c.In)
		if got != c.Out {
			t.Errorf("SHA256Hex(%q) = %s, want %s", c.In, got, c.Out)
		}
	}
}

func TestEncodingHelpers(t *testing.T) {
	// hex round-trip
	in := []byte{0x00, 0x1f, 0xab, 0xff}
	h := BytesToHex(in)
	if h != "001fabff" {
		t.Errorf("BytesToHex = %s", h)
	}
	back, err := HexToBytes(h)
	if err != nil || !bytes.Equal(back, in) {
		t.Errorf("HexToBytes round-trip failed: %v %x", err, back)
	}
	if _, err := HexToBytes("abc"); err == nil {
		t.Errorf("HexToBytes(odd-length) should error")
	}

	// base64 round-trip
	b64 := BytesToBase64(in)
	again, err := Base64ToBytes(b64)
	if err != nil || !bytes.Equal(again, in) {
		t.Errorf("base64 round-trip failed: %v %x", err, again)
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	a := GenerateRandomBytes(32)
	b := GenerateRandomBytes(32)
	if len(a) != 32 || len(b) != 32 {
		t.Fatal("wrong length")
	}
	if bytes.Equal(a, b) {
		t.Error("two random 32-byte draws matched (astronomically unlikely)")
	}
}

func TestIsPasswordHighStrength(t *testing.T) {
	// >=128 hex chars with a rich char set.
	if IsPasswordHighStrength(strings.Repeat("0", 127)) {
		t.Error("127-char string should NOT be high strength")
	}
	if !IsPasswordHighStrength(strings.Repeat("0123456789abcdef", 8)) { // 128 hex chars
		t.Error("128-hex string should be high strength")
	}
}
