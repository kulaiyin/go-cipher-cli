package container

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Tests for the container package.
// Layout (little-endian): version(4) | reserved(4) | salt_seed(64 bytes) | length(4) | ciphertext.

func TestAssembleExtract_RoundTrip(t *testing.T) {
	saltSeedHex := "0102030405060708090a0b0c0d0e0f10" +
		"1112131415161718191a1b1c1d1e1f20" +
		"2122232425262728292a2b2c2d2e2f30" +
		"3132333435363738393a3b3c3d3e3f40" // 128 hex -> 64 bytes
	ct := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	buf, err := AssembleDownloadData(10000, 0, saltSeedHex, ct)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	// total length = 4+4+64+4+len(ct) = 80
	if len(buf) != 80 {
		t.Errorf("len = %d, want 80", len(buf))
	}

	ex, err := ExtractDecryptedData(buf)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if ex.Version != 10000 || ex.Reserved != 0 {
		t.Errorf("version/reserved = %d/%d", ex.Version, ex.Reserved)
	}
	if ex.SaltSeed != saltSeedHex {
		t.Errorf("salt_seed = %s, want %s", ex.SaltSeed, saltSeedHex)
	}
	if int(ex.DataLength) != len(ct) {
		t.Errorf("length = %d, want %d", ex.DataLength, len(ct))
	}
	if !bytes.Equal(ex.EncryptedData, ct) {
		t.Errorf("ct = %x, want %x", ex.EncryptedData, ct)
	}
}

func TestExtractDecryptedData_TooShort(t *testing.T) {
	if _, err := ExtractDecryptedData(bytes.Repeat([]byte{0}, 75)); err == nil {
		t.Error("expected error for <76 bytes")
	}
}

func TestExtractDecryptedData_BadLength(t *testing.T) {
	buf := make([]byte, 80)
	// set length to a value larger than available data
	binary.LittleEndian.PutUint32(buf[72:76], 1000)
	if _, err := ExtractDecryptedData(buf); err == nil {
		t.Error("expected error for overstated length")
	}
}

func TestExtractSaltFromEncryptedData(t *testing.T) {
	saltSeedHex := "0102030405060708090a0b0c0d0e0f10" +
		"1112131415161718191a1b1c1d1e1f20" +
		"2122232425262728292a2b2c2d2e2f30" +
		"3132333435363738393a3b3c3d3e3f40"
	ct := []byte{0x01}
	buf, _ := AssembleDownloadData(1, 0, saltSeedHex, ct)
	got := ExtractSaltFromEncryptedData(buf)
	if got != saltSeedHex {
		t.Errorf("salt = %s, want %s", got, saltSeedHex)
	}
}
